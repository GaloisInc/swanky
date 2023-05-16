use std::{path::PathBuf, sync::Arc, time::Instant};

use eyre::{Context, ContextCompat};
use mac_n_cheese_sieve_parser::{RelationReader, ValueStreamKind, ValueStreamReader};
use mac_n_cheese_wire_map::WireMap;

use crate::sieve_compiler::{
    circuit_ir::{CircuitChunk, CounterInfo, Instruction, Permissiveness, WireRange},
    supported_fields::{
        CompilerField, CompilerFieldVisitor, FieldGenericIdentity, FieldGenericProduct,
        FieldGenericType, FieldIndexedArray,
    },
    to_fe, to_k_bits,
};

use super::{
    circuit_ir::{
        FieldInstruction, FieldInstructions, FieldInstructionsTy, FunctionDefinition, FunctionId,
    },
    put,
    supported_fields::{FieldType, InvariantType},
    Inputs, SieveArgs,
};

struct EvaluateFieldInstructions<'a, 'b, VSR: ValueStreamReader> {
    muls_per_field: &'a mut FieldIndexedArray<u64>,
    wm: &'a mut FieldGenericProduct<WireMap<'b, FieldGenericIdentity>>,
    witnesses: &'a mut Inputs<VSR>,
    public_inputs: &'a mut FieldGenericProduct<std::vec::IntoIter<FieldGenericIdentity>>,
}

impl<'a, 'b, 'c, VSR: ValueStreamReader> CompilerFieldVisitor<&'c FieldInstructionsTy>
    for EvaluateFieldInstructions<'a, 'b, VSR>
{
    type Output = InvariantType<eyre::Result<()>>;
    fn visit<FE: CompilerField>(self, instructions: &'c FieldInstructions<FE>) -> eyre::Result<()> {
        let mut witness_buf = Vec::<FE>::with_capacity(1);
        let wm = self.wm.as_mut().get::<FE>();
        let public_inputs = self.public_inputs.as_mut().get::<FE>();
        for insn in instructions.iter() {
            match insn {
                FieldInstruction::Constant { dst, src } => put(wm, dst, src)?,
                FieldInstruction::AssertZero { src } => {
                    let src = *wm.get(src)?;
                    eyre::ensure!(src == FE::ZERO, "assert zero failed")
                }
                FieldInstruction::Copy { dst, src } => {
                    let src = *wm.get(src).with_context(|| {
                        format!(
                            "Copy to {dst} from {src} in {}",
                            std::any::type_name::<FE>()
                        )
                    })?;
                    put(wm, dst, src)?;
                }
                FieldInstruction::Add { dst, left, right } => {
                    let left = *wm.get(left).with_context(|| {
                        format!(
                            "Add to {dst} from {left} in {}",
                            std::any::type_name::<FE>()
                        )
                    })?;
                    let right = *wm.get(right)?;
                    put(wm, dst, left + right)?;
                }
                FieldInstruction::Mul { dst, left, right } => {
                    self.muls_per_field[FE::FIELD_TYPE] += 1;
                    let left = *wm.get(left)?;
                    let right = *wm.get(right)?;
                    put(wm, dst, left * right)?;
                }
                FieldInstruction::AddConstant { dst, left, right } => {
                    let left = *wm.get(left)?;
                    put(wm, dst, left + right)?;
                }
                FieldInstruction::MulConstant { dst, left, right } => {
                    let left = *wm.get(left)?;
                    put(wm, dst, left * right)?;
                }
                FieldInstruction::GetPublicInput { dst } => {
                    put(wm, dst, public_inputs.next().context("need public input")?)?;
                }
                FieldInstruction::GetWitness { dst } => {
                    witness_buf.clear();
                    self.witnesses.read_into(1, &mut witness_buf)?;
                    put(wm, dst, witness_buf[0])?;
                }
                FieldInstruction::Alloc { first, last } => wm.alloc(first, last)?,
                FieldInstruction::Free { first, last } => wm.free(first, last)?,
            }
        }
        Ok(())
    }
}

fn eval<VSR: ValueStreamReader>(
    wm: &mut FieldGenericProduct<WireMap<FieldGenericIdentity>>,
    witnesses: &mut Inputs<VSR>,
    instructions: &[Instruction],
    public_inputs: &mut FieldGenericProduct<std::vec::IntoIter<FieldGenericIdentity>>,
    functions: &[Arc<FunctionDefinition>],
    muls_per_field: &mut FieldIndexedArray<u64>,
) -> eyre::Result<()> {
    for instruction in instructions {
        match instruction {
            Instruction::FieldInstructions(instructions) => {
                instructions.as_ref().visit(EvaluateFieldInstructions {
                    wm,
                    witnesses,
                    public_inputs,
                    muls_per_field,
                })?
            }
            Instruction::FunctionCall {
                function_id: FunctionId::UserDefined(function_id),
                out_ranges,
                in_ranges,
                counter_info,
            } => {
                let function = &functions[*function_id];
                let mut child_wire_maps = {
                    struct V<'a> {
                        in_ranges: &'a FieldIndexedArray<Vec<WireRange>>,
                        out_ranges: &'a FieldIndexedArray<Vec<WireRange>>,
                        counter_info: &'a Option<CounterInfo>,
                    }
                    impl<'a, 'b, 'c> CompilerFieldVisitor<&'b mut WireMap<'c, FieldGenericIdentity>> for &'_ mut V<'a> {
                        type Output = eyre::Result<WireMap<'b, FieldGenericIdentity>>;
                        fn visit<FE: CompilerField>(
                            self,
                            parent: &'b mut WireMap<'c, FE>,
                        ) -> eyre::Result<WireMap<'b, FE>> {
                            let in_ranges = &self.in_ranges[FE::FIELD_TYPE];
                            let out_ranges = &self.out_ranges[FE::FIELD_TYPE];
                            for range in out_ranges.iter() {
                                parent
                                    .alloc_range_if_unallocated(range.start, range.inclusive_end)?;
                            }
                            let total_outputs =
                                out_ranges.iter().map(|range| range.len()).sum::<u64>();
                            let mut input_pos = total_outputs;
                            let mut output_pos = 0;
                            let mut out = parent.borrow_child(
                                out_ranges.iter().map(|range| {
                                    let dst_start = output_pos;
                                    output_pos += range.len();
                                    mac_n_cheese_wire_map::DestinationRange {
                                        src_start: range.start,
                                        src_inclusive_end: range.inclusive_end,
                                        dst_start,
                                    }
                                }),
                                in_ranges.iter().enumerate().map(|(i, range)| {
                                    // If this is a call created by map_enumerated, we adjust
                                    // input_pos by num_wires to leave room for us to allocate the
                                    // wires needed for the iteration counter value.
                                    if let &Some(CounterInfo {
                                        num_env_for_field,
                                        field_type,
                                        num_wires,
                                        ..
                                    }) = self.counter_info
                                    {
                                        if field_type == FE::FIELD_TYPE && i == num_env_for_field {
                                            input_pos += num_wires as u64
                                        }
                                    }

                                    let dst_start = input_pos;
                                    input_pos += range.len();
                                    mac_n_cheese_wire_map::DestinationRange {
                                        src_start: range.start,
                                        src_inclusive_end: range.inclusive_end,
                                        dst_start,
                                    }
                                }),
                            )?;
                            debug_assert_eq!(output_pos, total_outputs);

                            if let &Some(CounterInfo {
                                num_env_for_field,
                                field_type,
                                num_wires,
                                value,
                            }) = self.counter_info
                            {
                                if field_type == FE::FIELD_TYPE {
                                    match FE::FIELD_TYPE {
                                        FieldType::F2 => {
                                            let value_le_bits = to_k_bits::<FE>(value, num_wires)?;

                                            let start = total_outputs + num_env_for_field as u64;
                                            let inclusive_end = start + num_wires as u64 - 1;
                                            out.alloc(start, inclusive_end)?;

                                            for (w, &b) in (start..=inclusive_end)
                                                .zip(value_le_bits.iter().rev())
                                            {
                                                put(&mut out, w, b)?;
                                            }
                                        }
                                        _ => {
                                            debug_assert_eq!(num_wires, 1);

                                            let start = total_outputs + num_env_for_field as u64;
                                            out.alloc(start, start)?;

                                            let counter = to_fe(value)?;

                                            put(&mut out, start, counter)?;
                                        }
                                    }
                                }
                            }

                            Ok(out)
                        }
                    }
                    wm.as_mut().map_result(&mut V {
                        in_ranges,
                        out_ranges,
                        counter_info,
                    })?
                };
                eval(
                    &mut child_wire_maps,
                    witnesses,
                    &function.body,
                    public_inputs,
                    functions,
                    muls_per_field,
                )?;
            }
            Instruction::MuxCall {
                permissiveness,
                field_type,
                out_ranges,
                in_ranges,
            } => {
                struct V<'a, 'b> {
                    wm: &'a mut FieldGenericProduct<WireMap<'b, FieldGenericIdentity>>,
                    permissiveness: &'a Permissiveness,
                    in_ranges: &'a Vec<WireRange>,
                    out_ranges: &'a Vec<WireRange>,
                }
                impl<'a, 'b> CompilerFieldVisitor for &'_ mut V<'a, 'b> {
                    type Output = InvariantType<eyre::Result<()>>;
                    fn visit<FE: CompilerField>(self, _arg: ()) -> eyre::Result<()> {
                        let wm = self.wm.as_mut().get::<FE>();

                        for range in self.out_ranges.iter() {
                            wm.alloc_range_if_unallocated(range.start, range.inclusive_end)?;
                        }

                        // There should at least be a wire range for the condition
                        debug_assert_ne!(self.in_ranges.len(), 0);

                        // For F2, need to interpret condition wires as big-endian
                        // bits. Otherwise, we just use the value on the single wire.

                        // bits should be little-endian
                        fn bits_to_usize(
                            bits: impl IntoIterator<Item = bool>,
                        ) -> eyre::Result<usize> {
                            bits.into_iter().fold(Ok(0_usize), |acc, b| {
                                2_usize
                                    .checked_mul(acc?)
                                    .and_then(|x| x.checked_add(b.into()))
                                    .context("Overflow while computing condition value")
                            })
                        }

                        let cond_wire_range = self.in_ranges[0];
                        let cond: usize = match FE::FIELD_TYPE {
                            FieldType::F2 => {
                                // TODO: Can we avoid the allocation here?
                                // Get the wire values in reverse order (i.e. little-endian)
                                let le_vals = (cond_wire_range.start
                                    ..=cond_wire_range.inclusive_end)
                                    .rev()
                                    .map(|w| Ok(*wm.get(w)?))
                                    .collect::<eyre::Result<Vec<_>>>()?;

                                bits_to_usize(
                                    le_vals.iter().flat_map(|b| FE::bit_decomposition(b)),
                                )?
                            }
                            _ => {
                                debug_assert_eq!(cond_wire_range.len(), 1);
                                bits_to_usize(
                                    FE::bit_decomposition(wm.get(cond_wire_range.start)?)
                                        .into_iter()
                                        .rev(),
                                )?
                            }
                        };

                        let branch_inputs = &self.in_ranges[1..];
                        let num_ranges_per_branch = self.out_ranges.len();
                        debug_assert!(branch_inputs.len() % num_ranges_per_branch == 0);

                        let num_branches = branch_inputs.len() / num_ranges_per_branch;
                        if cond >= num_branches {
                            match self.permissiveness {
                                Permissiveness::Permissive => {
                                    for wr in self.out_ranges {
                                        for w in wr.start..=wr.inclusive_end {
                                            put(wm, w, FE::ZERO)?;
                                        }
                                    }
                                }
                                Permissiveness::Strict => eyre::bail!("Strict mux failed: selector value {cond} >= number of branches {}", num_branches)
                            }
                        } else {
                            let in_ranges_to_output: &[WireRange] = branch_inputs
                                .chunks_exact(num_ranges_per_branch)
                                .collect::<Vec<_>>()[cond];
                            for (in_wr, out_wr) in in_ranges_to_output.iter().zip(self.out_ranges) {
                                debug_assert_eq!(in_wr.len(), out_wr.len());
                                for (in_w, out_w) in (in_wr.start..=in_wr.inclusive_end)
                                    .zip(out_wr.start..=out_wr.inclusive_end)
                                {
                                    let src = *wm.get(in_w)?;
                                    put(wm, out_w, src)?;
                                }
                            }
                        }

                        Ok(())
                    }
                }

                field_type.visit(&mut V {
                    wm,
                    permissiveness,
                    in_ranges,
                    out_ranges,
                })?;
            }
        }
    }
    Ok(())
}

pub(super) fn plaintext_evaluate<
    RR: RelationReader + Send + 'static,
    VSR: ValueStreamReader + Send + 'static,
>(
    args: &SieveArgs,
    witnesses: &[PathBuf],
) -> eyre::Result<()> {
    let mut witnesses = Inputs::<VSR>::open(ValueStreamKind::Private, witnesses)?;
    let chunks = CircuitChunk::stream::<RR, VSR>(&args.relation, &args.public_inputs);
    let mut functions = Vec::new();
    let mut root_wm = FieldGenericProduct::<WireMap<FieldGenericIdentity>>::default();
    let start = Instant::now();
    let mut muls_per_field = Default::default();
    for chunk in chunks.into_iter() {
        let chunk = chunk?;
        for (id, defn) in chunk.new_functions.into_iter() {
            assert_eq!(id, functions.len());
            functions.push(defn);
        }
        struct V;
        impl CompilerFieldVisitor<Vec<FieldGenericIdentity>> for &'_ mut V {
            type Output = std::vec::IntoIter<FieldGenericIdentity>;
            fn visit<FE: CompilerField>(
                self,
                arg: <Vec<FieldGenericIdentity> as FieldGenericType>::Out<FE>,
            ) -> <Self::Output as FieldGenericType>::Out<FE> {
                arg.into_iter()
            }
        }
        let mut public_inputs = chunk.public_inputs.map(&mut V);
        eval(
            &mut root_wm,
            &mut witnesses,
            &chunk.new_root_instructions,
            &mut public_inputs,
            &functions,
            &mut muls_per_field,
        )?;
    }
    dbg!(
        mac_n_cheese_wire_map::LOOKUP_MISSES.load(std::sync::atomic::Ordering::Relaxed),
        mac_n_cheese_wire_map::NUM_LOOKUPS.load(std::sync::atomic::Ordering::Relaxed),
        muls_per_field,
        start.elapsed(),
    );
    Ok(())
}
