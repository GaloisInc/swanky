// TODO: this file contains a lot of code copy-pasted from plaintext_eval. We should avoid
// copy-pasting code!
use std::{
    collections::hash_map::DefaultHasher, hash::BuildHasherDefault, path::PathBuf, sync::Arc,
    time::Instant,
};
use vectoreyes::array_utils::ArrayUnrolledExt;

use eyre::{Context, ContextCompat};
use mac_n_cheese_ir::circuit_builder::{FixData, PrivateBuilder};
use mac_n_cheese_sieve_parser::{RelationReader, ValueStreamKind, ValueStreamReader};
use mac_n_cheese_wire_map::WireMap;
use rustc_hash::FxHashMap;
use smallvec::SmallVec;

use crate::sieve_compiler::{
    circuit_ir::{
        CircuitChunk, FieldInstruction, FieldInstructions, FieldInstructionsTy, FunctionDefinition,
        FunctionId, Instruction, WireRange,
    },
    put,
    supported_fields::{
        CompilerField, CompilerFieldVisitor, FieldGenericIdentity, FieldGenericProduct,
        FieldGenericType, FieldIndexedArray, FieldType, InvariantType,
    },
    writer::should_inline,
    Inputs, SieveArgs,
};

pub(super) type CallChain = SmallVec<[FunctionId; 2]>;
#[derive(Default)]
struct PrivateStreamsWip {
    /// Fixes performed _by_ the `CallChain`
    ///
    /// `Fixes([])` _is_ valid
    fixes: FxHashMap<CallChain, FieldGenericProduct<PrivateStreamWipTy>>,
    /// Arguments and outputs for the function.
    ///
    /// `FunctionIo([.., a, b])` contains the inputs and outputs for `a`'s calls to `b`.
    ///
    /// `FunctionIo([])` is _not_ valid.
    ///
    /// The `usize` is the number of times this function has been called.
    function_io: FxHashMap<CallChain, (usize, FieldGenericProduct<PrivateStreamWipTy>)>,
}

struct PrivateStreamWip<FE: CompilerField> {
    threshold: usize,
    written: Vec<FixData>,
    wip: Vec<FE>,
}
impl<FE: CompilerField> PrivateStreamWip<FE> {
    fn new(threshold: usize) -> Self {
        Self {
            threshold,
            written: Vec::new(),
            wip: Vec::new(),
        }
    }
    fn add(&mut self, pb: &mut PrivateBuilder, fe: FE) -> eyre::Result<()> {
        self.wip.push(fe);
        if self.wip.len() >= self.threshold {
            assert_eq!(self.wip.len(), self.threshold);
            self.flush(pb)?;
        }
        Ok(())
    }
    fn flush(&mut self, pb: &mut PrivateBuilder) -> eyre::Result<()> {
        if self.wip.is_empty() {
            return Ok(());
        }
        self.written.push(pb.write_unassociated_fix_data(|dst| {
            for x in self.wip.drain(..) {
                dst.add(x)?
            }
            Ok(())
        })?);
        Ok(())
    }
}
field_generic_type!(PrivateStreamWipTy<FE: CompilerField> => PrivateStreamWip<FE>);

fn new_private_streams(threshold: usize) -> FieldGenericProduct<PrivateStreamWipTy> {
    struct V(usize);
    impl CompilerFieldVisitor<()> for &'_ mut V {
        type Output = PrivateStreamWipTy;
        fn visit<FE: CompilerField>(self, (): ()) -> PrivateStreamWip<FE> {
            PrivateStreamWip::new(self.0)
        }
    }
    FieldGenericProduct::new(&mut V(threshold))
}

struct EvaluateFieldInstructions<'a, 'b, 'c, VSR: ValueStreamReader> {
    wm: &'a mut FieldGenericProduct<WireMap<'b, FieldGenericIdentity>>,
    witnesses: &'a mut Inputs<VSR>,
    public_inputs: &'a mut FieldGenericProduct<std::slice::Iter<'c, FieldGenericIdentity>>,
    fix_streams: &'a mut FieldGenericProduct<PrivateStreamWipTy>,
    pb: &'a mut PrivateBuilder,
}

impl<'a, 'b, 'c, 'd, VSR: ValueStreamReader> CompilerFieldVisitor<&'c FieldInstructionsTy>
    for EvaluateFieldInstructions<'a, 'b, 'd, VSR>
{
    type Output = InvariantType<eyre::Result<()>>;
    fn visit<FE: CompilerField>(self, instructions: &'c FieldInstructions<FE>) -> eyre::Result<()> {
        let fix_stream = self.fix_streams.as_mut().get::<FE>();
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
                    let src = *wm.get(src)?;
                    put(wm, dst, src)?;
                }
                FieldInstruction::Add { dst, left, right } => {
                    let left = *wm.get(left)?;
                    let right = *wm.get(right)?;
                    put(wm, dst, left + right)?;
                }
                FieldInstruction::Mul { dst, left, right } => {
                    let left = *wm.get(left)?;
                    let right = *wm.get(right)?;
                    let product = left * right;
                    fix_stream.add(self.pb, product)?;
                    put(wm, dst, product)?;
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
                    put(wm, dst, *public_inputs.next().context("need public input")?)?;
                }
                FieldInstruction::GetWitness { dst } => {
                    witness_buf.clear();
                    self.witnesses.read_into(1, &mut witness_buf)?;
                    let witness = witness_buf[0];
                    fix_stream.add(self.pb, witness)?;
                    put(wm, dst, witness)?;
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
    public_inputs: &mut FieldGenericProduct<std::slice::Iter<FieldGenericIdentity>>,
    functions: &[Arc<FunctionDefinition>],
    private_streams: &mut PrivateStreamsWip,
    function_breadcrumbs: &CallChain,
    pb: &mut PrivateBuilder,
) -> eyre::Result<()> {
    for instruction in instructions {
        match instruction {
            Instruction::FieldInstructions(instructions) => {
                instructions.as_ref().visit(EvaluateFieldInstructions {
                    wm,
                    witnesses,
                    public_inputs,
                    pb,
                    fix_streams: match private_streams.fixes.get_mut(function_breadcrumbs) {
                        Some(x) => x,
                        None => private_streams
                            .fixes
                            .entry(function_breadcrumbs.clone())
                            .or_insert(new_private_streams(super::FIX_WRITE_THRESHOLD)),
                    },
                })?
            }
            Instruction::FunctionCall {
                function_id: FunctionId::UserDefined(function_id),
                out_ranges,
                in_ranges,
            } => {
                let function = &functions[*function_id];
                let inline = should_inline(&function);
                let mut child_wire_maps = {
                    struct V<'a> {
                        in_ranges: &'a FieldIndexedArray<Vec<WireRange>>,
                        out_ranges: &'a FieldIndexedArray<Vec<WireRange>>,
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
                            let out = parent.borrow_child(
                                out_ranges.iter().map(|range| {
                                    let dst_start = output_pos;
                                    output_pos += range.len();
                                    mac_n_cheese_wire_map::DestinationRange {
                                        src_start: range.start,
                                        src_inclusive_end: range.inclusive_end,
                                        dst_start,
                                    }
                                }),
                                in_ranges.iter().map(|range| {
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
                            Ok(out)
                        }
                    }
                    wm.as_mut().map_result(&mut V {
                        in_ranges,
                        out_ranges,
                    })?
                };
                // TODO: cache this allocation.
                let mut callee_chain = function_breadcrumbs.clone();
                if !inline {
                    callee_chain.push(FunctionId::UserDefined(*function_id));
                }
                eval(
                    &mut child_wire_maps,
                    witnesses,
                    &function.body,
                    public_inputs,
                    functions,
                    private_streams,
                    &callee_chain,
                    pb,
                )?;
                std::mem::drop(child_wire_maps);
                if !inline {
                    // Now we write the inputs and the outputs.
                    let call_limit = super::max_repeats_of_function(function).get();
                    let (call_count, function_io) = private_streams
                        .function_io
                        .entry(callee_chain)
                        // We manually flush these, rather than calculate an appropriate threshold.
                        .or_insert_with(|| (0, new_private_streams(usize::MAX)));
                    debug_assert!(*call_count < call_limit);
                    for ty in FieldType::ALL.iter().copied() {
                        struct V<'a, 'b> {
                            in_ranges: &'a FieldIndexedArray<Vec<WireRange>>,
                            out_ranges: &'a FieldIndexedArray<Vec<WireRange>>,
                            function_io: &'a mut FieldGenericProduct<PrivateStreamWipTy>,
                            pb: &'a mut PrivateBuilder,
                            wm: &'a mut FieldGenericProduct<WireMap<'b, FieldGenericIdentity>>,
                        }
                        impl CompilerFieldVisitor<()> for V<'_, '_> {
                            type Output = InvariantType<eyre::Result<()>>;
                            fn visit<FE: CompilerField>(self, (): ()) -> eyre::Result<()> {
                                let in_ranges = &self.in_ranges[FE::FIELD_TYPE];
                                let out_ranges = &self.out_ranges[FE::FIELD_TYPE];
                                let function_io = self.function_io.as_mut().get::<FE>();
                                let wm = self.wm.as_mut().get::<FE>();
                                // TODO: do this more efficiently.
                                for range in out_ranges.iter().chain(in_ranges.iter()) {
                                    for wire in range.start..=range.inclusive_end {
                                        function_io.add(self.pb, *wm.get(wire)?)?;
                                    }
                                }
                                Ok(())
                            }
                        }
                        ty.visit(V {
                            function_io,
                            pb,
                            wm,
                            in_ranges,
                            out_ranges,
                        })?;
                    }
                    *call_count += 1;
                    if *call_count >= call_limit {
                        assert_eq!(*call_count, call_limit);
                        *call_count = 0;
                        for ty in FieldType::ALL.iter().copied() {
                            struct V<'a>(
                                &'a mut FieldGenericProduct<PrivateStreamWipTy>,
                                &'a mut PrivateBuilder,
                            );
                            impl CompilerFieldVisitor<()> for V<'_> {
                                type Output = InvariantType<eyre::Result<()>>;
                                fn visit<FE: CompilerField>(self, (): ()) -> eyre::Result<()> {
                                    self.0.as_mut().get::<FE>().flush(self.1)
                                }
                            }
                            ty.visit(V(function_io, pb))?;
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

pub(super) struct PrivateStreams {
    /// Fixes performed _by_ the `CallChain`
    ///
    /// `Fixes([])` _is_ valid
    pub(super) fixes: FxHashMap<CallChain, FieldIndexedArray<std::vec::IntoIter<FixData>>>,
    /// Arguments and outputs for the function.
    ///
    /// `FunctionIo([.., a, b])` contains the inputs and outputs for `a`'s calls to `b`.
    ///
    /// `FunctionIo([])` is _not_ valid.
    pub(super) function_io: FxHashMap<CallChain, FieldIndexedArray<std::vec::IntoIter<FixData>>>,
}

pub(super) fn empty_fix_data() -> FieldIndexedArray<std::vec::IntoIter<FixData>> {
    FieldIndexedArray(
        <[std::vec::IntoIter<FixData>; FieldType::ALL.len()]>::array_generate(|_| {
            Vec::new().into_iter()
        }),
    )
}

pub(super) type ConstructPrivateStreamsOut<'a> = (&'a mut PrivateBuilder, PrivateStreams);
pub(super) fn construct_private_streams<'a, VSR: ValueStreamReader + Send + 'static>(
    pb: &'a mut PrivateBuilder,
    chunks: flume::Receiver<Arc<CircuitChunk>>,
    mut witnesses: Inputs<VSR>,
) -> eyre::Result<ConstructPrivateStreamsOut<'a>> {
    let mut functions = Vec::new();
    let mut root_wm = FieldGenericProduct::<WireMap<FieldGenericIdentity>>::default();
    let mut wip: PrivateStreamsWip = Default::default();
    for chunk in chunks.into_iter() {
        for (id, defn) in chunk.new_functions.iter() {
            assert_eq!(*id, functions.len());
            functions.push(defn.clone());
        }
        struct V;
        impl<'a> CompilerFieldVisitor<&'a Vec<FieldGenericIdentity>> for &'_ mut V {
            type Output = std::slice::Iter<'a, FieldGenericIdentity>;
            fn visit<FE: CompilerField>(self, arg: &'a Vec<FE>) -> std::slice::Iter<'a, FE> {
                arg.iter()
            }
        }
        let mut public_inputs = chunk.public_inputs.as_ref().map(&mut V);
        eval(
            &mut root_wm,
            &mut witnesses,
            &chunk.new_root_instructions,
            &mut public_inputs,
            &functions,
            &mut wip,
            &Default::default(), // the root has empty breadcrumbs
            pb,
        )?;
    }
    let mut out = PrivateStreams {
        fixes: FxHashMap::with_capacity_and_hasher(wip.fixes.len(), BuildHasherDefault::default()),
        function_io: FxHashMap::with_capacity_and_hasher(
            wip.function_io.len(),
            BuildHasherDefault::default(),
        ),
    };
    fn finish(
        kv: impl Iterator<Item = (CallChain, FieldGenericProduct<PrivateStreamWipTy>)>,
        pb: &mut PrivateBuilder,
        dst: &mut FxHashMap<CallChain, FieldIndexedArray<std::vec::IntoIter<FixData>>>,
    ) -> eyre::Result<()> {
        for (k, v) in kv {
            struct V<'a> {
                pb: &'a mut PrivateBuilder,
                dst: &'a mut FieldIndexedArray<std::vec::IntoIter<FixData>>,
            }
            impl CompilerFieldVisitor<PrivateStreamWipTy> for &'_ mut V<'_> {
                type Output = eyre::Result<()>;
                fn visit<FE: CompilerField>(
                    self,
                    mut ps: PrivateStreamWip<FE>,
                ) -> eyre::Result<()> {
                    ps.flush(self.pb)?;
                    debug_assert!(ps.wip.is_empty());
                    self.dst[FE::FIELD_TYPE] = ps.written.into_iter();
                    Ok(())
                }
            }
            let mut cells = empty_fix_data();
            v.map_result(&mut V {
                pb,
                dst: &mut cells,
            })?;
            dst.insert(k, cells);
        }
        Ok(())
    }
    finish(wip.fixes.into_iter(), pb, &mut out.fixes)?;
    finish(
        wip.function_io
            .into_iter()
            .map(|(call_chain, (_count, fix_data))| (call_chain, fix_data)),
        pb,
        &mut out.function_io,
    )?;
    Ok((pb, out))
}
