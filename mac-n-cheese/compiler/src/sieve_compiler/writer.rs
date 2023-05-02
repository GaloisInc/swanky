use std::{marker::PhantomData, num::NonZeroUsize, path::Path, sync::Arc};

use crate::sieve_compiler::{
    circuit_ir::{FieldInstructionsTy, Type, WireRange},
    supported_fields::CompilerFieldVisitor,
    writer::prototype_builder::ExternWires,
};

use self::{
    private::{empty_fix_data, CallChain, ConstructPrivateStreamsOut, PrivateStreams},
    prototype_builder::{
        ExternWiresId, ExternWiresTy, PrototypeCohort, PrototypeCohortBuilder, RawWipWire,
        WipWireTy,
    },
};

use super::{
    circuit_ir::{
        self, CircuitChunk, FieldInstruction, FieldInstructions, FunctionDefinition, FunctionId,
        Instruction, SizeHint,
    },
    put,
    supported_fields::{
        CompilerField, FieldGenericProduct, FieldGenericType, FieldIndexedArray, FieldType,
        InvariantType,
    },
    Inputs,
};
use eyre::{Context, ContextCompat};
use mac_n_cheese_ir::circuit_builder::{
    build_circuit, vole_supplier::VoleSupplier, CircuitBuilder, FixData, PrivateBuilder,
    TaskPrototypeRef, WireSlice,
};
use mac_n_cheese_ir::compilation_format::{wire_format::Wire as IrWire, Type as IrType};
use mac_n_cheese_party::{
    either::PartyEitherCopy,
    private::{ProverPrivate, ProverPrivateCopy},
    Party, WhichParty,
};
use mac_n_cheese_sieve_parser::{RelationReader, ValueStreamReader};
use mac_n_cheese_wire_map::WireMap;
use rustc_hash::{FxHashMap, FxHashSet};
use smallvec::SmallVec;
use vectoreyes::array_utils::ArrayUnrolledExt;

const FIX_WRITE_THRESHOLD: usize = 1024 * 16;

mod private;
mod prototype_builder;

struct Function {
    definition: Arc<FunctionDefinition>,
    inlined: bool,
}

struct ExternFunctionInstance {
    extern_pages: FieldGenericProduct<Option<ExternWiresTy>>,
    num_instances: usize,
}

struct PrototypesBuilder<'a, 'b, 'c, 'd> {
    cohort: &'c mut PrototypeCohortBuilder<'a, 'b>,
    functions: &'c Vec<Function>,
    extern_functions: &'c mut FxHashMap<FunctionId, Vec<ExternFunctionInstance>>,
    wires: &'c mut FieldIndexedArray<WireMap<'d, RawWipWire>>,
}
impl PrototypesBuilder<'_, '_, '_, '_> {
    fn add_field_instructions<FE: CompilerField>(
        &mut self,
        insns: &FieldInstructions<FE>,
    ) -> eyre::Result<()> {
        let wires = &mut self.wires[FE::FIELD_TYPE];
        // TODO: peephole optimize the linear instruction
        // NOTE: keep this in sync with the code in private.rs
        // e.g. the multiply function in that file needs to fix the output, even though that's not
        // needed for plaintext evaluation by itself.
        for insn in insns.iter() {
            match insn {
                FieldInstruction::Constant { dst, src } => {
                    put(wires, dst, self.cohort.push_constant(src)?.into())?;
                }
                FieldInstruction::AssertZero { src } => {
                    self.cohort
                        .push_assert_zero(wires.get(src)?.assert_field::<FE>())?;
                }
                FieldInstruction::Copy { dst, src } => {
                    let src = *wires.get(src)?;
                    put(wires, dst, src)?;
                }
                FieldInstruction::Add { dst, left, right } => {
                    let left = wires.get(left)?.assert_field::<FE>();
                    let right = wires.get(right)?.assert_field::<FE>();
                    put(
                        wires,
                        dst,
                        self.cohort
                            .push_linear([(left, FE::ONE), (right, FE::ONE)])?
                            .into(),
                    )?;
                }
                FieldInstruction::Mul { dst, left, right } => {
                    let left = wires.get(left)?.assert_field::<FE>();
                    let right = wires.get(right)?.assert_field::<FE>();
                    let out = self.cohort.push_fix()?;
                    put(wires, dst, out.into())?;
                    self.cohort.push_assert_multiply(left, right, out)?;
                }
                FieldInstruction::AddConstant { dst, left, right } => {
                    let left = wires.get(left)?.assert_field::<FE>();
                    let right = self.cohort.push_constant(right)?;
                    put(
                        wires,
                        dst,
                        self.cohort
                            .push_linear([(left, FE::ONE), (right, FE::ONE)])?
                            .into(),
                    )?;
                }
                FieldInstruction::MulConstant { dst, left, right } => {
                    let left = wires.get(left)?.assert_field::<FE>();
                    put(
                        wires,
                        dst,
                        self.cohort
                            .push_linear([(left, right), (left, FE::ZERO)])?
                            .into(),
                    )?;
                }
                FieldInstruction::GetPublicInput { dst } => todo!(),
                FieldInstruction::GetWitness { dst } => {
                    put(wires, dst, self.cohort.push_fix::<FE>()?.into())?;
                }
                FieldInstruction::Alloc { first, last } => wires.alloc(first, last)?,
                FieldInstruction::Free { first, last } => wires.free(first, last)?,
            }
        }
        Ok(())
    }
    fn add_instruction(&mut self, insn: &Instruction) -> eyre::Result<()> {
        match insn {
            Instruction::FieldInstructions(fi) => {
                struct V<'s, 'a, 'b, 'c, 'd>(&'s mut PrototypesBuilder<'a, 'b, 'c, 'd>);
                impl<'x> CompilerFieldVisitor<&'x FieldInstructionsTy> for V<'_, '_, '_, '_, '_> {
                    type Output = InvariantType<eyre::Result<()>>;
                    fn visit<FE: CompilerField>(
                        self,
                        fi: &FieldInstructions<FE>,
                    ) -> eyre::Result<()> {
                        self.0.add_field_instructions(fi)
                    }
                }
                fi.as_ref().visit(V(self))?;
            }
            Instruction::FunctionCall {
                function_id: FunctionId::UserDefined(id),
                out_ranges,
                in_ranges,
            } => {
                let function = &self.functions[*id];
                if function.inlined {
                    for ty in FieldType::ALL {
                        for range in out_ranges[*ty].iter() {
                            self.wires[*ty]
                                .alloc_range_if_unallocated(range.start, range.inclusive_end)?;
                        }
                    }
                    let mut pb = PrototypesBuilder {
                        cohort: self.cohort,
                        functions: self.functions,
                        extern_functions: self.extern_functions,
                        wires: &mut FieldIndexedArray(
                            out_ranges
                                .array_as_ref()
                                .array_zip(in_ranges.array_as_ref())
                                .array_zip(self.wires.array_as_mut())
                                .array_map_result::<WireMap<_>, eyre::Error, _>(
                                    |((out_ranges, in_ranges), wires)| {
                                        let mut total_outputs = 0;
                                        for range in out_ranges.iter() {
                                            wires.alloc_range_if_unallocated(
                                                range.start,
                                                range.inclusive_end,
                                            )?;
                                            total_outputs += range.len();
                                        }
                                        let mut input_pos = total_outputs;
                                        let mut output_pos = 0;
                                        let out = wires.borrow_child(
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
                                    },
                                )?,
                        ),
                    };
                    for insn in function.definition.body.iter() {
                        pb.add_instruction(insn)?;
                    }
                } else {
                    // Extern function!
                    let num_inputs = function.definition.num_inputs();
                    let num_outputs = function.definition.num_outputs();
                    let ef = self
                        .extern_functions
                        .entry(FunctionId::UserDefined(*id))
                        .or_default();
                    let entry = if let Some(ef) = ef.last_mut().filter(|entry| {
                        entry.num_instances < max_repeats_of_function(&function.definition).get()
                    }) {
                        ef
                    } else {
                        let mut extern_pages: FieldGenericProduct<Option<ExternWiresTy>> =
                            Default::default();
                        for ty in FieldType::ALL {
                            struct V<'a, 'b, 'c> {
                                cohort: &'c mut PrototypeCohortBuilder<'a, 'b>,
                                externs: &'c mut FieldGenericProduct<Option<ExternWiresTy>>,
                            }
                            impl CompilerFieldVisitor<()> for V<'_, '_, '_> {
                                type Output = InvariantType<()>;
                                fn visit<FE: CompilerField>(self, (): ()) {
                                    *self.externs.as_mut().get::<FE>() =
                                        Some(self.cohort.extern_proto(0));
                                }
                            }
                            if !in_ranges[*ty].is_empty() || !out_ranges[*ty].is_empty() {
                                ty.visit(V {
                                    cohort: self.cohort,
                                    externs: &mut extern_pages,
                                });
                            }
                        }
                        ef.push(ExternFunctionInstance {
                            extern_pages,
                            num_instances: 0,
                        });
                        ef.last_mut().unwrap()
                    };
                    entry.num_instances += 1;
                    for ty in FieldType::ALL {
                        struct V<'a, 'b, 'c, 'd> {
                            cohort: &'c mut PrototypeCohortBuilder<'a, 'b>,
                            num_inputs: &'c FieldIndexedArray<u64>,
                            num_outputs: &'c FieldIndexedArray<u64>,
                            externs: &'c mut FieldGenericProduct<Option<ExternWiresTy>>,
                            wires: &'c mut FieldIndexedArray<WireMap<'d, RawWipWire>>,
                            in_ranges: &'c FieldIndexedArray<Vec<WireRange>>,
                            out_ranges: &'c FieldIndexedArray<Vec<WireRange>>,
                        }
                        impl CompilerFieldVisitor<()> for V<'_, '_, '_, '_> {
                            type Output = InvariantType<eyre::Result<()>>;
                            fn visit<FE: CompilerField>(self, (): ()) -> eyre::Result<()> {
                                let extern_wires =
                                    self.externs.as_mut().get::<FE>().as_mut().unwrap();
                                let mut base = extern_wires.len();
                                let num_inputs =
                                    u32::try_from(self.num_inputs[FE::FIELD_TYPE]).unwrap();
                                let num_outputs =
                                    u32::try_from(self.num_outputs[FE::FIELD_TYPE]).unwrap();
                                self.cohort.enlarge_extern(
                                    extern_wires,
                                    base.checked_add(num_inputs.checked_add(num_outputs).unwrap())
                                        .unwrap(),
                                );
                                let in_ranges = self.in_ranges[FE::FIELD_TYPE].as_slice();
                                let out_ranges = self.out_ranges[FE::FIELD_TYPE].as_slice();
                                let wires = &mut self.wires[FE::FIELD_TYPE];
                                // TODO: do something more efficient here
                                // Grab the output values from the start of the out range.
                                for out_range in out_ranges {
                                    wires.alloc_range_if_unallocated(
                                        out_range.start,
                                        out_range.inclusive_end,
                                    )?;
                                    for wire in out_range.start..=out_range.inclusive_end {
                                        put(wires, wire, extern_wires.get(base).into())?;
                                        base += 1;
                                    }
                                }
                                // Check that the input values are corect.
                                for in_range in in_ranges {
                                    for wire in in_range.start..=in_range.inclusive_end {
                                        let zero = self.cohort.push_linear([
                                            (wires.get(wire)?.assert_field::<FE>(), FE::ONE),
                                            (extern_wires.get(base), -FE::ONE),
                                        ])?;
                                        self.cohort.push_assert_zero(zero)?;
                                        base += 1;
                                    }
                                }
                                Ok(())
                            }
                        }
                        if !in_ranges[*ty].is_empty() || !out_ranges[*ty].is_empty() {
                            ty.visit(V {
                                cohort: self.cohort,
                                externs: &mut entry.extern_pages,
                                num_inputs: &num_inputs,
                                num_outputs: &num_outputs,
                                in_ranges,
                                out_ranges,
                                wires: self.wires,
                            })?;
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

fn should_inline(defn: &FunctionDefinition) -> bool {
    if defn.name.contains("MNC_NOINLINE") {
        return false;
    } else if defn.name.contains("MNC_INLINE") {
        return true;
    }
    // TODO: improve this heuristic
    defn.size_hint >= 64
}

fn max_repeats_of_function(defn: &FunctionDefinition) -> NonZeroUsize {
    // TODO: improve this heuristic
    NonZeroUsize::new(
        usize::try_from(1024 * 1024 / defn.size_hint)
            .unwrap()
            .max(1),
    )
    .unwrap()
}

pub(super) fn write_circuit<'a, P: Party, VSR: ValueStreamReader + Send + 'static>(
    dst: &Path,
    circuit_chunks: flume::Receiver<eyre::Result<CircuitChunk>>,
    witness_reader: ProverPrivate<P, Inputs<VSR>>,
    private_builder: ProverPrivate<P, &'a mut PrivateBuilder>,
) -> eyre::Result<()> {
    build_circuit(dst, |cb| {
        std::thread::scope(|scope| {
            let circuit_chunks_private = match P::WHICH {
                WhichParty::Prover(e) => {
                    let (s, r) = flume::bounded::<Arc<CircuitChunk>>(32);
                    let pb = private_builder.into_inner(e);
                    let witnesses = witness_reader.into_inner(e);
                    ProverPrivate::new((
                        s,
                        std::thread::Builder::new()
                            .name("Private data thread".to_string())
                            .spawn_scoped::<_, eyre::Result<ConstructPrivateStreamsOut<'a>>>(
                                scope,
                                move || private::construct_private_streams(pb, r, witnesses),
                            )
                            .unwrap(),
                    ))
                }
                WhichParty::Verifier(e) => ProverPrivate::empty(e),
            };
            let mut functions = Vec::new();
            let mut root_cohort = PrototypeCohortBuilder::new(cb);
            let mut wires = Default::default();
            let mut root_extern_functions = Default::default();
            for chunk in circuit_chunks.into_iter() {
                let chunk = Arc::new(chunk?);
                if let WhichParty::Prover(e) = P::WHICH {
                    if let Err(_) = circuit_chunks_private
                        .as_ref()
                        .into_inner(e)
                        .0
                        .send(chunk.clone())
                    {
                        let handle = circuit_chunks_private.into_inner(e).1;
                        match handle
                            .join()
                            .unwrap()
                            .context("constructing private values")
                        {
                            Ok(_) => panic!(
                                "Private thread closed the receiver early, but didn't error out"
                            ),
                            Err(e) => return Err(e),
                        }
                    }
                }
                for (id, defn) in chunk.new_functions.iter() {
                    assert_eq!(*id, functions.len());
                    functions.push(Function {
                        definition: defn.clone(),
                        inlined: should_inline(&defn),
                    });
                }
                let mut pb = PrototypesBuilder {
                    functions: &functions,
                    wires: &mut wires,
                    cohort: &mut root_cohort,
                    extern_functions: &mut root_extern_functions,
                };
                for insn in chunk.new_root_instructions.iter() {
                    pb.add_instruction(insn)?;
                }
            }
            let root_cohort = root_cohort.finish()?;
            let mut function_cohorts: FxHashMap<(FunctionId, usize), FunctionPrototypeCohort> =
                Default::default();
            let mut function_cohort_queue: Vec<(FunctionId, usize)> = Default::default();
            function_cohort_queue.extend(root_extern_functions.iter().flat_map(
                |(id, instances)| {
                    instances
                        .iter()
                        .map(|instance| (*id, instance.num_instances))
                },
            ));
            while let Some((id, instance_count)) = function_cohort_queue.pop() {
                if function_cohorts.contains_key(&(id, instance_count)) {
                    continue;
                }
                function_cohorts.insert(
                    (id, instance_count),
                    make_function_prototype_cohort(
                        &functions,
                        id,
                        instance_count,
                        cb,
                        &mut function_cohort_queue,
                    )?,
                );
            }
            let (mut pb, mut private_streams) = circuit_chunks_private
                .map(|(s, join_handle)| {
                    std::mem::drop(s); // drop the sender so we make the privates thread terminate
                    join_handle.join().unwrap()
                })
                .lift_result()?
                .unzip();
            // TODO: use differnt vole parameters
            let mut vs = VoleSupplier::new(2000, Default::default());
            // TODO: interleave vole usage
            instantiate(
                &SmallVec::new(),
                cb,
                &mut vs,
                &mut pb,
                &mut private_streams,
                &FunctionPrototypeCohort {
                    proto: root_cohort,
                    io: Default::default(),
                    extern_functions: root_extern_functions,
                },
                &function_cohorts,
            )?;
            Ok(())
        })
    })
}

fn get_extern_pages_id(
    x: &FieldGenericProduct<Option<ExternWiresTy>>,
) -> FieldIndexedArray<Option<ExternWiresId>> {
    let mut out = Default::default();
    struct V<'a>(&'a mut FieldIndexedArray<Option<ExternWiresId>>);
    impl CompilerFieldVisitor<&'_ Option<ExternWiresTy>> for &'_ mut V<'_> {
        type Output = ();
        fn visit<FE: CompilerField>(self, extern_wires: &Option<ExternWires<FE>>) {
            self.0[FE::FIELD_TYPE] = extern_wires.as_ref().map(|ew| ew.id());
        }
    }
    x.as_ref().map(&mut V(&mut out));
    out
}

// Return the wire slices for our I/O.
fn instantiate<P: Party>(
    call_chain: &CallChain,
    cb: &mut CircuitBuilder,
    vs: &mut VoleSupplier,
    // TODO: we we ought to be able to fix this &mut
    pb: &mut ProverPrivate<P, &mut PrivateBuilder>,
    private_streams: &mut ProverPrivate<P, PrivateStreams>,
    this_func: &FunctionPrototypeCohort,
    function_cohorts: &FxHashMap<(FunctionId, usize), FunctionPrototypeCohort>,
) -> eyre::Result<FieldIndexedArray<Option<WireSlice>>> {
    // TODO: cache this allocation
    let mut externs: FxHashMap<ExternWiresId, WireSlice> = Default::default();
    // First we setup up the function I/O for the functions we call.
    for (id, instances) in this_func.extern_functions.iter() {
        // TODO: cache this allocation
        let mut call_chain = call_chain.clone();
        call_chain.push(*id);
        for instance in instances {
            let callee_io = instantiate(
                &call_chain,
                cb,
                vs,
                pb,
                private_streams,
                &function_cohorts[&(*id, instance.num_instances)],
                function_cohorts,
            )?;
            for (dst, wire_slice) in get_extern_pages_id(&instance.extern_pages)
                .0
                .iter()
                .zip(callee_io.0.iter())
            {
                match (dst, wire_slice) {
                    (Some(dst), Some(wire_slice)) => {
                        let old = externs.insert(*dst, *wire_slice);
                        assert!(old.is_none());
                    }
                    (None, None) => {}
                    _ => panic!("extern page doesn't match up with callee wire_slice"),
                }
            }
        }
    }
    // Next we set up OUR function io. This what we'll return.
    let mut our_function_io_priv = private_streams.as_mut().map(|ps| {
        ps.function_io
            .remove(call_chain)
            .unwrap_or_else(empty_fix_data)
    });
    let mut our_function_io_out = FieldIndexedArray::<Option<WireSlice>>::default();
    for ty in FieldType::ALL.iter().copied() {
        struct V<'a, 'b, 'c, P: Party> {
            our_function_io_out: &'a mut FieldIndexedArray<Option<WireSlice>>,
            cb: &'a mut CircuitBuilder<'c>,
            vs: &'a mut VoleSupplier,
            pb: &'a mut ProverPrivate<P, &'b mut PrivateBuilder>,
            fio_priv: ProverPrivate<P, Option<FixData>>,
            this_func: &'a FunctionPrototypeCohort,
            call_chain: &'a CallChain,
            externs: &'a mut FxHashMap<ExternWiresId, WireSlice>,
        }
        impl<P: Party> CompilerFieldVisitor<()> for V<'_, '_, '_, P> {
            type Output = InvariantType<eyre::Result<()>>;
            fn visit<FE: CompilerField>(self, (): ()) -> eyre::Result<()> {
                assert!(self.our_function_io_out[FE::FIELD_TYPE].is_none());
                let io = self.this_func.io.as_ref().get::<FE>();
                if let Some(io) = io {
                    // TODO: we we can reuse fix prototypes.
                    let proto = self
                        .cb
                        .new_fix_prototype(FE::FIELD_TYPE.field_mac_type(), io.len())?;
                    let voles = self.vs.supply_voles(self.cb, &proto)?;
                    let task = self.cb.instantiate(&proto, &[], &[voles])?;
                    self.cb
                        .name_task(&task, &format!("Function I/O for {:?}", self.call_chain));
                    self.pb
                        .as_mut()
                        .zip(self.fio_priv.map(|x| x.unwrap()))
                        .map(|(pb, data)| pb.associate_fix_data(&task, data))
                        .lift_result()?;
                    let fixed = task.outputs(IrType::Mac(FE::FIELD_TYPE.field_mac_type()));
                    self.our_function_io_out[FE::FIELD_TYPE] = Some(fixed);
                    let old = self.externs.insert(io.id(), fixed);
                    assert!(old.is_none());
                }
                Ok(())
            }
        }
        ty.visit(V {
            our_function_io_out: &mut our_function_io_out,
            cb,
            vs,
            fio_priv: our_function_io_priv.as_mut().map(|x| x[ty].next()),
            pb,
            this_func,
            call_chain,
            externs: &mut externs,
        })?;
    }

    let mut empty = empty_fix_data();
    this_func.proto.instantiate(
        cb,
        vs,
        &format!("Cohort for {call_chain:?}"),
        private_streams
            .as_mut()
            .map(|x| x.fixes.get_mut(call_chain).unwrap_or(&mut empty)),
        pb,
        &externs,
    )?;
    Ok(our_function_io_out)
}

struct FunctionPrototypeCohort {
    proto: PrototypeCohort,
    io: FieldGenericProduct<Option<ExternWiresTy>>,
    extern_functions: FxHashMap<FunctionId, Vec<ExternFunctionInstance>>,
}

fn make_function_prototype_cohort(
    functions: &Vec<Function>,
    FunctionId::UserDefined(id): FunctionId,
    instance_count: usize,
    cb: &mut CircuitBuilder,
    function_cohort_queue: &mut Vec<(FunctionId, usize)>,
) -> eyre::Result<FunctionPrototypeCohort> {
    // TODO: cache num_inputs, num_outputs
    let instance_count = u32::try_from(instance_count).unwrap();
    let function = &functions[id];
    let mut cohort = PrototypeCohortBuilder::new(cb);
    let mut extern_functions = Default::default();
    let mut io = FieldGenericProduct::<Option<ExternWiresTy>>::default();
    for ty in FieldType::ALL {
        struct V<'a, 'b, 'c> {
            function: &'a Function,
            cohort: &'a mut PrototypeCohortBuilder<'b, 'c>,
            io: &'a mut FieldGenericProduct<Option<ExternWiresTy>>,
            instance_count: u32,
        }
        impl CompilerFieldVisitor<()> for V<'_, '_, '_> {
            type Output = InvariantType<()>;
            fn visit<FE: CompilerField>(self, (): ()) {
                let num_inputs = self.function.definition.num_inputs();
                let num_outputs = self.function.definition.num_outputs();
                let total = u32::try_from(num_inputs[FE::FIELD_TYPE] + num_outputs[FE::FIELD_TYPE])
                    .unwrap();
                if total == 0 {
                    return;
                }
                *self.io.as_mut().get::<FE>() = Some(
                    self.cohort
                        .extern_proto(total.checked_mul(self.instance_count).unwrap()),
                );
            }
        }
        ty.visit(V {
            function,
            cohort: &mut cohort,
            io: &mut io,
            instance_count,
        });
    }
    for i in 0..instance_count {
        let mut wires = Default::default();
        // Populate wires
        for ty in FieldType::ALL {
            struct V<'a> {
                wires: &'a mut FieldIndexedArray<WireMap<'static, RawWipWire>>,
                function: &'a Function,
                i: u32,
                io: &'a FieldGenericProduct<Option<ExternWiresTy>>,
            }
            impl CompilerFieldVisitor<()> for V<'_> {
                type Output = InvariantType<eyre::Result<()>>;
                fn visit<FE: CompilerField>(self, (): ()) -> eyre::Result<()> {
                    let num_inputs = self.function.definition.num_inputs()[FE::FIELD_TYPE];
                    let num_outputs = self.function.definition.num_outputs()[FE::FIELD_TYPE];
                    let total = u32::try_from(num_inputs + num_outputs).unwrap();
                    if total == 0 {
                        return Ok(());
                    }
                    let io = &self.io.as_ref().get::<FE>().as_ref().unwrap();
                    let mut wire_base = 0;
                    // Allocate outputs
                    for (Type::Field(field), len) in self.function.definition.output_sizes.iter() {
                        if *field != FE::FIELD_TYPE {
                            continue;
                        }
                        self.wires[FE::FIELD_TYPE].alloc(wire_base, wire_base + len - 1)?;
                        wire_base += len;
                    }
                    // We know that the sum of wire ranges already fits in a u32.
                    let mut extern_base = self.i * total + num_outputs as u32;
                    // Set up inputs
                    for (Type::Field(field), len) in self.function.definition.input_sizes.iter() {
                        if *field != FE::FIELD_TYPE {
                            continue;
                        }
                        self.wires[FE::FIELD_TYPE].alloc(wire_base, wire_base + len - 1)?;
                        // TODO: do this more efficiently.
                        for _ in 0..*len {
                            self.wires[FE::FIELD_TYPE]
                                .insert(wire_base, io.get(extern_base).into());
                            wire_base += 1;
                            extern_base += 1;
                        }
                    }
                    Ok(())
                }
            }
            ty.visit(V {
                wires: &mut wires,
                function,
                i,
                io: &io,
            })?;
        }
        // Execute the instructions
        let mut pb = PrototypesBuilder {
            functions: &functions,
            wires: &mut wires,
            cohort: &mut cohort,
            extern_functions: &mut extern_functions,
        };
        for insn in function.definition.body.iter() {
            pb.add_instruction(insn)?;
        }
        // Assert that the output matches what was fixed.
        for ty in FieldType::ALL {
            struct V<'a, 'b, 'c> {
                wires: &'a mut FieldIndexedArray<WireMap<'static, RawWipWire>>,
                function: &'a Function,
                i: u32,
                io: &'a FieldGenericProduct<Option<ExternWiresTy>>,
                cohort: &'a mut PrototypeCohortBuilder<'b, 'c>,
            }
            impl CompilerFieldVisitor<()> for V<'_, '_, '_> {
                type Output = InvariantType<eyre::Result<()>>;
                fn visit<FE: CompilerField>(self, (): ()) -> eyre::Result<()> {
                    let num_inputs = self.function.definition.num_inputs()[FE::FIELD_TYPE];
                    let num_outputs = self.function.definition.num_outputs()[FE::FIELD_TYPE];
                    let total = u32::try_from(num_inputs + num_outputs).unwrap();
                    if total == 0 {
                        return Ok(());
                    }
                    let mut base = self.i * total;
                    let io = &self.io.as_ref().get::<FE>().as_ref().unwrap();
                    for out_wire in 0..num_outputs {
                        let expected_out = io.get(base);
                        let actual_out = self.wires[FE::FIELD_TYPE]
                            .get(out_wire)?
                            .assert_field::<FE>();
                        let zero = self
                            .cohort
                            .push_linear([(expected_out, FE::ONE), (actual_out, -FE::ONE)])?;
                        self.cohort.push_assert_zero(zero)?;
                        base += 1;
                    }
                    Ok(())
                }
            }
            ty.visit(V {
                wires: &mut wires,
                function,
                i,
                io: &io,
                cohort: &mut cohort,
            })?;
        }
    }
    let cohort = cohort.finish()?;
    function_cohort_queue.extend(extern_functions.iter().flat_map(|(id, instances)| {
        instances
            .iter()
            .map(|instance| (*id, instance.num_instances))
    }));
    Ok(FunctionPrototypeCohort {
        proto: cohort,
        io,
        extern_functions,
    })
}
