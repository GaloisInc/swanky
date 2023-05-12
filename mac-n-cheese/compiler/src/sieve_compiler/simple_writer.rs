use std::{
    any::TypeId, collections::BTreeMap, marker::PhantomData, path::Path, sync::Arc, time::Instant,
};

use eyre::{Context, ContextCompat};
use mac_n_cheese_ir::circuit_builder::{
    build_circuit, vole_supplier::VoleSupplier, CircuitBuilder, PrivateBuilder, TaskOutputRef,
    TaskPrototypeRef,
};
use mac_n_cheese_party::{
    private::{ProverPrivate, ProverPrivateCopy},
    Party, WhichParty,
};
use mac_n_cheese_sieve_parser::ValueStreamReader;
use mac_n_cheese_wire_map::WireMap;
use rustc_hash::FxHashMap;
use scuttlebutt::field::F2;

use super::{
    circuit_ir::{
        FieldInstruction, FieldInstructions, FieldInstructionsTy, FunctionDefinition, FunctionId,
    },
    put,
    supported_fields::{FieldType, InvariantType},
    to_fe, to_k_bits, to_k_flipped_bits, Inputs,
};
use crate::sieve_compiler::{
    circuit_ir::{CircuitChunk, CounterInfo, Instruction, Permissiveness, WireRange},
    supported_fields::{
        CompilerField, CompilerFieldVisitor, FieldGenericIdentity, FieldGenericProduct,
        FieldGenericType, FieldIndexedArray,
    },
};
use mac_n_cheese_ir::compilation_format::wire_format::Wire as IrWire;
use mac_n_cheese_ir::compilation_format::Type as IrType;

#[derive(Clone, Copy, Debug)]
struct WireRef {
    which_task: u32,
    which_wire: u32,
}

// map from task id to the indicies of the inputs we take and their lengths.
type Protos = BTreeMap<u32, (TaskPrototypeRef, Vec<(u32, u32)>)>;

struct Resolver {
    my_id: u32,
    // map from task id to (index, size)
    mapping: FxHashMap<u32, (u32, u32)>,
    input_sizes: Vec<u32>,
}

impl Resolver {
    fn make<P: Party, FE: CompilerField>(
        cm: &CircuitMaker<P, FE>,
        my_id: u32,
        wires: impl Iterator<Item = WireRef>,
    ) -> Self {
        let mut out = Resolver {
            my_id,
            mapping: Default::default(),
            input_sizes: Default::default(),
        };
        for wire in wires {
            let tid = wire.which_task;
            if tid == my_id || out.mapping.contains_key(&tid) {
                continue;
            }
            let new_id = u32::try_from(out.input_sizes.len()).unwrap();
            let sz = if tid == cm.fix_id {
                u32::try_from(cm.fix_data.len()).unwrap()
            } else if tid == cm.constant_id {
                u32::try_from(cm.constant_data.len()).unwrap()
            } else if tid == cm.linear_id {
                u32::try_from(cm.linear_data.len()).unwrap()
            } else if let Some(task) = cm.finished_tasks.get(&tid) {
                task.outputs(IrType::Mac(FE::FIELD_TYPE.field_mac_type()))
                    .len()
            } else if let Some((proto, _)) = cm.linear_protos.get(&tid) {
                proto.outputs()[0].count()
            } else {
                panic!("cannot find task id {tid}");
            };
            out.mapping.insert(tid, (new_id, sz));
            out.input_sizes.push(sz);
        }
        out
    }
    fn resolve(&self, wire: WireRef) -> IrWire {
        if wire.which_task == self.my_id {
            IrWire::own_wire(wire.which_wire)
        } else {
            IrWire::input_wire(self.mapping[&wire.which_task].0, wire.which_wire)
        }
    }
    fn finish(self) -> Vec<(u32, u32)> {
        debug_assert_eq!(self.input_sizes.len(), self.mapping.len());
        let mut out = self
            .input_sizes
            .into_iter()
            .map(|x| (u32::MAX, x))
            .collect::<Vec<_>>();
        for (tid, (new_id, _)) in self.mapping.into_iter() {
            out[new_id as usize].0 = tid;
        }
        out
    }
}

struct CircuitMaker<P: Party, FE: CompilerField> {
    fix_id: u32,
    fix_data: Vec<ProverPrivateCopy<P, FE>>,
    constant_id: u32,
    constant_data: Vec<FE>,
    linear_id: u32,
    linear_data: Vec<[(WireRef, FE); 2]>,
    linear_protos: Protos,
    assert_zero_id: u32,
    assert_zero_data: Vec<WireRef>,
    assert_zero_protos: Protos,
    assert_multiply_id: u32,
    assert_multiply_data: Vec<[WireRef; 3]>,
    assert_multiply_protos: Protos,
    next_id: u32,
    finished_tasks: FxHashMap<u32, TaskOutputRef>,
}

impl<P: Party, FE: CompilerField> Default for CircuitMaker<P, FE> {
    fn default() -> Self {
        Self {
            fix_id: 0,
            fix_data: Default::default(),
            constant_id: 1,
            constant_data: Default::default(),
            linear_id: 2,
            linear_data: Default::default(),
            linear_protos: Default::default(),
            assert_zero_id: 3,
            assert_zero_data: Default::default(),
            assert_zero_protos: Default::default(),
            assert_multiply_id: 4,
            assert_multiply_data: Default::default(),
            assert_multiply_protos: Default::default(),
            next_id: 5,
            finished_tasks: Default::default(),
        }
    }
}
impl<P: Party, FE: CompilerField> CircuitMaker<P, FE> {
    fn next_id(x: &mut u32) -> u32 {
        let out = *x;
        *x += 1;
        out
    }
    fn insert_task(&mut self, id: u32, task: TaskOutputRef) {
        let old = self.finished_tasks.insert(id, task);
        assert!(old.is_none());
    }
    fn flush_fix(
        &mut self,
        cb: &mut CircuitBuilder,
        vs: &mut VoleSupplier,
        pb: &mut ProverPrivate<P, &mut PrivateBuilder>,
    ) -> eyre::Result<()> {
        if self.fix_data.is_empty() {
            return Ok(());
        }
        let task = cb.new_fix_prototype(
            FE::FIELD_TYPE.field_mac_type(),
            self.fix_data.len().try_into().unwrap(),
        )?;
        let voles = vs.supply_voles(cb, &task)?;
        let task = cb.instantiate(&task, &[], &[voles])?;
        if let WhichParty::Prover(e) = P::WHICH {
            pb.as_mut().into_inner(e).write_fix_data(&task, |dst| {
                for x in self.fix_data.drain(..) {
                    dst.add(x.into_inner(e))?;
                }
                Ok(())
            })?;
        }
        self.fix_data.clear();
        self.insert_task(self.fix_id, task);
        self.fix_id = Self::next_id(&mut self.next_id);
        Ok(())
    }
    fn fix(
        &mut self,
        cb: &mut CircuitBuilder,
        vs: &mut VoleSupplier,
        pb: &mut ProverPrivate<P, &mut PrivateBuilder>,
        x: ProverPrivateCopy<P, FE>,
    ) -> eyre::Result<WireRef> {
        let out = WireRef {
            which_task: self.fix_id,
            which_wire: self.fix_data.len().try_into().unwrap(),
        };
        self.fix_data.push(x);
        if self.fix_data.len() >= 1024 * 1024 {
            self.flush_fix(cb, vs, pb)?;
        }
        Ok(out)
    }
    fn flush_constant(&mut self, cb: &mut CircuitBuilder) -> eyre::Result<()> {
        if self.constant_data.is_empty() {
            return Ok(());
        }
        let proto = cb.new_constant_prototype(
            FE::FIELD_TYPE.field_mac_type(),
            self.constant_data.drain(..),
        )?;
        self.insert_task(self.constant_id, cb.instantiate(&proto, &[], &[])?);
        self.constant_id = Self::next_id(&mut self.next_id);
        Ok(())
    }
    fn constant(&mut self, cb: &mut CircuitBuilder, x: FE) -> eyre::Result<WireRef> {
        let out = WireRef {
            which_task: self.constant_id,
            which_wire: self.constant_data.len().try_into().unwrap(),
        };
        self.constant_data.push(x);
        if self.constant_data.len() >= 1024 * 1024 {
            self.flush_constant(cb)?;
        }
        Ok(out)
    }
    fn flush_assert_zero(&mut self, cb: &mut CircuitBuilder) -> eyre::Result<()> {
        if self.assert_zero_data.is_empty() {
            return Ok(());
        }
        let id = self.assert_zero_id;
        let r = Resolver::make(self, id, self.assert_zero_data.iter().copied());
        let proto = cb.new_assert_zero_prototype(
            FE::FIELD_TYPE.field_mac_type(),
            &r.input_sizes,
            self.assert_zero_data.drain(..).map(|x| r.resolve(x)),
        )?;
        self.assert_zero_protos
            .insert(self.assert_zero_id, (proto, r.finish()));
        self.assert_zero_id = Self::next_id(&mut self.next_id);
        Ok(())
    }
    fn assert_zero(&mut self, cb: &mut CircuitBuilder, x: WireRef) -> eyre::Result<()> {
        self.assert_zero_data.push(x);
        if self.assert_zero_data.len() >= 1024 * 1024 {
            self.flush_assert_zero(cb)?;
        }
        Ok(())
    }

    fn flush_assert_multiply(&mut self, cb: &mut CircuitBuilder) -> eyre::Result<()> {
        if self.assert_multiply_data.is_empty() {
            return Ok(());
        }
        let id = self.assert_multiply_id;
        let r = Resolver::make(
            self,
            id,
            self.assert_multiply_data
                .iter()
                .flat_map(|x| (*x).into_iter()),
        );
        let proto = cb.new_assert_multiply_prototype(
            FE::FIELD_TYPE.field_mac_type(),
            &r.input_sizes,
            self.assert_multiply_data
                .drain(..)
                .map(|[x, y, z]| [r.resolve(x), r.resolve(y), r.resolve(z)]),
        )?;
        self.assert_multiply_protos
            .insert(self.assert_multiply_id, (proto, r.finish()));
        self.assert_multiply_id = Self::next_id(&mut self.next_id);
        Ok(())
    }
    fn assert_multiply(
        &mut self,
        cb: &mut CircuitBuilder,
        x: WireRef,
        y: WireRef,
        z: WireRef,
    ) -> eyre::Result<()> {
        self.assert_multiply_data.push([x, y, z]);
        if self.assert_multiply_data.len() >= 1024 * 1024 {
            self.flush_assert_multiply(cb)?;
        }
        Ok(())
    }
    fn linear(
        &mut self,
        cb: &mut CircuitBuilder,
        a: WireRef,
        a_c: FE,
        b: WireRef,
        b_c: FE,
    ) -> eyre::Result<WireRef> {
        if TypeId::of::<FE>() == TypeId::of::<F2>() {
            match (a_c == FE::ONE, b_c == FE::ONE) {
                (true, true) => {
                    // Do the normal thing
                }
                (true, false) => {
                    return Ok(a);
                }
                (false, true) => {
                    return Ok(b);
                }
                (false, false) => {
                    return self.constant(cb, FE::ZERO);
                }
            }
        }
        let out = WireRef {
            which_task: self.linear_id,
            which_wire: self.linear_data.len().try_into().unwrap(),
        };
        self.linear_data.push([(a, a_c), (b, b_c)]);
        if self.linear_data.len() >= 1024 * 1024 {
            self.flush_linear(cb)?;
        }
        Ok(out)
    }
    fn flush_linear(&mut self, cb: &mut CircuitBuilder) -> eyre::Result<()> {
        if self.linear_data.is_empty() {
            return Ok(());
        }
        let id = self.linear_id;
        let r = Resolver::make(
            self,
            id,
            self.linear_data
                .iter()
                .flat_map(|[(a, _), (b, _)]| [*a, *b].into_iter()),
        );
        let proto = if TypeId::of::<FE>() == TypeId::of::<F2>() {
            cb.new_add_prototype(
                FE::FIELD_TYPE.field_mac_type(),
                &r.input_sizes,
                self.linear_data.drain(..).map(|[(a, a_c), (b, b_c)]| {
                    debug_assert_eq!(a_c, FE::ONE);
                    debug_assert_eq!(b_c, FE::ONE);
                    [r.resolve(a), r.resolve(b)]
                }),
            )?
        } else {
            cb.new_linear_prototype(
                FE::FIELD_TYPE.field_mac_type(),
                &r.input_sizes,
                self.linear_data
                    .drain(..)
                    .map(|[(a, a_c), (b, b_c)]| [(r.resolve(a), a_c), (r.resolve(b), b_c)]),
            )?
        };
        self.linear_protos
            .insert(self.linear_id, (proto, r.finish()));
        self.linear_id = Self::next_id(&mut self.next_id);
        Ok(())
    }
}

field_generic_type!(CircuitMakerTy<P: Party, FE: CompilerField> => CircuitMaker<P, FE>);
field_generic_type!(ValuedWire<P: Party, FE: CompilerField> => (WireRef, ProverPrivateCopy<P, FE>));

fn mul<P: Party, FE: CompilerField>(
    cb: &mut CircuitBuilder,
    vs: &mut VoleSupplier,
    pb: &mut ProverPrivate<P, &mut PrivateBuilder>,
    cm: &mut CircuitMaker<P, FE>,
    (left, left_v): (WireRef, ProverPrivateCopy<P, FE>),
    (right, right_v): (WireRef, ProverPrivateCopy<P, FE>),
) -> eyre::Result<(WireRef, ProverPrivateCopy<P, FE>)> {
    let product_v = left_v.zip(right_v).map(|(a, b)| a * b);
    let product = cm.fix(cb, vs, pb, product_v)?;
    cm.assert_multiply(cb, left, right, product)?;
    Ok((product, product_v))
}

struct EvaluateFieldInstructions<'a, 'b, 'c, 'd, P: Party, VSR: ValueStreamReader> {
    wm: &'a mut FieldGenericProduct<WireMap<'b, ValuedWire<P>>>,
    cb: &'a mut CircuitBuilder<'c>,
    vs: &'a mut VoleSupplier,
    pb: &'a mut ProverPrivate<P, &'d mut PrivateBuilder>,
    cm: &'a mut FieldGenericProduct<CircuitMakerTy<P>>,
    witnesses: &'a mut ProverPrivate<P, Inputs<VSR>>,
    public_inputs: &'a mut FieldGenericProduct<std::vec::IntoIter<FieldGenericIdentity>>,
}

impl<'a, 'b, 'c, P: Party, VSR: ValueStreamReader> CompilerFieldVisitor<&'c FieldInstructionsTy>
    for EvaluateFieldInstructions<'a, 'b, '_, '_, P, VSR>
{
    type Output = InvariantType<eyre::Result<()>>;
    fn visit<FE: CompilerField>(self, instructions: &'c FieldInstructions<FE>) -> eyre::Result<()> {
        let mut witness_buf = Vec::<FE>::with_capacity(1);
        let wm = self.wm.as_mut().get::<FE>();
        let public_inputs = self.public_inputs.as_mut().get::<FE>();
        let cm = self.cm.as_mut().get::<FE>();
        for insn in instructions.iter() {
            match insn {
                FieldInstruction::Constant { dst, src } => put(
                    wm,
                    dst,
                    (cm.constant(self.cb, src)?, ProverPrivateCopy::new(src)),
                )?,
                FieldInstruction::AssertZero { src } => {
                    let (src, src_value) = *wm.get(src)?;
                    if let WhichParty::Prover(e) = P::WHICH {
                        eyre::ensure!(
                            src_value.into_inner(e) == FE::ZERO,
                            "assert zero will fail!"
                        );
                    }
                    cm.assert_zero(self.cb, src)?;
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
                    let (left, left_v) = *wm.get(left).with_context(|| {
                        format!(
                            "Add to {dst} from {left} in {}",
                            std::any::type_name::<FE>()
                        )
                    })?;
                    let (right, right_v) = *wm.get(right)?;
                    put(
                        wm,
                        dst,
                        (
                            cm.linear(self.cb, left, FE::ONE, right, FE::ONE)?,
                            left_v.zip(right_v).map(|(a, b)| a + b),
                        ),
                    )?;
                }
                FieldInstruction::Mul { dst, left, right } => {
                    let (left, left_v) = *wm.get(left)?;
                    let (right, right_v) = *wm.get(right)?;
                    let (product, product_v) = mul(
                        self.cb,
                        self.vs,
                        self.pb,
                        cm,
                        (left, left_v),
                        (right, right_v),
                    )?;
                    put(wm, dst, (product, product_v))?;
                }
                FieldInstruction::AddConstant { dst, left, right } => {
                    let (left, left_v) = *wm.get(left)?;
                    let right_c = cm.constant(self.cb, right)?;
                    put(
                        wm,
                        dst,
                        (
                            cm.linear(self.cb, left, FE::ONE, right_c, FE::ONE)?,
                            left_v.map(|x| x + right),
                        ),
                    )?;
                }
                FieldInstruction::MulConstant { dst, left, right } => {
                    let (left, left_v) = *wm.get(left)?;
                    put(
                        wm,
                        dst,
                        (
                            cm.linear(self.cb, left, right, left, FE::ZERO)?,
                            left_v.map(|x| x * right),
                        ),
                    )?;
                }
                FieldInstruction::GetPublicInput { dst } => {
                    let c = public_inputs.next().context("need public input")?;
                    put(
                        wm,
                        dst,
                        (cm.constant(self.cb, c)?, ProverPrivateCopy::new(c)),
                    )?;
                }
                FieldInstruction::GetWitness { dst } => {
                    witness_buf.clear();
                    let value = ProverPrivateCopy::from(
                        self.witnesses
                            .as_mut()
                            .map(|x| x.read_into(1, &mut witness_buf))
                            .lift_result()?
                            .map(|()| witness_buf[0]),
                    );
                    put(wm, dst, (cm.fix(self.cb, self.vs, self.pb, value)?, value))?;
                }
                FieldInstruction::Alloc { first, last } => wm.alloc(first, last)?,
                FieldInstruction::Free { first, last } => wm.free(first, last)?,
            }
        }
        Ok(())
    }
}

fn eval<P: Party, VSR: ValueStreamReader>(
    cb: &mut CircuitBuilder,
    vs: &mut VoleSupplier,
    pb: &mut ProverPrivate<P, &mut PrivateBuilder>,
    wm: &mut FieldGenericProduct<WireMap<ValuedWire<P>>>,
    cm: &mut FieldGenericProduct<CircuitMakerTy<P>>,
    witnesses: &mut ProverPrivate<P, Inputs<VSR>>,
    instructions: &[Instruction],
    public_inputs: &mut FieldGenericProduct<std::vec::IntoIter<FieldGenericIdentity>>,
    functions: &[Arc<FunctionDefinition>],
) -> eyre::Result<()> {
    for instruction in instructions {
        match instruction {
            Instruction::FieldInstructions(instructions) => {
                instructions.as_ref().visit(EvaluateFieldInstructions {
                    wm,
                    witnesses,
                    public_inputs,
                    cb,
                    vs,
                    pb,
                    cm,
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
                    struct V<'a, 'b, P: Party> {
                        cb: &'a mut CircuitBuilder<'b>,
                        cm: &'a mut FieldGenericProduct<CircuitMakerTy<P>>,
                        in_ranges: &'a FieldIndexedArray<Vec<WireRange>>,
                        out_ranges: &'a FieldIndexedArray<Vec<WireRange>>,
                        counter_info: &'a Option<CounterInfo>,
                        phantom: PhantomData<P>,
                    }
                    impl<'a, 'b, 'c, P: Party>
                        CompilerFieldVisitor<&'b mut WireMap<'c, ValuedWire<P>>>
                        for &'_ mut V<'a, '_, P>
                    {
                        type Output = eyre::Result<WireMap<'b, ValuedWire<P>>>;
                        fn visit<FE: CompilerField>(
                            self,
                            parent: &'b mut WireMap<'c, (WireRef, ProverPrivateCopy<P, FE>)>,
                        ) -> eyre::Result<WireMap<'b, (WireRef, ProverPrivateCopy<P, FE>)>>
                        {
                            let cm = self.cm.as_mut().get::<FE>();

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
                                                let counter_b_v = ProverPrivateCopy::new(b);
                                                let counter_b = cm.constant(self.cb, b)?;

                                                put(&mut out, w, (counter_b, counter_b_v))?;
                                            }
                                        }
                                        _ => {
                                            debug_assert_eq!(num_wires, 1);

                                            let start = total_outputs + num_env_for_field as u64;
                                            out.alloc(start, start)?;

                                            let counter = to_fe(value)?;
                                            let counter_v = ProverPrivateCopy::new(counter);
                                            let counter = cm.constant(self.cb, counter)?;

                                            put(&mut out, start, (counter, counter_v))?;
                                        }
                                    }
                                }
                            }

                            Ok(out)
                        }
                    }
                    wm.as_mut().map_result(&mut V::<P> {
                        cb,
                        cm,
                        in_ranges,
                        out_ranges,
                        counter_info,
                        phantom: PhantomData,
                    })?
                };
                eval(
                    cb,
                    vs,
                    pb,
                    &mut child_wire_maps,
                    cm,
                    witnesses,
                    &function.body,
                    public_inputs,
                    functions,
                )?;
            }
            Instruction::MuxCall {
                permissiveness,
                field_type,
                out_ranges,
                in_ranges,
            } => {
                struct V<'a, 'b, 'c, 'd, P: Party> {
                    wm: &'a mut FieldGenericProduct<WireMap<'b, ValuedWire<P>>>,
                    cb: &'a mut CircuitBuilder<'c>,
                    vs: &'a mut VoleSupplier,
                    pb: &'a mut ProverPrivate<P, &'d mut PrivateBuilder>,
                    cm: &'a mut FieldGenericProduct<CircuitMakerTy<P>>,
                    permissiveness: &'a Permissiveness,
                    in_ranges: &'a Vec<WireRange>,
                    out_ranges: &'a Vec<WireRange>,
                    phantom: PhantomData<P>,
                }
                impl<'a, 'b, P: Party> CompilerFieldVisitor for &'_ mut V<'a, 'b, '_, '_, P> {
                    type Output = InvariantType<eyre::Result<()>>;
                    fn visit<FE: CompilerField>(self, _arg: ()) -> eyre::Result<()> {
                        let wm = self.wm.as_mut().get::<FE>();
                        let cm = self.cm.as_mut().get::<FE>();

                        for range in self.out_ranges.iter() {
                            wm.alloc_range_if_unallocated(range.start, range.inclusive_end)?;
                        }

                        debug_assert_ne!(self.in_ranges.len(), 0);

                        let cond_wire_range = self.in_ranges[0];
                        let branch_inputs = &self.in_ranges[1..];
                        let num_ranges_per_branch = self.out_ranges.len();
                        debug_assert_eq!(branch_inputs.len() % num_ranges_per_branch, 0);

                        // N
                        let num_branches = branch_inputs.len() / num_ranges_per_branch;

                        // Build one-hot selecting vector, convince verifier it's correct. F2 has special behavior.
                        let mut g: Vec<(WireRef, ProverPrivateCopy<P, FE>)> =
                            Vec::with_capacity(num_branches);
                        match FE::FIELD_TYPE {
                            FieldType::F2 => {
                                let mut cond_wires =
                                    Vec::with_capacity(cond_wire_range.len() as usize);
                                for w in cond_wire_range.start..=cond_wire_range.inclusive_end {
                                    cond_wires.push(*wm.get(w)?);
                                }

                                for i in 0..num_branches {
                                    let i: Vec<FE> = to_k_flipped_bits(i, cond_wires.len())?;

                                    // TODO: Move to inner loop?
                                    let one = cm.constant(self.cb, FE::ONE)?;

                                    // Xor corresponding bits
                                    let mut xors = Vec::with_capacity(cond_wires.len());
                                    for (i_j, &(c_j, c_j_v)) in
                                        i.into_iter().rev().zip(cond_wires.iter())
                                    {
                                        xors.push((
                                            cm.linear(self.cb, c_j, FE::ONE, one, i_j)?,
                                            c_j_v.map(|x| x + i_j),
                                        ));
                                    }

                                    // Multiply the results
                                    let (mut g_i, mut g_i_v) =
                                        xors.get(0).context("Mux condition empty")?;
                                    for &(xor, xor_v) in &xors[1..] {
                                        (g_i, g_i_v) = mul(
                                            self.cb,
                                            self.vs,
                                            self.pb,
                                            cm,
                                            (g_i, g_i_v),
                                            (xor, xor_v),
                                        )?;
                                    }

                                    g.push((g_i, g_i_v));
                                }
                            }
                            _ => {
                                debug_assert_eq!(cond_wire_range.len(), 1);

                                // c
                                let (cond, cond_v) = *wm.get(cond_wire_range.start)?;

                                for i in 0..num_branches {
                                    let i = to_fe(i)?;

                                    // g
                                    let g_i_v =
                                        cond_v.map(|c| if c == i { FE::ONE } else { FE::ZERO });
                                    let g_i = cm.fix(self.cb, self.vs, self.pb, g_i_v)?;
                                    g.push((g_i, g_i_v));

                                    // AssertNeqZero(c - i, 1 - g_i)
                                    for (i, &(g_i, _)) in g.iter().enumerate() {
                                        let i = to_fe(i)?;

                                        let one = cm.constant(self.cb, FE::ONE)?;

                                        let x_v = cond_v.map(|c| c - i);
                                        let x = cm.linear(self.cb, cond, FE::ONE, one, -i)?;

                                        let x_prime_v = x_v.map(|x| {
                                            if x != FE::ZERO {
                                                x.inverse()
                                            } else {
                                                FE::ZERO
                                            }
                                        });
                                        let x_prime =
                                            cm.fix(self.cb, self.vs, self.pb, x_prime_v)?;

                                        let b = cm.linear(self.cb, one, FE::ONE, g_i, -FE::ONE)?;

                                        cm.assert_multiply(self.cb, x, x_prime, b)?;
                                        cm.assert_multiply(self.cb, x, b, x)?;
                                    }
                                }
                            }
                        }

                        // For strict mode, assert sum(g_i) = 1
                        if let Permissiveness::Strict = self.permissiveness {
                            let (mut sum, _) = g.get(0).context("Mux has no branches")?;

                            // sum(g_i)
                            for &(g_i, _) in &g[1..] {
                                sum = cm.linear(self.cb, sum, FE::ONE, g_i, FE::ONE)?;
                            }

                            // sum(g_i) - 1
                            let one = cm.constant(self.cb, FE::ONE)?;
                            let sum_minus_one = cm.linear(self.cb, sum, FE::ONE, one, -FE::ONE)?;

                            // AsserZero(sum(g_i) - 1)
                            cm.assert_zero(self.cb, sum_minus_one)?;
                        }

                        // Expanded input wire ranges, chunked by branch
                        let branch_input_wires = branch_inputs
                            .chunks_exact(num_ranges_per_branch)
                            .map(|branch_ranges| {
                                let mut v = Vec::new();
                                for range in branch_ranges {
                                    for w in range.start..=range.inclusive_end {
                                        v.push(w)
                                    }
                                }
                                // This property guarantees that the indexing done later is safe
                                debug_assert_eq!(
                                    v.len(),
                                    self.out_ranges
                                        .iter()
                                        .fold(0, |acc, range| { acc + range.len() as usize })
                                );
                                v
                            })
                            .collect::<Vec<_>>();

                        // Output wires computed by dot product of g and the
                        // vector of all branch wires in that position
                        for out_range in self.out_ranges {
                            for (j, out_wire) in
                                (out_range.start..=out_range.inclusive_end).enumerate()
                            {
                                // Get the jth wire of every branch's input range
                                let mut jth_branch_wires =
                                    branch_input_wires.iter().map(|branch| branch[j]);
                                debug_assert_eq!(jth_branch_wires.len(), num_branches);

                                // The first product is computed outside the loop
                                let &g_0 = g.get(0).context("Mux has no branches")?;

                                // b_i_j is the jth wire of input branch i
                                let b_0_j = *wm.get(
                                    jth_branch_wires
                                        .next()
                                        .context("Mux has no input branches")?,
                                )?;

                                let (mut sum, mut sum_v) =
                                    mul(self.cb, self.vs, self.pb, cm, g_0, b_0_j)?;

                                for (b_i_j, &g_i) in jth_branch_wires.zip(&g[1..]) {
                                    let b_i_j = *wm.get(b_i_j)?;
                                    let (prod, prod_v) =
                                        mul(self.cb, self.vs, self.pb, cm, g_i, b_i_j)?;
                                    sum = cm.linear(self.cb, sum, FE::ONE, prod, FE::ONE)?;
                                    sum_v = sum_v.zip(prod_v).map(|(s, p)| s + p);
                                }

                                put(wm, out_wire, (sum, sum_v))?;
                            }
                        }

                        Ok(())
                    }
                }

                field_type.visit(&mut V {
                    wm,
                    cb,
                    vs,
                    pb,
                    cm,
                    permissiveness,
                    in_ranges,
                    out_ranges,
                    phantom: PhantomData,
                })?;
            }
        }
    }
    Ok(())
}

pub(super) fn write_circuit<P: Party, VSR: ValueStreamReader + Send + 'static>(
    dst: &Path,
    circuit_chunks: flume::Receiver<eyre::Result<CircuitChunk>>,
    mut witness_reader: ProverPrivate<P, Inputs<VSR>>,
    mut private_builder: ProverPrivate<P, &mut PrivateBuilder>,
) -> eyre::Result<()> {
    build_circuit(dst, |cb| {
        let mut functions = Vec::new();
        let mut root_wm = FieldGenericProduct::<WireMap<ValuedWire<P>>>::default();
        let start = Instant::now();
        let mut vs = VoleSupplier::new(1024, Default::default());
        let mut cm: FieldGenericProduct<CircuitMakerTy<P>> = Default::default();
        for chunk in circuit_chunks.into_iter() {
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
                cb,
                &mut vs,
                &mut private_builder,
                &mut root_wm,
                &mut cm,
                &mut witness_reader,
                &chunk.new_root_instructions,
                &mut public_inputs,
                &functions,
            )?;
        }
        struct V<'a, 'b, 'c, P: Party> {
            cb: &'a mut CircuitBuilder<'c>,
            pb: &'a mut ProverPrivate<P, &'b mut PrivateBuilder>,
            vs: &'a mut VoleSupplier,
            phantom: PhantomData<P>,
        }
        impl<P: Party> CompilerFieldVisitor<CircuitMakerTy<P>> for &'_ mut V<'_, '_, '_, P> {
            type Output = eyre::Result<()>;
            fn visit<FE: CompilerField>(self, mut cm: CircuitMaker<P, FE>) -> eyre::Result<()> {
                cm.flush_fix(self.cb, self.vs, self.pb)?;
                cm.flush_constant(self.cb)?;
                cm.flush_assert_zero(self.cb)?;
                cm.flush_assert_multiply(self.cb)?;
                cm.flush_linear(self.cb)?;
                fn instantiate_protos(
                    ty: IrType,
                    cb: &mut CircuitBuilder,
                    protos: &Protos,
                    finished_tasks: &mut FxHashMap<u32, TaskOutputRef>,
                ) -> eyre::Result<()> {
                    let mut inputs = Vec::new();
                    for (task_id, (proto, tids_and_lengths)) in protos.iter() {
                        inputs.clear();
                        for (tid, len) in tids_and_lengths {
                            assert_ne!(task_id, tid);
                            inputs.push(
                                finished_tasks
                                    .get(tid)
                                    .with_context(|| {
                                        format!("{task_id} is unable to find task id {tid}")
                                    })
                                    .unwrap()
                                    .outputs(ty)
                                    .slice(0..*len),
                            );
                        }
                        let task = cb.instantiate(proto, &inputs, &[])?;
                        let old = finished_tasks.insert(*task_id, task);
                        assert!(old.is_none());
                    }
                    Ok(())
                }
                eprintln!("linear instantiate");
                instantiate_protos(
                    IrType::Mac(FE::FIELD_TYPE.field_mac_type()),
                    self.cb,
                    &cm.linear_protos,
                    &mut cm.finished_tasks,
                )?;
                eprintln!("assert mult instantiate");
                instantiate_protos(
                    IrType::Mac(FE::FIELD_TYPE.field_mac_type()),
                    self.cb,
                    &cm.assert_multiply_protos,
                    &mut cm.finished_tasks,
                )?;
                eprintln!("assert zero instantiate");
                instantiate_protos(
                    IrType::Mac(FE::FIELD_TYPE.field_mac_type()),
                    self.cb,
                    &cm.assert_zero_protos,
                    &mut cm.finished_tasks,
                )?;
                Ok(())
            }
        }
        cm.map_result(&mut V {
            phantom: PhantomData,
            cb,
            pb: &mut private_builder,
            vs: &mut vs,
        })?;
        dbg!(
            mac_n_cheese_wire_map::LOOKUP_MISSES.load(std::sync::atomic::Ordering::Relaxed),
            mac_n_cheese_wire_map::NUM_LOOKUPS.load(std::sync::atomic::Ordering::Relaxed),
            start.elapsed(),
        );
        Ok(())
    })?;
    Ok(())
}
