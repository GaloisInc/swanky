use std::any::TypeId;
use std::fmt::Debug;
use std::marker::PhantomData;

use crate::sieve_compiler::supported_fields::{
    CompilerField, CompilerFieldVisitor, FieldGenericIdentity, FieldGenericProduct,
    FieldGenericType, FieldIndexedArray, FieldType, InvariantType,
};
use eyre::ContextCompat;
use mac_n_cheese_ir::circuit_builder::vole_supplier::VoleSupplier;
use mac_n_cheese_ir::circuit_builder::{FixData, WireSlice};
use mac_n_cheese_ir::compilation_format::{TaskKind, TaskPrototypeId, WireSize};
use mac_n_cheese_ir::{
    circuit_builder::{CircuitBuilder, PrivateBuilder, TaskOutputRef, TaskPrototypeRef},
    compilation_format::wire_format::Wire as IrWire,
    compilation_format::Type as IrType,
};
use mac_n_cheese_party::private::ProverPrivate;
use mac_n_cheese_party::Party;
use rustc_hash::FxHashMap;
use scuttlebutt::field::F2;

/// The id of a prototype in this cohort.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
struct WipPrototypeId<FE: CompilerField>(u32, PhantomData<FE>);

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub(super) struct RawWipWire {
    proto: u32,
    idx: WireSize,
}
impl RawWipWire {
    pub(super) fn assert_field<FE: CompilerField>(&self) -> WipWire<FE> {
        WipWire {
            proto: WipPrototypeId(self.proto, PhantomData),
            idx: self.idx,
        }
    }
}
impl<FE: CompilerField> From<WipWire<FE>> for RawWipWire {
    fn from(value: WipWire<FE>) -> Self {
        Self {
            proto: value.proto.0,
            idx: value.idx,
        }
    }
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub(super) struct WipWire<FE: CompilerField> {
    proto: WipPrototypeId<FE>,
    idx: WireSize,
}
field_generic_type!(pub(super) WipWireTy<FE: CompilerField> => WipWire<FE>);

#[derive(Debug)]
enum Prototype<FE: CompilerField> {
    Defined {
        proto: TaskPrototypeRef,
        // input sizes should be pulled from the TaskPrototypeRef
        args: Vec<WipPrototypeId<FE>>,
    },
    Extern {
        id: ExternWiresId,
        idx: usize,
        len: WireSize,
    },
}
field_generic_type!(PrototypeTy<FE: CompilerField> => Prototype<FE>);

struct WipPrototype<FE: CompilerField, T> {
    id: WipPrototypeId<FE>,
    values: Vec<T>,
    num_outputs: WireSize,
    // TODO: maybe use a linear search data structure instead
    // Map from prototype ID to which argument it will be provided in
    // self shouldn't be contained in this.
    argument_ids: FxHashMap<WipPrototypeId<FE>, WireSize>,
    // The keys of argument_ids, in order (sorted by value)
    arguments: Vec<WipPrototypeId<FE>>,
    // FE is needed as a type parameter to ensure that, even for a task like Add, which doesn't
    // contain any field element values, we can know what task we mean when we say "Constant" task
    // (we mean the "Constant" task for the given field element).
    phantom: PhantomData<FE>,
}

impl<FE: CompilerField, T> WipPrototype<FE, T> {
    fn resolve_wire(&mut self, wire: WipWire<FE>) -> IrWire {
        if wire.proto == self.id {
            IrWire::own_wire(wire.idx)
        } else {
            debug_assert_eq!(self.argument_ids.len(), self.arguments.len());
            let id = *self.argument_ids.entry(wire.proto).or_insert_with(|| {
                let id = WireSize::try_from(self.arguments.len()).unwrap();
                self.arguments.push(wire.proto);
                id
            });
            IrWire::input_wire(id, wire.idx)
        }
    }

    fn num_outputs_if_id_matches(&self, id: WipPrototypeId<FE>) -> Option<WireSize> {
        if id == self.id {
            Some(self.num_outputs)
        } else {
            None
        }
    }

    fn new(id: WipPrototypeId<FE>) -> Self {
        Self {
            id,
            values: Vec::new(),
            argument_ids: Default::default(),
            arguments: Vec::new(),
            phantom: PhantomData,
            num_outputs: 0,
        }
    }
}

struct WipPrototypeTy<T: FieldGenericType>(PhantomData<T>);
impl<T: FieldGenericType> FieldGenericType for WipPrototypeTy<T> {
    type Out<FE: CompilerField> = WipPrototype<FE, T::Out<FE>>;
}

type FixArg = ();
type ConstantArg = FieldGenericIdentity;
field_generic_type!(LinearArg<FE: CompilerField> => [(IrWire, FE); 2]);
type AssertZeroArg = InvariantType<IrWire>;
type AssertMutliplyArg = InvariantType<[IrWire; 3]>;

fn new_wip_prototype<T: FieldGenericType>(id: u32) -> FieldGenericProduct<WipPrototypeTy<T>> {
    struct V<T: FieldGenericType>(u32, PhantomData<T>);
    impl<T: FieldGenericType> CompilerFieldVisitor<()> for &'_ mut V<T> {
        type Output = WipPrototypeTy<T>;
        fn visit<FE: CompilerField>(self, (): ()) -> <Self::Output as FieldGenericType>::Out<FE> {
            WipPrototype::new(WipPrototypeId(self.0, PhantomData))
        }
    }
    FieldGenericProduct::<WipPrototypeTy<T>>::new(&mut V::<T>(id, PhantomData))
}

pub(super) struct PrototypeCohortBuilder<'a, 'b> {
    fix: FieldGenericProduct<WipPrototypeTy<FixArg>>,
    constant: FieldGenericProduct<WipPrototypeTy<ConstantArg>>,
    linear: FieldGenericProduct<WipPrototypeTy<LinearArg>>,
    assert_zero: FieldGenericProduct<WipPrototypeTy<AssertZeroArg>>,
    assert_multiply: FieldGenericProduct<WipPrototypeTy<AssertMutliplyArg>>,
    next_ids: FieldIndexedArray<u32>,
    prototypes: FieldGenericProduct<Vec<Option<PrototypeTy>>>,
    externs: FieldIndexedArray<Vec<WireSize>>,
    cb: &'a mut CircuitBuilder<'b>,
    cohort_id: PrototypeCohortId,
}

impl<'a, 'b> PrototypeCohortBuilder<'a, 'b> {
    pub(super) fn new(cb: &'a mut CircuitBuilder<'b>) -> Self {
        Self {
            fix: new_wip_prototype(0),
            constant: new_wip_prototype(1),
            linear: new_wip_prototype(2),
            assert_zero: new_wip_prototype(3),
            assert_multiply: new_wip_prototype(4),
            next_ids: FieldIndexedArray([5; FieldType::ALL.len()]),
            prototypes: Default::default(),
            externs: Default::default(),
            cohort_id: new_prototype_cohort_id(),
            cb,
        }
    }
    fn push_into_proto<FE: CompilerField, T: FieldGenericType, S, F, const NOUT: usize>(
        &mut self,
        t: T::Out<FE>,
        threshold: WireSize,
        select: S,
        finish: F,
    ) -> eyre::Result<[WipWire<FE>; NOUT]>
    where
        for<'c> S: Fn(&'c mut Self) -> &'c mut FieldGenericProduct<WipPrototypeTy<T>>,
        for<'c> F: Fn(&'c mut Self) -> eyre::Result<()>,
    {
        let wip = select(self).as_mut().get::<FE>();
        wip.values.push(t);
        let mut out = [WipWire {
            proto: wip.id,
            idx: wip.num_outputs,
        }; NOUT];
        for (i, dst) in out.iter_mut().enumerate() {
            let i = i as u32;
            dst.idx += i;
        }
        wip.num_outputs += NOUT as u32;
        debug_assert_eq!(
            WireSize::try_from(wip.values.len() * NOUT).unwrap(),
            wip.num_outputs
        );
        if wip.values.len() >= threshold as usize {
            finish(self)?;
        }
        Ok(out)
    }
    fn flush_proto<FE: CompilerField, T: FieldGenericType, S, F>(
        &mut self,
        select: S,
        create_proto: F,
    ) -> eyre::Result<()>
    where
        for<'c> S: Fn(&'c mut Self) -> &'c mut FieldGenericProduct<WipPrototypeTy<T>>,
        for<'c> F: Fn(
            &'c mut CircuitBuilder,
            /* input sizes */ &'c [WireSize],
            /* values */ std::vec::Drain<T::Out<FE>>,
        ) -> eyre::Result<TaskPrototypeRef>,
    {
        let wip = select(self).as_mut().get::<FE>();
        if wip.values.is_empty() {
            return Ok(());
        }
        let id = wip.id;
        let mut arguments = std::mem::take(&mut wip.arguments);
        let mut values = std::mem::take(&mut wip.values);
        let next_id = self.fresh_proto_id::<FE>();
        // TODO: cache the input_sizes allocation
        let input_sizes: Vec<_> = arguments
            .iter()
            .copied()
            .map(|id| {
                self.prototypes
                    .as_ref()
                    .get::<FE>()
                    .get(id.0 as usize)
                    .and_then(|x| {
                        x.as_ref().map(|x| match x {
                            Prototype::Defined { proto, args: _ } => {
                                debug_assert_eq!(proto.outputs().len(), 1);
                                let shape = proto.outputs()[0];
                                debug_assert_eq!(
                                    shape.ty(),
                                    IrType::Mac(FE::FIELD_TYPE.field_mac_type())
                                );
                                shape.count()
                            }
                            Prototype::Extern { len, .. } => *len,
                        })
                    })
                    // We only need to consider producing prototypes.
                    .or_else(|| self.fix.as_ref().get::<FE>().num_outputs_if_id_matches(id))
                    .or_else(|| {
                        self.constant
                            .as_ref()
                            .get::<FE>()
                            .num_outputs_if_id_matches(id)
                    })
                    .or_else(|| {
                        self.linear
                            .as_ref()
                            .get::<FE>()
                            .num_outputs_if_id_matches(id)
                    })
                    .expect("Unable to find work in progress prototype")
            })
            .collect();
        let proto = create_proto(self.cb, &input_sizes, values.drain(..))?;
        let wip = select(self).as_mut().get::<FE>();
        wip.values = values;
        debug_assert!(wip.values.is_empty());
        wip.num_outputs = 0;
        wip.argument_ids.clear();
        wip.id = next_id;
        self.set_proto(
            id,
            Prototype::Defined {
                proto,
                args: arguments,
            },
        );
        Ok(())
    }
    fn set_proto<FE: CompilerField>(&mut self, id: WipPrototypeId<FE>, proto: Prototype<FE>) {
        let protos = self.prototypes.as_mut().get::<FE>();
        let id = id.0 as usize;
        if id >= protos.len() {
            protos.resize_with(id + 1, || None);
        }
        assert!(protos[id].is_none());
        protos[id] = Some(proto);
    }
    fn flush_fix<FE: CompilerField>(&mut self) -> eyre::Result<()> {
        self.flush_proto::<FE, _, _, _>(
            |s| &mut s.fix,
            |cb, _input_sizes, values| {
                cb.new_fix_prototype(
                    FE::FIELD_TYPE.field_mac_type(),
                    values.len().try_into().unwrap(),
                )
            },
        )
    }
    pub(super) fn push_fix<FE: CompilerField>(&mut self) -> eyre::Result<WipWire<FE>> {
        Ok(self.push_into_proto::<_, _, _, _, 1>(
            (),
            super::FIX_WRITE_THRESHOLD.try_into().unwrap(),
            |s| &mut s.fix,
            |s| s.flush_fix::<FE>(),
        )?[0])
    }
    fn flush_linear<FE: CompilerField>(&mut self) -> eyre::Result<()> {
        self.flush_proto::<FE, _, _, _>(
            |s| &mut s.linear,
            |cb, input_sizes, values| {
                if TypeId::of::<FE>() == TypeId::of::<F2>() {
                    cb.new_add_prototype(
                        FE::FIELD_TYPE.field_mac_type(),
                        input_sizes,
                        values.map(|[(a, a_c), (b, b_c)]| {
                            debug_assert_eq!(a_c, FE::ONE);
                            debug_assert_eq!(b_c, FE::ONE);
                            [a, b]
                        }),
                    )
                } else {
                    cb.new_linear_prototype(FE::FIELD_TYPE.field_mac_type(), input_sizes, values)
                }
            },
        )
    }
    pub(super) fn push_linear<FE: CompilerField>(
        &mut self,
        [(a_x, a_c), (b_x, b_c)]: [(WipWire<FE>, FE); 2],
    ) -> eyre::Result<WipWire<FE>> {
        const TUNABLE_THRESHOLD: WireSize = 1024 * 1024;
        let wip = self.linear.as_mut().get::<FE>();
        if TypeId::of::<FE>() == TypeId::of::<F2>() {
            match (a_c == FE::ONE, b_c == FE::ONE) {
                (true, true) => {
                    // Do the normal thing
                }
                (true, false) => {
                    return Ok(a_x);
                }
                (false, true) => {
                    return Ok(b_x);
                }
                (false, false) => {
                    return self.push_constant(FE::ZERO);
                }
            }
        }
        let a_x = wip.resolve_wire(a_x);
        let b_x = wip.resolve_wire(b_x);
        Ok(self.push_into_proto::<_, _, _, _, 1>(
            [(a_x, a_c), (b_x, b_c)],
            TUNABLE_THRESHOLD,
            |s| &mut s.linear,
            |s| s.flush_linear::<FE>(),
        )?[0])
    }
    fn flush_constant<FE: CompilerField>(&mut self) -> eyre::Result<()> {
        self.flush_proto::<FE, _, _, _>(
            |s| &mut s.constant,
            |cb, _input_sizes, values| {
                cb.new_constant_prototype(FE::FIELD_TYPE.field_mac_type(), values)
            },
        )
    }
    pub(super) fn push_constant<FE: CompilerField>(&mut self, x: FE) -> eyre::Result<WipWire<FE>> {
        const TUNABLE_THRESHOLD: WireSize = 1024 * 1024;
        Ok(self.push_into_proto::<_, _, _, _, 1>(
            x,
            TUNABLE_THRESHOLD,
            |s| &mut s.constant,
            |s| s.flush_constant::<FE>(),
        )?[0])
    }
    fn flush_assert_zero<FE: CompilerField>(&mut self) -> eyre::Result<()> {
        self.flush_proto::<FE, _, _, _>(
            |s| &mut s.assert_zero,
            |cb, input_sizes, values| {
                cb.new_assert_zero_prototype(FE::FIELD_TYPE.field_mac_type(), input_sizes, values)
            },
        )
    }
    pub(super) fn push_assert_zero<FE: CompilerField>(
        &mut self,
        x: WipWire<FE>,
    ) -> eyre::Result<()> {
        const TUNABLE_THRESHOLD: WireSize = 1024 * 1024;
        let wip = self.assert_zero.as_mut().get::<FE>();
        let x = wip.resolve_wire(x);
        self.push_into_proto::<FE, _, _, _, 0>(
            x,
            TUNABLE_THRESHOLD,
            |s| &mut s.assert_zero,
            |s| s.flush_assert_zero::<FE>(),
        )?;
        Ok(())
    }
    fn flush_assert_multiply<FE: CompilerField>(&mut self) -> eyre::Result<()> {
        self.flush_proto::<FE, _, _, _>(
            |s| &mut s.assert_multiply,
            |cb, input_sizes, values| {
                cb.new_assert_multiply_prototype(
                    FE::FIELD_TYPE.field_mac_type(),
                    input_sizes,
                    values,
                )
            },
        )
    }
    pub(super) fn push_assert_multiply<FE: CompilerField>(
        &mut self,
        x: WipWire<FE>,
        y: WipWire<FE>,
        product: WipWire<FE>,
    ) -> eyre::Result<()> {
        const TUNABLE_THRESHOLD: WireSize = 1024 * 1024;
        let wip = self.assert_multiply.as_mut().get::<FE>();
        let x = wip.resolve_wire(x);
        let y = wip.resolve_wire(y);
        let product = wip.resolve_wire(product);
        self.push_into_proto::<FE, _, _, _, 0>(
            [x, y, product],
            TUNABLE_THRESHOLD,
            |s| &mut s.assert_multiply,
            |s| s.flush_assert_multiply::<FE>(),
        )?;
        Ok(())
    }
    fn fresh_proto_id<FE: CompilerField>(&mut self) -> WipPrototypeId<FE> {
        let id = self.next_ids[FE::FIELD_TYPE];
        self.next_ids[FE::FIELD_TYPE] = id.checked_add(1).unwrap();
        WipPrototypeId(id, PhantomData)
    }
    pub(super) fn extern_proto<FE: CompilerField>(&mut self, len: WireSize) -> ExternWires<FE> {
        let idx = self.externs[FE::FIELD_TYPE].len();
        let id = self.fresh_proto_id::<FE>();
        self.externs[FE::FIELD_TYPE].push(len);
        let out = ExternWires {
            proto: id,
            len,
            cohort_id: self.cohort_id,
        };
        self.set_proto(
            id,
            Prototype::Extern {
                id: out.id(),
                idx,
                len,
            },
        );
        out
    }
    pub(super) fn enlarge_extern<FE: CompilerField>(
        &mut self,
        e: &mut ExternWires<FE>,
        new_len: WireSize,
    ) {
        assert_eq!(e.cohort_id, self.cohort_id);
        assert!(new_len >= e.len);
        e.len = new_len;
        match self.prototypes.as_mut().get::<FE>()[e.proto.0 as usize]
            .as_mut()
            .unwrap()
        {
            Prototype::Defined { .. } => panic!("Expected extern prototype"),
            Prototype::Extern { idx, len, .. } => {
                debug_assert_eq!(self.externs[FE::FIELD_TYPE][*idx], *len);
                *len = new_len;
                self.externs[FE::FIELD_TYPE][*idx] = new_len;
            }
        }
    }
    pub(super) fn finish(mut self) -> eyre::Result<PrototypeCohort> {
        for f in FieldType::ALL {
            struct V<'a, 'b, 'c>(&'c mut PrototypeCohortBuilder<'a, 'b>);
            impl CompilerFieldVisitor<()> for V<'_, '_, '_> {
                type Output = InvariantType<eyre::Result<()>>;
                fn visit<FE: CompilerField>(self, (): ()) -> eyre::Result<()> {
                    self.0.flush_fix::<FE>()?;
                    self.0.flush_constant::<FE>()?;
                    self.0.flush_linear::<FE>()?;
                    self.0.flush_assert_zero::<FE>()?;
                    self.0.flush_assert_multiply::<FE>()?;
                    Ok(())
                }
            }
            f.visit(V(&mut self))?;
        }
        Ok(PrototypeCohort {
            externs: self.externs,
            prototypes: self.prototypes,
            id: self.cohort_id,
        })
    }
}

#[cfg(debug_assertions)]
type PrototypeCohortId = u64;
#[cfg(not(debug_assertions))]
type PrototypeCohortId = ();
fn new_prototype_cohort_id() -> PrototypeCohortId {
    #[cfg(debug_assertions)]
    {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        NEXT_ID.fetch_add(1, Ordering::Relaxed)
    }
    #[cfg(not(debug_assertions))]
    ()
}

pub(super) struct PrototypeCohort {
    id: PrototypeCohortId,
    // TODO: can we remove this externs field. I think we're currently only using it for assertions
    // and we can achieve the same effect without it.
    externs: FieldIndexedArray<Vec<WireSize>>,
    prototypes: FieldGenericProduct<Vec<Option<PrototypeTy>>>,
}
impl PrototypeCohort {
    fn iter_protos<FE: CompilerField>(&self) -> impl Iterator<Item = (usize, &Prototype<FE>)> + '_ {
        self.prototypes
            .as_ref()
            .get::<FE>()
            .iter()
            .enumerate()
            .filter_map(|(id, proto)| proto.as_ref().map(|proto| (id, proto)))
    }
    fn instantiate_field<P: Party, FE: CompilerField>(
        &self,
        cb: &mut CircuitBuilder,
        vs: &mut VoleSupplier,
        name: &str,
        externs: &FxHashMap<ExternWiresId, WireSlice>,
        pb: &mut ProverPrivate<P, &mut PrivateBuilder>,
        mut private_stream: ProverPrivate<P, &mut std::vec::IntoIter<FixData>>,
    ) -> eyre::Result<()> {
        // TODO: cache the wire_slices allocation
        let mut wire_slices = vec![None; self.prototypes.as_ref().get::<FE>().len()];
        // TODO: should we avoid multiple iterations?
        // First make prototypes for tasks without any inputs: Fix, Constant, Extern
        for (id, proto) in self.iter_protos::<FE>() {
            match proto {
                Prototype::Defined { proto, args } => {
                    match proto.prototype_kind() {
                        TaskKind::Fix(_) => {
                            assert!(wire_slices[id].is_none());
                            assert!(args.is_empty());
                            let voles = vs.supply_voles(cb, proto)?;
                            wire_slices[id] = Some({
                                let task = cb.instantiate(proto, &[], &[voles])?;
                                cb.name_task(&task, name);
                                pb.as_mut()
                                    .zip(private_stream.as_mut())
                                    .map(|(pb, privates)| {
                                        pb.associate_fix_data(
                                            &task,
                                            match privates.next() {
                                                Some(x) => x,
                                                None => {
                                                    panic!("Missing private entry for {name:?}")
                                                }
                                            },
                                        )
                                    })
                                    .lift_result()?;
                                task.outputs(IrType::Mac(FE::FIELD_TYPE.field_mac_type()))
                            });
                        }
                        TaskKind::Constant(_) => {
                            assert!(wire_slices[id].is_none());
                            assert!(args.is_empty());
                            // TODO: we only need to instantiate the constants prototype once
                            // (ignoring graph degree issues). We don't need to instantiate it
                            // every time we instantiate the cohort.
                            wire_slices[id] = Some({
                                let task = cb.instantiate(proto, &[], &[])?;
                                cb.name_task(&task, name);
                                task.outputs(IrType::Mac(FE::FIELD_TYPE.field_mac_type()))
                            });
                        }
                        _ => {
                            // We'll handle this prototype later.
                        }
                    }
                }
                Prototype::Extern { id: eid, len, .. } => {
                    assert!(wire_slices[id].is_none());
                    assert_eq!(externs[eid].len(), *len);
                    wire_slices[id] = Some(externs[eid]);
                }
            }
        }
        // Then do Linear prototypes, and then the rest of the prototypes
        // TODO: cache this allocation?
        let mut single_array_inputs = Vec::new();
        let kind_sets: [&[TaskKind]; 2] = [
            &[TaskKind::Linear(FE::FIELD_TYPE.field_mac_type())],
            &[
                TaskKind::AssertMultiplication(FE::FIELD_TYPE.field_mac_type()),
                TaskKind::AssertZero(FE::FIELD_TYPE.field_mac_type()),
            ],
        ];
        for should_process_task_kinds in kind_sets {
            for (id, proto) in self.iter_protos::<FE>() {
                match proto {
                    Prototype::Defined { proto, args }
                        if should_process_task_kinds.contains(&proto.prototype_kind()) =>
                    {
                        assert!(wire_slices[id].is_none());
                        single_array_inputs.clear();
                        assert_eq!(proto.single_array_inputs().len(), args.len());
                        single_array_inputs.extend(
                            proto.single_array_inputs().iter().zip(args.iter()).map(
                                |(shape, arg_id)| {
                                    debug_assert_eq!(
                                        shape.ty(),
                                        IrType::Mac(FE::FIELD_TYPE.field_mac_type())
                                    );
                                    wire_slices[arg_id.0 as usize]
                                        .with_context(|| format!(
                                            "should_process_task_kinds={should_process_task_kinds:?}\narg_id={arg_id:?}\nprotos={:?}",
                                            self.iter_protos::<FE>().collect::<Vec<_>>())
                                        ).unwrap()
                                        .slice(0..shape.count())
                                },
                            ),
                        );
                        wire_slices[id] = Some({
                            let task = cb.instantiate(proto, &single_array_inputs, &[])?;
                            cb.name_task(&task, name);
                            task.outputs(IrType::Mac(FE::FIELD_TYPE.field_mac_type()))
                        });
                    }
                    _ => {
                        // Do nothing
                    }
                }
            }
        }
        Ok(())
    }
    pub(super) fn instantiate<'a, 'b, P: Party>(
        &self,
        cb: &mut CircuitBuilder,
        vs: &mut VoleSupplier,
        name: &str,
        mut private_streams: ProverPrivate<
            P,
            &'a mut FieldIndexedArray<std::vec::IntoIter<FixData>>,
        >,
        pb: &mut ProverPrivate<P, &'b mut PrivateBuilder>,
        externs: &FxHashMap<ExternWiresId, WireSlice>,
    ) -> eyre::Result<()> {
        #[cfg(debug_assertions)]
        {
            for k in externs.keys() {
                assert_eq!(k.2, self.id);
            }
        }
        for ty in FieldType::ALL.iter().copied() {
            struct V<'a, 'b, 'd, 'e, P: Party> {
                this: &'d PrototypeCohort,
                cb: &'a mut CircuitBuilder<'b>,
                vs: &'a mut VoleSupplier,
                externs: &'a FxHashMap<ExternWiresId, WireSlice>,
                name: &'a str,
                pb: &'a mut ProverPrivate<P, &'e mut PrivateBuilder>,
                private_stream: ProverPrivate<P, &'a mut std::vec::IntoIter<FixData>>,
            }
            impl<P: Party> CompilerFieldVisitor<()> for V<'_, '_, '_, '_, P> {
                type Output = InvariantType<eyre::Result<()>>;
                fn visit<FE: CompilerField>(self, (): ()) -> eyre::Result<()> {
                    self.this.instantiate_field::<P, FE>(
                        self.cb,
                        self.vs,
                        self.name,
                        self.externs,
                        self.pb,
                        self.private_stream,
                    )
                }
            }
            ty.visit(V {
                this: self,
                cb,
                vs,
                name,
                externs,
                pb,
                private_stream: private_streams.as_mut().map(|ps| &mut ps[ty]),
            })?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) struct ExternWiresId(u32, FieldType, PrototypeCohortId);

// This isn't clone or copy because the size can change.
pub(super) struct ExternWires<FE: CompilerField> {
    cohort_id: PrototypeCohortId,
    proto: WipPrototypeId<FE>,
    len: WireSize,
}
impl<FE: CompilerField> ExternWires<FE> {
    pub(super) fn id(&self) -> ExternWiresId {
        ExternWiresId(self.proto.0, FE::FIELD_TYPE, self.cohort_id)
    }
    pub(super) fn get(&self, idx: WireSize) -> WipWire<FE> {
        assert!(idx < self.len());
        WipWire {
            proto: self.proto,
            idx,
        }
    }
    pub(super) fn len(&self) -> WireSize {
        self.len
    }
}

field_generic_type!(pub(super) ExternWiresTy<FE: CompilerField> => ExternWires<FE>);
