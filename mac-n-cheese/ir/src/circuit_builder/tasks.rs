use std::any::TypeId;

use arrayvec::ArrayVec;
use mac_n_cheese_vole::specialization::FiniteFieldSpecialization;
use mac_n_cheese_vole::vole::VoleSizes;
use scuttlebutt::field::{FiniteField, IsSubFieldOf};
use scuttlebutt::serialization::SequenceSerializer;

use crate::circuit_builder::PrototypeBuilder;
use crate::compilation_format::wire_format::{
    AssertMultiplyPrototypeNoSpecWireFormat, AssertMultiplyPrototypeSmallBinaryWireFormat,
    AssertZeroPrototypeWireFormat, CopyPrototypeWireFormat, LinearPrototypeWireFormat,
    SupportsOwnWires, Wire, Xor4PrototypeWireFormat, XorPrototypeWireFormat,
};
use crate::compilation_format::{FieldMacType, FieldTypeMacVisitor, TaskKind, Type, WireSize};

use super::TaskPrototypeRef;

impl<'a> super::CircuitBuilder<'a> {
    pub fn new_constant_prototype<FE: FiniteField, I: IntoIterator<Item = FE>>(
        &mut self,
        ty: FieldMacType,
        values: I,
    ) -> eyre::Result<TaskPrototypeRef> {
        ty.assert_value_field_is::<FE>();
        self.register_prototype(|pb| {
            let mut s = FE::Serializer::new(pb)?;
            let mut n = 0_u32;
            for value in values {
                n = n.checked_add(1).unwrap();
                s.write(pb, value)?;
            }
            s.finish(pb)?;
            pb.output(Type::Mac(ty), n);
            Ok(TaskKind::Constant(ty))
        })
    }

    pub fn new_linear_prototype<FE: FiniteField, I: IntoIterator<Item = [(Wire, FE); 2]>>(
        &mut self,
        ty: FieldMacType,
        input_sizes: &[WireSize],
        operations: I,
    ) -> eyre::Result<TaskPrototypeRef> {
        ty.assert_value_field_is::<FE>();
        self.register_prototype(|pb| {
            for sz in input_sizes.iter().copied() {
                pb.add_single_array_input(Type::Mac(ty), sz);
            }
            let mut ww = LinearPrototypeWireFormat::<FE>::new_writer(
                pb,
                input_sizes,
                SupportsOwnWires::ProducesValues,
            )?;
            for op in operations {
                ww.write_wires(op)?;
                ww.add_own_wires(1);
            }
            let n = ww.finish()?;
            pb.output(Type::Mac(ty), n);
            Ok(TaskKind::Linear(ty))
        })
    }

    pub fn new_copy_base_svole_prototype(
        &mut self,
        field: FieldMacType,
    ) -> eyre::Result<TaskPrototypeRef> {
        struct V;
        impl FieldTypeMacVisitor for V {
            type Output = u32;
            fn visit<
                VF: FiniteField + IsSubFieldOf<TF>,
                TF: FiniteField,
                S: FiniteFieldSpecialization<VF, TF>,
            >(
                self,
            ) -> Self::Output {
                assert_eq!(
                    TypeId::of::<VF>(),
                    TypeId::of::<TF::PrimeField>(),
                    "We only have base svole where the value field is the prime field!"
                );
                VoleSizes::of::<VF, TF>()
                    .base_voles_needed
                    .try_into()
                    .unwrap()
            }
        }
        let size = field.visit(V);
        self.register_prototype(|b| {
            b.output(Type::RandomMac(field), size);
            Ok(TaskKind::BaseSvole(field))
        })
    }

    pub fn new_vole_extend_prototype(
        &mut self,
        ty: FieldMacType,
        count: u32,
    ) -> eyre::Result<TaskPrototypeRef> {
        assert_ne!(count, 0);
        self.register_prototype(|pb| {
            struct V<'a, 'b, 'c>(&'a mut PrototypeBuilder<'b, 'c>, FieldMacType, u32);
            impl FieldTypeMacVisitor for V<'_, '_, '_> {
                type Output = eyre::Result<()>;
                fn visit<
                    VF: FiniteField + IsSubFieldOf<TF>,
                    TF: FiniteField,
                    S: FiniteFieldSpecialization<VF, TF>,
                >(
                    self,
                ) -> Self::Output {
                    let count = self.2;
                    let sizes = VoleSizes::of::<VF, TF>();
                    self.0
                        .prover_sends(u32::try_from(sizes.comms_1s).unwrap() * count);
                    self.0
                        .verifier_sends(u32::try_from(sizes.comms_2r).unwrap() * count);
                    self.0
                        .prover_sends(u32::try_from(sizes.comms_3s).unwrap() * count);
                    self.0
                        .verifier_sends(u32::try_from(sizes.comms_4r).unwrap() * count);
                    self.0
                        .prover_sends(u32::try_from(sizes.comms_5s).unwrap() * count);
                    for _ in 0..count {
                        self.0.add_single_array_input(
                            Type::RandomMac(self.1),
                            sizes.base_voles_needed.try_into().unwrap(),
                        );
                    }
                    self.0.output(
                        Type::RandomMac(self.1),
                        u32::try_from(sizes.voles_outputted).unwrap() * count,
                    );
                    Ok(())
                }
            }
            ty.visit(V(pb, ty, count))?;
            Ok(TaskKind::VoleExtension(ty))
        })
    }

    pub fn new_copy_prototype(
        &mut self,
        ty: Type,
        input_sizes: &[WireSize],
        wires: impl IntoIterator<Item = Wire>,
    ) -> eyre::Result<TaskPrototypeRef> {
        self.register_prototype(|pb| {
            for sz in input_sizes.iter().copied() {
                pb.add_single_array_input(ty, sz);
            }
            let mut ww = CopyPrototypeWireFormat::new_writer(
                pb,
                input_sizes,
                SupportsOwnWires::ProducesValues,
            )?;
            for wire in wires {
                ww.write_wires([(wire, ())])?;
                ww.add_own_wires(1);
            }
            let num_outputs = ww.finish()?;
            pb.output(ty, num_outputs);
            Ok(TaskKind::Copy(ty))
        })
    }

    pub fn new_add_prototype(
        &mut self,
        ty: FieldMacType,
        input_sizes: &[WireSize],
        wires: impl IntoIterator<Item = [Wire; 2]>,
    ) -> eyre::Result<TaskPrototypeRef> {
        self.register_prototype(|pb| {
            for sz in input_sizes.iter().copied() {
                pb.add_single_array_input(Type::Mac(ty), sz);
            }
            let mut ww = XorPrototypeWireFormat::new_writer(
                pb,
                input_sizes,
                SupportsOwnWires::ProducesValues,
            )?;
            for [a, b] in wires {
                ww.write_wires([(a, ()), (b, ())])?;
                ww.add_own_wires(1);
            }
            let num_outputs = ww.finish()?;
            pb.output(Type::Mac(ty), num_outputs);
            Ok(TaskKind::Add(ty))
        })
    }

    pub fn new_xor4_prototype(
        &mut self,
        ty: FieldMacType,
        input_sizes: &[WireSize],
        wires: impl IntoIterator<Item = [[Wire; 2]; 4]>,
    ) -> eyre::Result<TaskPrototypeRef> {
        assert!(ty.uses_small_binary_specialization());
        self.register_prototype(|pb| {
            for sz in input_sizes.iter().copied() {
                pb.add_single_array_input(Type::Mac(ty), sz);
            }
            let mut ww = Xor4PrototypeWireFormat::new_writer(
                pb,
                input_sizes,
                SupportsOwnWires::ProducesValues,
            )?;
            for chunk in wires {
                ww.write_wires(chunk)?;
                ww.add_own_wires(4);
            }
            let num_outputs = ww.finish()?;
            pb.output(Type::Mac(ty), num_outputs);
            Ok(TaskKind::Xor4(ty))
        })
    }

    /// `[a, b, c]` asserts `a * b == c`
    pub fn new_assert_multiply_prototype(
        &mut self,
        ty: FieldMacType,
        input_sizes: &[WireSize],
        wires: impl IntoIterator<Item = [Wire; 3]>,
    ) -> eyre::Result<TaskPrototypeRef> {
        self.register_prototype(|pb| {
            for sz in input_sizes.iter().copied() {
                pb.add_single_array_input(Type::Mac(ty), sz);
            }
            if ty.uses_small_binary_specialization() {
                let mut ww = AssertMultiplyPrototypeSmallBinaryWireFormat::new_writer(
                    pb,
                    input_sizes,
                    SupportsOwnWires::OnlyConsumes,
                )?;
                // TODO: this buffer approach should be pulled into a helper type so it can be used for more tasks.
                let mut buf = ArrayVec::<[Wire; 3], 4>::new();
                let mut wires = wires.into_iter().fuse();
                'outer: while let Some(chunk) = wires.next() {
                    buf.push(chunk);
                    for _ in 0..3 {
                        if let Some(chunk) = wires.next() {
                            buf.push(chunk);
                        } else {
                            break 'outer;
                        }
                    }
                    let chunks = std::mem::take(&mut buf)
                        .into_inner()
                        .expect("exactly four chunks");
                    ww.write_wires(chunks)?;
                }
                if let Some(last_chunk) = buf.last().copied() {
                    debug_assert!(!buf.is_empty());
                    debug_assert!(!buf.is_full()); // otherwise the above loop would've emptied it
                    while buf.try_push(last_chunk).is_ok() {}
                    let chunks = buf.into_inner().expect("exactly four chunks");
                    ww.write_wires(chunks)?;
                }
                ww.finish()?;
            } else {
                let mut ww = AssertMultiplyPrototypeNoSpecWireFormat::new_writer(
                    pb,
                    input_sizes,
                    SupportsOwnWires::OnlyConsumes,
                )?;
                for [a, b, c] in wires {
                    ww.write_wires([(a, ()), (b, ()), (c, ())])?;
                }
                ww.finish()?;
            }
            Ok(TaskKind::AssertMultiplication(ty))
        })
    }

    pub fn new_assert_zero_prototype(
        &mut self,
        ty: FieldMacType,
        input_sizes: &[WireSize],
        wires: impl IntoIterator<Item = Wire>,
    ) -> eyre::Result<TaskPrototypeRef> {
        self.register_prototype(|pb| {
            for sz in input_sizes.iter().copied() {
                pb.add_single_array_input(Type::Mac(ty), sz);
            }
            let mut ww = AssertZeroPrototypeWireFormat::new_writer(
                pb,
                input_sizes,
                SupportsOwnWires::OnlyConsumes,
            )?;
            for wire in wires {
                ww.write_wires([(wire, ())])?;
            }
            ww.finish()?;
            Ok(TaskKind::AssertZero(ty))
        })
    }

    pub fn new_fix_prototype(
        &mut self,
        ty: FieldMacType,
        count: WireSize,
    ) -> eyre::Result<TaskPrototypeRef> {
        struct V(usize);
        impl FieldTypeMacVisitor for V {
            type Output = u32;
            fn visit<
                VF: FiniteField + IsSubFieldOf<TF>,
                TF: FiniteField,
                S: FiniteFieldSpecialization<VF, TF>,
            >(
                self,
            ) -> Self::Output {
                VF::Serializer::serialized_size(self.0).try_into().unwrap()
            }
        }
        self.register_prototype(|pb| {
            pb.add_multi_array_input(Type::RandomMac(ty), count);
            pb.prover_sends(ty.visit(V(count as usize)));
            pb.output(Type::Mac(ty), count);
            Ok(TaskKind::Fix(ty))
        })
    }
}
