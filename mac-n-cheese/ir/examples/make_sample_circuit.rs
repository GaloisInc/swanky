use mac_n_cheese_ir::{
    circuit_builder::{build_circuit, build_privates, vole_supplier::VoleSupplier},
    compilation_format::{wire_format::Wire, FieldMacType, Type},
};

use scuttlebutt::{
    field::{F61p, F2},
    ring::FiniteRing,
};

fn main() -> eyre::Result<()> {
    color_eyre::install()?;
    build_circuit("example.bin", |cb| {
        build_privates("example.priv.bin", |pb| {
            let c1 = cb.new_constant_prototype(FieldMacType::BinaryF63b, [F2::ZERO, F2::ONE])?;
            let binary_constants = cb
                .instantiate(&c1, &[], &[])?
                .outputs(Type::Mac(FieldMacType::BinaryF63b));
            let xor_proto = cb.new_add_prototype(
                FieldMacType::BinaryF63b,
                &[2],
                [
                    [Wire::input_wire(0, 0), Wire::input_wire(0, 1)], // 1
                    [Wire::own_wire(0), Wire::own_wire(0)],           // 0
                    [Wire::input_wire(0, 0), Wire::own_wire(1)],      // 0
                ],
            )?;
            let xor = cb
                .instantiate(&xor_proto, &[binary_constants], &[])?
                .outputs(Type::Mac(FieldMacType::BinaryF63b));
            let az_proto = cb.new_assert_zero_prototype(
                FieldMacType::BinaryF63b,
                &[3],
                [Wire::input_wire(0, 1), Wire::input_wire(0, 2)],
            )?;
            cb.instantiate(&az_proto, &[xor], &[])?;
            let mut voles = VoleSupplier::new(1, Default::default());
            let fix = cb.new_fix_prototype(FieldMacType::F61p, 56)?;
            let v = voles.supply_voles(cb, &fix)?;
            let fix_out = cb.instantiate(&fix, &[], &[v])?;
            pb.write_fix_data::<_, F61p>(&fix_out, |x| {
                for i in 0..56_u128 {
                    x.add(F61p::try_from(i).unwrap())?;
                }
                Ok(())
            })?;
            let az =
                cb.new_assert_zero_prototype(FieldMacType::F61p, &[5], [Wire::input_wire(0, 0)])?;
            cb.instantiate(
                &az,
                &[fix_out.outputs(Type::Mac(FieldMacType::F61p)).slice(0..5)],
                &[],
            )?;
            let am = cb.new_assert_multiply_prototype(
                FieldMacType::F61p,
                &[12],
                [[
                    Wire::input_wire(0, 2),
                    Wire::input_wire(0, 3),
                    Wire::input_wire(0, 6),
                ]],
            )?;
            cb.instantiate(
                &am,
                &[fix_out.outputs(Type::Mac(FieldMacType::F61p)).slice(0..12)],
                &[],
            )?;
            let fix = cb.new_fix_prototype(FieldMacType::BinaryF63b, 2)?;
            let v = voles.supply_voles(cb, &fix)?;
            let fix_out = cb.instantiate(&fix, &[], &[v])?;
            pb.write_fix_data(&fix_out, |x| {
                x.add(F2::ZERO)?;
                x.add(F2::ONE)?;
                Ok(())
            })?;

            let am = cb.new_assert_multiply_prototype(FieldMacType::BinaryF63b, &[2], {
                let o = Wire::input_wire(0, 0);
                let i = Wire::input_wire(0, 1);
                [[o, o, o], [o, i, o], [i, o, o], [i, i, i], [i, i, i]]
            })?;
            cb.instantiate(
                &am,
                &[fix_out.outputs(Type::Mac(FieldMacType::BinaryF63b))],
                &[],
            )?;

            let constant = cb.new_constant_prototype(
                FieldMacType::F61p,
                [
                    F61p::try_from(12).unwrap(),
                    F61p::try_from(13).unwrap(),
                    F61p::try_from(14).unwrap(),
                    -F61p::try_from(847).unwrap(),
                ],
            )?;
            let constants = cb
                .instantiate(&constant, &[], &[])?
                .outputs(Type::Mac(FieldMacType::F61p));
            let linear = cb.new_linear_prototype::<F61p, _>(
                FieldMacType::F61p,
                &[4],
                [
                    // d := 2*a+3*b
                    [
                        (Wire::input_wire(0, 0), F61p::try_from(2).unwrap()),
                        (Wire::input_wire(0, 1), F61p::try_from(3).unwrap()),
                    ],
                    // e := 1 * d + c * 56
                    [
                        (Wire::own_wire(0), F61p::try_from(1).unwrap()),
                        (Wire::input_wire(0, 2), F61p::try_from(56).unwrap()),
                    ],
                    [
                        (Wire::input_wire(0, 3), F61p::try_from(1).unwrap()),
                        (Wire::own_wire(1), F61p::try_from(1).unwrap()),
                    ],
                ],
            )?;
            let linear = cb
                .instantiate(&linear, &[constants], &[])?
                .outputs(Type::Mac(FieldMacType::F61p));
            let az =
                cb.new_assert_zero_prototype(FieldMacType::F61p, &[1], [Wire::input_wire(0, 0)])?;
            cb.instantiate(&az, &[linear.slice(2..)], &[])?;
            Ok(())
        })
    })?;
    Ok(())
}
