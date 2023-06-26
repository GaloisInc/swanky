use super::Plugin;
use crate::circuit_ir::{first_unused_wire_id, GateM, GatesBody, TypeId, TypeStore, WireCount};
use eyre::{eyre, Result};
use mac_n_cheese_sieve_parser::PluginTypeArg;
use scuttlebutt::{field::F2, ring::FiniteRing, serialization::CanonicalSerialize};

pub(crate) struct MuxV0;

impl Plugin for MuxV0 {
    const NAME: &'static str = "mux_v0";

    fn gates_body(
        operation: &str,
        params: &[PluginTypeArg],
        output_counts: &[(TypeId, WireCount)],
        input_counts: &[(TypeId, WireCount)],
        _type_store: &TypeStore,
    ) -> Result<GatesBody> {
        if operation != "strict" {
            return Err(eyre!(
                "{}: Implementation only handles strict permissiveness: {operation}",
                Self::NAME,
            ));
        }

        if params.len() != 0 {
            return Err(eyre!(
                "{}: Invalid number of params (must be zero): {}",
                Self::NAME,
                params.len()
            ));
        }

        // TODO: Ensure that `F2` is being used.

        // r <- mux(cond, b_0, b_1)
        // cond_neg = cond + 1
        // r = b_0 * cond_neg + b_1 * cond
        // TODO: could minimize the number of multiplication gates

        let field = input_counts[0].0;
        let callframe_size = first_unused_wire_id(output_counts, input_counts);

        let mut vec_gates = vec![];

        // 1) find where the condition is:
        let mut prev = 0;
        // assert_eq!(out_ranges.len(), func.output_counts.len());
        for (_field_idx, count) in output_counts {
            prev += *count;
        }

        // assert_eq!(in_ranges.len(), func.input_counts.len());
        let cond = prev;

        // 2) MUX dedicated circuit

        // wire_cond_neg <- cond - 1
        let wire_cond_neg = callframe_size;
        vec_gates.push(
            GateM::AddConstant(
                field,
                wire_cond_neg,
                cond,
                Box::from(F2::ONE.to_bytes().to_vec()),
            ), // WARNING only works in F2
        );

        let middle_index = input_counts.len() / 2; // WARNING: works for F2, Should divide by the number of possibilities

        let mut pos = 0;
        for i in 0..middle_index {
            let (field, how_many) = input_counts[1 + i];
            for idx in 0..how_many {
                // Allocate one new wire per input.
                //println!("WIRE 0: {:?}", callframe_size + 1 + pos + idx);
                //println!("WIRE 0: {:?}", wire_cond_neg);
                //println!("WIRE 0: {:?}", cond + 1 + pos + idx);
                vec_gates.push(GateM::Mul(
                    field,
                    callframe_size + 1 + pos + idx,
                    wire_cond_neg,
                    cond + 1 + pos + idx,
                ));
            }
            pos += how_many;
        }

        let input_range = pos;

        let mut pos = 0;
        for i in 0..middle_index {
            let (field, how_many) = input_counts[1 + middle_index + i];
            for idx in 0..how_many {
                //println!("WIRE 1: {:?}", callframe_size + 1 + input_range + pos + idx);
                //println!("WIRE 1: {:?}", cond);
                //println!("WIRE 1: {:?}", cond + 1 + input_range + pos + idx);
                vec_gates.push(GateM::Mul(
                    field,
                    callframe_size + 1 + input_range + pos + idx,
                    cond,
                    cond + 1 + input_range + pos + idx,
                ));
            }
            pos += how_many;
        }

        let mut pos = 0;
        for (field, how_many) in output_counts {
            for idx in 0..*how_many {
                //println!("WIRE 2: {:?}", pos + idx);
                //println!("WIRE 2: {:?}", callframe_size + 1 + pos + idx);
                //println!("WIRE 2: {:?}", callframe_size + 1 + input_range + pos + idx);
                vec_gates.push(GateM::Add(
                    *field,
                    pos + idx,
                    callframe_size + 1 + pos + idx,
                    callframe_size + 1 + input_range + pos + idx,
                ));
            }
            pos += how_many;
        }

        Ok(GatesBody::new(vec_gates))
    }
}

#[cfg(test)]
mod tests {
    use super::MuxV0;
    use crate::{
        backend_multifield::tests::{into_vec, minus_one, one, test_circuit, zero},
        circuit_ir::{FunStore, FuncDecl, GateM, TypeStore},
    };
    use crate::{
        backend_multifield::tests::{F2_VEC, FF0},
        plugins::Plugin,
    };
    use scuttlebutt::{field::F2, ring::FiniteRing};

    // Simplest test for mux on f2
    #[test]
    fn test_f2_mux() {
        let fields = vec![F2_VEC.to_vec()];
        let mut func_store = FunStore::default();
        let type_store = TypeStore::try_from(fields.clone()).unwrap();

        let func = FuncDecl::new_plugin(
            "my_mux".into(),
            42,
            vec![(FF0, 1)],
            vec![(FF0, 1), (FF0, 1), (FF0, 1)],
            MuxV0::NAME.into(),
            "strict".into(),
            vec![],
            vec![],
            vec![],
            &type_store,
        )
        .unwrap();

        func_store.insert("my_mux".into(), func);

        let gates = vec![
            GateM::Witness(FF0, 0),
            GateM::Witness(FF0, 1),
            GateM::Witness(FF0, 2),
            GateM::Witness(FF0, 3),
            GateM::Instance(FF0, 4),
            GateM::Instance(FF0, 5),
            GateM::Instance(FF0, 6),
            GateM::Instance(FF0, 7),
            GateM::Instance(FF0, 8),
            GateM::Instance(FF0, 9),
            GateM::Instance(FF0, 10),
            GateM::Instance(FF0, 11),
            GateM::Call(Box::new((
                "my_mux".into(),
                vec![(12, 12)],
                vec![(0, 0), (4, 4), (8, 8)],
            ))),
            GateM::AssertZero(FF0, 12),
            GateM::Call(Box::new((
                "my_mux".into(),
                vec![(13, 13)],
                vec![(1, 1), (4, 4), (8, 8)],
            ))),
            GateM::AddConstant(FF0, 14, 13, Box::from(into_vec(-F2::ONE))),
            GateM::AssertZero(FF0, 14),
        ];

        let instances = vec![vec![
            zero::<F2>(),
            zero::<F2>(),
            zero::<F2>(),
            zero::<F2>(),
            one::<F2>(),
            one::<F2>(),
            one::<F2>(),
            one::<F2>(),
        ]];
        let witnesses = vec![vec![zero::<F2>(), one::<F2>(), zero::<F2>(), one::<F2>()]];

        test_circuit(fields, func_store, gates, instances, witnesses).unwrap();
    }

    // More complicated test of mux selecting a triple and a unique element
    #[test]
    fn test_f2_mux_on_slices() {
        let fields = vec![F2_VEC.to_vec()];
        let mut func_store = FunStore::default();
        let type_store = TypeStore::try_from(fields.clone()).unwrap();

        let func = FuncDecl::new_plugin(
            "my_mux".into(),
            42,
            vec![(FF0, 3), (FF0, 1)],
            vec![(FF0, 1), (FF0, 3), (FF0, 1), (FF0, 3), (FF0, 1)],
            MuxV0::NAME.into(),
            "strict".into(),
            vec![],
            vec![],
            vec![],
            &type_store,
        )
        .unwrap();

        func_store.insert("my_mux".into(), func);

        let gates = vec![
            GateM::New(FF0, 4, 11),
            GateM::Witness(FF0, 0),
            GateM::Witness(FF0, 1),
            // NOTE: there is a gap with 2 unused wires here
            GateM::Instance(FF0, 4),
            GateM::Instance(FF0, 5),
            GateM::Instance(FF0, 6),
            GateM::Instance(FF0, 7),
            GateM::Instance(FF0, 8),
            GateM::Instance(FF0, 9),
            GateM::Instance(FF0, 10),
            GateM::Instance(FF0, 11),
            GateM::Call(Box::new((
                "my_mux".into(),
                vec![(12, 14), (15, 15)],
                vec![(0, 0), (4, 6), (7, 7), (8, 10), (11, 11)],
            ))),
            GateM::AssertZero(FF0, 12),
            GateM::AssertZero(FF0, 13),
            GateM::AssertZero(FF0, 14),
            GateM::AssertZero(FF0, 15),
            GateM::Call(Box::new((
                "my_mux".into(),
                vec![(16, 18), (19, 19)],
                vec![(1, 1), (4, 6), (7, 7), (8, 10), (11, 11)],
            ))),
            GateM::AddConstant(FF0, 20, 16, Box::from(minus_one::<F2>())),
            GateM::AddConstant(FF0, 21, 17, Box::from(minus_one::<F2>())),
            GateM::AddConstant(FF0, 22, 18, Box::from(minus_one::<F2>())),
            GateM::AddConstant(FF0, 23, 19, Box::from(minus_one::<F2>())),
            GateM::AssertZero(FF0, 20),
            GateM::AssertZero(FF0, 21),
            GateM::AssertZero(FF0, 22),
            GateM::AssertZero(FF0, 23),
        ];

        let instances = vec![vec![
            zero::<F2>(),
            zero::<F2>(),
            zero::<F2>(),
            zero::<F2>(),
            one::<F2>(),
            one::<F2>(),
            one::<F2>(),
            one::<F2>(),
        ]];
        let witnesses = vec![vec![zero::<F2>(), one::<F2>()]];

        test_circuit(fields, func_store, gates, instances, witnesses).unwrap();
    }
}
