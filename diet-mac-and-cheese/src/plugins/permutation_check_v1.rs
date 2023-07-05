use super::Plugin;
use crate::circuit_ir::{
    first_unused_wire_id, FunStore, GateM, GatesBody, TypeId, TypeSpecification, TypeStore,
    WireCount,
};
use eyre::{ensure, eyre};
use mac_n_cheese_sieve_parser::PluginTypeArg;
use scuttlebutt::field::F61p;

pub(crate) struct PermutationCheckV1;

impl Plugin for PermutationCheckV1 {
    const NAME: &'static str = "permutation_check_v1";

    fn gates_body(
        operation: &str,
        params: &[PluginTypeArg],
        output_counts: &[(TypeId, WireCount)],
        input_counts: &[(TypeId, WireCount)],
        type_store: &TypeStore,
        _fun_store: &FunStore,
    ) -> eyre::Result<GatesBody> {
        ensure!(
            operation == "assert_perm",
            "{}: Invalid operation: {operation}",
            Self::NAME
        );
        ensure!(
            params.len() == 1,
            "{}: Invalid number of params (must be one): {}",
            Self::NAME,
            params.len()
        );
        let PluginTypeArg::Number(tuple_size) = params[0] else {
            eyre::bail!("{}: The tuple size parameter must be numeric, not a string.", Self::NAME);
        };
        // TODO: Should we assume this param fits in a u64?
        let tuple_size = tuple_size.as_words()[0];
        ensure!(tuple_size != 0, "{}: Tuple size cannot be zero", Self::NAME);
        ensure!(
            output_counts.len() == 0,
            "{}: Output count must be zero",
            Self::NAME
        );
        ensure!(
            input_counts.len() == 2,
            "{}: Input count must be two",
            Self::NAME
        );
        ensure!(
            input_counts[0].0 == input_counts[1].0,
            "{}: Input type indices must match",
            Self::NAME
        );
        let type_id = input_counts[0].0;
        let type_spec = type_store.get(&type_id)?;
        let field = match type_spec {
            TypeSpecification::Field(field) => *field,
            other => {
                return Err(eyre!(
                    "{}: Invalid type specification, must be `Field`: {other:?}",
                    Self::NAME,
                ))
            }
        };
        if field != std::any::TypeId::of::<F61p>() {
            todo!("Currently only support F61p");
        }

        ensure!(
            input_counts[0].1 == input_counts[1].1,
            "{}: Input lengths must match",
            Self::NAME
        );
        let nwires = input_counts[0].1;
        ensure!(
            nwires % tuple_size == 0,
            "{}: Number of wires must be divisible by `t`",
            Self::NAME
        );

        if tuple_size != 1 {
            todo!("Tuple sizes besides one temporarily not supported!");
        }

        let count = first_unused_wire_id(output_counts, input_counts);
        let challenge_gate = count;

        let mut gates = vec![];

        gates.push(GateM::Challenge(type_id, count));

        // Compute (xᵢ + c) -> x'ᵢ
        for i in 0..nwires {
            gates.push(GateM::Add(type_id, count + i + 1, i, challenge_gate));
        }
        // Compute ∏ x'ᵢ -> x
        let mut last = count + 1;
        for i in 1..nwires {
            gates.push(GateM::Mul(type_id, count + nwires + i, last, count + i + 1));
            last = count + nwires + i;
        }
        let x = last;
        // Compute (yᵢ + c) -> y'ᵢ
        for i in 0..nwires {
            gates.push(GateM::Add(type_id, x + i + 1, nwires + i, challenge_gate));
        }
        // Compute ∏ y'ᵢ -> y
        let mut last = 2 * count;
        for i in 1..nwires {
            gates.push(GateM::Mul(type_id, x + nwires + i, last, 2 * count + i));
            last = 2 * count + nwires + i - 1;
        }
        let y = last;
        let z = y + 1;
        // Compute x - y -> z
        gates.push(GateM::Sub(type_id, z, x, y));
        // AssertZero(z)
        gates.push(GateM::AssertZero(type_id, z));

        Ok(GatesBody::new(gates))
    }
}

#[cfg(test)]
mod tests {
    use super::PermutationCheckV1;
    use crate::{
        backend_multifield::tests::{test_circuit, F61P_VEC},
        circuit_ir::{FunStore, FuncDecl, GateM, TypeStore},
        plugins::Plugin,
    };
    use mac_n_cheese_sieve_parser::PluginTypeArg;
    use scuttlebutt::{field::F61p, ring::FiniteRing, serialization::CanonicalSerialize, AesRng};

    #[test]
    fn test_permutation_1() {
        let fields = vec![F61P_VEC.to_vec()];
        let mut fun_store = FunStore::default();
        let type_store = TypeStore::try_from(fields.clone()).unwrap();

        let name: String = "permutation".into();
        let func = FuncDecl::new_plugin(
            name.clone(),
            42,
            vec![],
            vec![(0, 1), (0, 1)],
            PermutationCheckV1::NAME.into(),
            "assert_perm".into(),
            vec![PluginTypeArg::from_str("1").unwrap()],
            vec![],
            vec![],
            &type_store,
            &fun_store,
        )
        .unwrap();
        fun_store.insert(name.clone(), func);
        let gates = vec![
            GateM::New(0, 0, 2),
            GateM::Witness(0, 0),
            GateM::Instance(0, 1),
            GateM::Call(Box::new((name.clone(), vec![], vec![(0, 0), (1, 1)]))),
        ];

        let mut rng = AesRng::new();

        let a = F61p::random(&mut rng).to_bytes().to_vec();

        let witnesses = vec![vec![a.clone()]];
        let instances = vec![vec![a]];

        test_circuit(fields, fun_store, gates, instances, witnesses).unwrap();
    }

    #[test]
    fn test_permutation_2() {
        let fields = vec![F61P_VEC.to_vec()];
        let mut fun_store = FunStore::default();
        let type_store = TypeStore::try_from(fields.clone()).unwrap();

        let name: String = "permutation".into();
        let func = FuncDecl::new_plugin(
            name.clone(),
            42,
            vec![],
            vec![(0, 2), (0, 2)],
            PermutationCheckV1::NAME.into(),
            "assert_perm".into(),
            vec![PluginTypeArg::from_str("1").unwrap()],
            vec![],
            vec![],
            &type_store,
            &fun_store,
        )
        .unwrap();
        fun_store.insert(name.clone(), func);
        let gates = vec![
            GateM::New(0, 0, 4),
            GateM::Witness(0, 0),
            GateM::Witness(0, 1),
            GateM::Instance(0, 2),
            GateM::Instance(0, 3),
            GateM::Call(Box::new((name.clone(), vec![], vec![(0, 1), (2, 3)]))),
        ];

        let mut rng = AesRng::new();

        let a = F61p::random(&mut rng).to_bytes().to_vec();
        let b = F61p::random(&mut rng).to_bytes().to_vec();

        let witnesses = vec![vec![a.clone(), b.clone()]];
        let instances = vec![vec![b, a]];

        test_circuit(fields, fun_store, gates, instances, witnesses).unwrap();
    }

    #[test]
    fn test_permutation_4() {
        let fields = vec![F61P_VEC.to_vec()];
        let mut fun_store = FunStore::default();
        let type_store = TypeStore::try_from(fields.clone()).unwrap();

        let name: String = "permutation".into();
        let func = FuncDecl::new_plugin(
            name.clone(),
            42,
            vec![],
            vec![(0, 4), (0, 4)],
            PermutationCheckV1::NAME.into(),
            "assert_perm".into(),
            vec![PluginTypeArg::from_str("1").unwrap()],
            vec![],
            vec![],
            &type_store,
            &fun_store,
        )
        .unwrap();
        fun_store.insert(name.clone(), func);
        let gates = vec![
            GateM::New(0, 0, 8),
            GateM::Witness(0, 0),
            GateM::Witness(0, 1),
            GateM::Witness(0, 2),
            GateM::Witness(0, 3),
            GateM::Instance(0, 4),
            GateM::Instance(0, 5),
            GateM::Instance(0, 6),
            GateM::Instance(0, 7),
            GateM::Call(Box::new((name.clone(), vec![], vec![(0, 3), (4, 7)]))),
        ];

        let mut rng = AesRng::new();

        let a = F61p::random(&mut rng).to_bytes().to_vec();
        let b = F61p::random(&mut rng).to_bytes().to_vec();
        let c = F61p::random(&mut rng).to_bytes().to_vec();
        let d = F61p::random(&mut rng).to_bytes().to_vec();

        let witnesses = vec![vec![a.clone(), b.clone(), c.clone(), d.clone()]];
        let instances = vec![vec![d, c, b, a]];

        test_circuit(fields, fun_store, gates, instances, witnesses).unwrap();
    }

    #[test]
    fn test_bad_permutation_4() {
        let fields = vec![F61P_VEC.to_vec()];
        let mut fun_store = FunStore::default();
        let type_store = TypeStore::try_from(fields.clone()).unwrap();

        let name: String = "permutation".into();
        let func = FuncDecl::new_plugin(
            name.clone(),
            42,
            vec![],
            vec![(0, 4), (0, 4)],
            PermutationCheckV1::NAME.into(),
            "assert_perm".into(),
            vec![PluginTypeArg::from_str("1").unwrap()],
            vec![],
            vec![],
            &type_store,
            &fun_store,
        )
        .unwrap();
        fun_store.insert(name.clone(), func);
        let gates = vec![
            GateM::New(0, 0, 8),
            GateM::Witness(0, 0),
            GateM::Witness(0, 1),
            GateM::Witness(0, 2),
            GateM::Witness(0, 3),
            GateM::Instance(0, 4),
            GateM::Instance(0, 5),
            GateM::Instance(0, 6),
            GateM::Instance(0, 7),
            GateM::Call(Box::new((name.clone(), vec![], vec![(0, 3), (4, 7)]))),
        ];

        let mut rng = AesRng::new();

        let a = F61p::random(&mut rng).to_bytes().to_vec();
        let b = F61p::random(&mut rng).to_bytes().to_vec();
        let c = F61p::random(&mut rng).to_bytes().to_vec();
        let d = F61p::random(&mut rng).to_bytes().to_vec();

        let witnesses = vec![vec![a.clone(), b.clone(), c.clone(), d.clone()]];
        let instances = vec![vec![d, c, b.clone(), b]];

        let result = test_circuit(fields, fun_store, gates, instances, witnesses);
        assert!(result.is_err());
    }
}
