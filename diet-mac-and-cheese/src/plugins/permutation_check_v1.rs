use super::{Plugin, PluginExecution};
use crate::{
    backend_trait::BackendT,
    circuit_ir::{FunStore, TypeId, TypeStore, WireCount},
};
use eyre::{bail, ensure, Result};
use mac_n_cheese_sieve_parser::PluginTypeArg;
use swanky_field::FiniteRing;

/// The permutation check plugin.
#[derive(Clone, Debug)]
pub(crate) struct PermutationCheckV1 {
    /// The [`TypeId`] associated with this permutation check.
    type_id: TypeId,
    /// The number of tuples to check.
    ntuples: usize,
    /// The number of elements in each tuple.
    tuple_size: usize,
}

impl PermutationCheckV1 {
    /// Create a new [`PermutationCheckV1`] instantiation for the field
    /// associated with the provided [`TypeId`] and the provided number of
    /// tuples and tuple size.
    pub(crate) fn new(type_id: TypeId, ntuples: usize, tuple_size: usize) -> Self {
        Self {
            type_id,
            ntuples,
            tuple_size,
        }
    }

    /// Return the [`TypeId`] of this instantiation.
    pub(crate) fn type_id(&self) -> TypeId {
        self.type_id
    }

    /// Run the permutation check on two lists provided by `xs` and `ys`,
    /// utilizing the provided `backend`.
    pub(crate) fn execute<B: BackendT>(
        &self,
        xs: &[B::Wire],
        ys: &[B::Wire],
        backend: &mut B,
    ) -> Result<()> {
        ensure!(
            self.tuple_size == 1,
            "{}: Tuple sizes besides one temporarily not supported!",
            Self::NAME
        );
        ensure!(
            xs.len() == ys.len(),
            "{}: Input lengths are not equal",
            Self::NAME
        );
        ensure!(
            xs.len() == self.ntuples * self.tuple_size,
            "{}: Provided input length not equal to expected input length",
            Self::NAME
        );

        let minus_one = -B::FieldElement::ONE;
        let challenge = backend.random()?;
        let mut x = backend.constant(B::FieldElement::ONE)?;
        for x_i in xs {
            let tmp = backend.add_constant(x_i, challenge * minus_one)?;
            x = backend.mul(&x, &tmp)?;
        }
        let mut y = backend.constant(B::FieldElement::ONE)?;
        for y_i in ys {
            let tmp = backend.add_constant(y_i, challenge * minus_one)?;
            y = backend.mul(&y, &tmp)?;
        }
        let z = backend.sub(&x, &y)?;
        backend.assert_zero(&z)
    }
}

impl Plugin for PermutationCheckV1 {
    const NAME: &'static str = "permutation_check_v1";

    fn instantiate(
        operation: &str,
        params: &[PluginTypeArg],
        output_counts: &[(TypeId, WireCount)],
        input_counts: &[(TypeId, WireCount)],
        _type_store: &TypeStore,
        _fun_store: &FunStore,
    ) -> eyre::Result<PluginExecution> {
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
            bail!("{}: The tuple size parameter must be numeric, not a string.", Self::NAME);
        };
        // TODO: Should we assume this param fits in a u64?
        let tuple_size: u64 = tuple_size.as_words()[0].into();
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

        Ok(PluginExecution::PermutationCheck(PermutationCheckV1::new(
            type_id,
            nwires as usize,
            tuple_size as usize,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::PermutationCheckV1;
    use crate::{
        backend_multifield::tests::test_circuit,
        circuit_ir::{FunStore, FuncDecl, GateM, TypeStore},
        fields::F61P_MODULUS,
        plugins::Plugin,
    };
    use mac_n_cheese_sieve_parser::PluginTypeArg;
    use scuttlebutt::{
        field::{F61p, PrimeFiniteField},
        ring::FiniteRing,
        AesRng,
    };

    #[test]
    fn test_permutation_1() {
        let fields = vec![F61P_MODULUS];
        let mut fun_store = FunStore::default();
        let type_store = TypeStore::try_from(fields.clone()).unwrap();

        let name: String = "permutation".into();
        let func = FuncDecl::new_plugin(
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

        let a = F61p::random(&mut rng).into_int();

        let witnesses = vec![vec![a.clone()]];
        let instances = vec![vec![a]];

        test_circuit(fields, fun_store, gates, instances, witnesses).unwrap();
    }

    #[test]
    fn test_permutation_2() {
        let fields = vec![F61P_MODULUS];
        let mut fun_store = FunStore::default();
        let type_store = TypeStore::try_from(fields.clone()).unwrap();

        let name: String = "permutation".into();
        let func = FuncDecl::new_plugin(
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

        let a = F61p::random(&mut rng).into_int();
        let b = F61p::random(&mut rng).into_int();

        let witnesses = vec![vec![a.clone(), b.clone()]];
        let instances = vec![vec![b, a]];

        test_circuit(fields, fun_store, gates, instances, witnesses).unwrap();
    }

    #[test]
    fn test_permutation_4() {
        let fields = vec![F61P_MODULUS];
        let mut fun_store = FunStore::default();
        let type_store = TypeStore::try_from(fields.clone()).unwrap();

        let name: String = "permutation".into();
        let func = FuncDecl::new_plugin(
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

        let a = F61p::random(&mut rng).into_int();
        let b = F61p::random(&mut rng).into_int();
        let c = F61p::random(&mut rng).into_int();
        let d = F61p::random(&mut rng).into_int();

        let witnesses = vec![vec![a.clone(), b.clone(), c.clone(), d.clone()]];
        let instances = vec![vec![d, c, b, a]];

        test_circuit(fields, fun_store, gates, instances, witnesses).unwrap();
    }

    #[test]
    fn test_bad_permutation_4() {
        let fields = vec![F61P_MODULUS];
        let mut fun_store = FunStore::default();
        let type_store = TypeStore::try_from(fields.clone()).unwrap();

        let name: String = "permutation".into();
        let func = FuncDecl::new_plugin(
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

        let a = F61p::random(&mut rng).into_int();
        let b = F61p::random(&mut rng).into_int();
        let c = F61p::random(&mut rng).into_int();
        let d = F61p::random(&mut rng).into_int();

        let witnesses = vec![vec![a.clone(), b.clone(), c.clone(), d.clone()]];
        let instances = vec![vec![d, c, b.clone(), b]];

        let result = test_circuit(fields, fun_store, gates, instances, witnesses);
        assert!(result.is_err());
    }
}
