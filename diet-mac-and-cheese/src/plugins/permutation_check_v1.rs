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
        // TODO: Need to ensure that `B::FieldElement` is larger than 40 bits!

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
        let random = backend.random()?;

        // TODO: Better would be to generate random values using `random` as a seed.
        let mut acc = random;
        let mut challenges = vec![B::FieldElement::ZERO; self.tuple_size];
        for challenge in challenges.iter_mut() {
            *challenge = acc;
            acc = random * random;
        }

        let challenge = backend.random()?;

        let mut x = backend.constant(B::FieldElement::ONE)?;
        for i in 0..self.ntuples {
            let result = dotproduct(
                &xs[i * self.tuple_size..(i + 1) * self.tuple_size],
                &challenges,
                backend,
            )?;
            let tmp = backend.add_constant(&result, challenge * minus_one)?;
            x = backend.mul(&x, &tmp)?;
        }
        let mut y = backend.constant(B::FieldElement::ONE)?;
        for i in 0..self.ntuples {
            let result = dotproduct(
                &ys[i * self.tuple_size..(i + 1) * self.tuple_size],
                &challenges,
                backend,
            )?;
            let tmp = backend.add_constant(&result, challenge * minus_one)?;
            y = backend.mul(&y, &tmp)?;
        }
        let z = backend.sub(&x, &y)?;
        backend.assert_zero(&z)
    }
}

fn dotproduct<B: BackendT>(
    xs: &[B::Wire],
    ys: &[B::FieldElement],
    backend: &mut B,
) -> Result<B::Wire> {
    let mut result = backend.input_public(B::FieldElement::ZERO)?;
    for (x, y) in xs.iter().zip(ys.iter()) {
        let tmp = backend.mul_constant(x, *y)?;
        result = backend.add(&result, &tmp)?;
    }
    Ok(result)
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
        let ntuples = nwires / tuple_size;

        Ok(PluginExecution::PermutationCheck(PermutationCheckV1::new(
            type_id,
            ntuples as usize,
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
    use mac_n_cheese_sieve_parser::{Number, PluginTypeArg};
    use rand::seq::SliceRandom;
    use scuttlebutt::AesRng;
    use swanky_field::PrimeFiniteField;
    use swanky_field_f61p::F61p;

    fn test_permutation<F: PrimeFiniteField>(
        ntuples: u64,
        tuple_size: u64,
        modulus: Number,
        is_good: bool,
    ) {
        let total = ntuples * tuple_size;
        let fields = vec![modulus];
        let mut fun_store = FunStore::default();
        let type_store = TypeStore::try_from(fields.clone()).unwrap();

        let name: String = "permutation".into();
        let func = FuncDecl::new_plugin(
            vec![],
            vec![(0, total), (0, total)],
            PermutationCheckV1::NAME.into(),
            "assert_perm".into(),
            vec![PluginTypeArg::Number(tuple_size.into())],
            vec![],
            vec![],
            &type_store,
            &fun_store,
        )
        .unwrap();
        fun_store.insert(name.clone(), func);
        let mut gates = vec![GateM::New(0, 0, total * 2)];
        for i in 0..total {
            gates.push(GateM::Witness(0, i));
        }
        for i in 0..total {
            gates.push(GateM::Instance(0, total + i));
        }
        gates.push(GateM::Call(Box::new((
            name.clone(),
            vec![],
            vec![(0, total - 1), (total, 2 * total - 1)],
        ))));

        let mut rng = AesRng::new();
        let mut v: Vec<Vec<Number>> = (0..ntuples)
            .map(|_| {
                (0..tuple_size)
                    .map(|_| F::random(&mut rng).into_int())
                    .collect()
            })
            .collect();

        let witnesses: Vec<Number> = v.clone().into_iter().flatten().collect();
        v.shuffle(&mut rng);
        let mut instances: Vec<Number> = v.into_iter().flatten().collect();
        if !is_good {
            instances[0] = F::random(&mut rng).into_int();
        }

        let result = test_circuit(fields, fun_store, gates, vec![instances], vec![witnesses]);
        if is_good {
            assert!(result.is_ok());
        } else {
            assert!(result.is_err());
        }
    }

    #[test]
    fn permutation_of_one_element_works() {
        test_permutation::<F61p>(1, 1, F61P_MODULUS, true);
    }

    #[test]
    fn bad_permutation_of_one_element_fails() {
        test_permutation::<F61p>(1, 1, F61P_MODULUS, false);
    }

    #[test]
    fn permutation_of_ten_elements_works() {
        test_permutation::<F61p>(10, 1, F61P_MODULUS, true);
    }

    #[test]
    fn bad_permutation_of_ten_elements_fails() {
        test_permutation::<F61p>(10, 1, F61P_MODULUS, false);
    }

    #[test]
    fn permutation_of_ten_tuples_of_length_five_works() {
        test_permutation::<F61p>(10, 5, F61P_MODULUS, true);
    }

    #[test]
    fn bad_permutation_of_ten_tuples_of_length_five_fails() {
        test_permutation::<F61p>(10, 5, F61P_MODULUS, false);
    }
}
