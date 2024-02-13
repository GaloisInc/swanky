//! This module implements the permutation check plugin.
//!
//! We check that two lists are permutations of each other by mapping the lists
//! to polynomials and doing a polynomial equality check. This allows us to
//! compute the check with `O(N)` multiplications, where `N` is the list size.
//! Using a sorting network would require `O(N log N)` multiplications.
//!
//! Consider lists `A = [a_1, ..., a_n]` and `B = [b_1, ..., b_n]`. We can view
//! these as the polynomials `A(X) = ∏_i (X - a_i)` and `B(X) = ∏_i (X - b_i)`.
//! Now, based on Schwartz-Zippel, given a random value `r` then `A(r) = B(r) ⇒
//! A = B` with high probability.
//!
//! Thus, the protocol proceeds by the verifier sending a random "challenge"
//! value `r` to the prover, and then the parties check that `ZeroTest(A(r) -
//! B(r))` holds.
//!
//! The above approach works if each list contains only single elements, however
//! we also support the setting where, say, a given `a_i` is composed of a tuple
//! of elements `(a_i1, ..., a_im)`. We map these `m` values to a single element
//! by computing the dot product with the vector `(r, r^2, ..., r^m)` for some
//! random `r` supplied by the verifier.

use super::{Plugin, PluginExecution};
use crate::{
    backend_multifield::BackendLiftT,
    circuit_ir::{FunStore, TypeId, TypeSpecification, TypeStore, WireCount},
    gadgets::{permutation_check, permutation_check_binary},
    mac::MacT,
};
use eyre::{bail, ensure, Result};
use mac_n_cheese_sieve_parser::PluginTypeArg;
use swanky_field_binary::F2;

/// The permutation check plugin.
#[derive(Clone, Debug)]
pub(crate) struct PermutationCheckV1 {
    /// The [`TypeId`] associated with this permutation check.
    type_id: TypeId,
    field_type_id: std::any::TypeId,
    /// The number of tuples to check.
    ntuples: usize,
    /// The number of elements in each tuple.
    tuple_size: usize,
}

impl PermutationCheckV1 {
    /// Create a new [`PermutationCheckV1`] instantiation for the field
    /// associated with the provided [`TypeId`] and the provided number of
    /// tuples and tuple size.
    pub(crate) fn new(
        type_id: TypeId,
        field_type_id: std::any::TypeId,
        ntuples: usize,
        tuple_size: usize,
    ) -> Self {
        Self {
            type_id,
            field_type_id,
            ntuples,
            tuple_size,
        }
    }

    /// Return the [`TypeId`] of this instantiation.
    pub(crate) fn type_id(&self) -> TypeId {
        self.type_id
    }

    pub(crate) fn execute_binary<M: MacT, B: BackendLiftT<Wire = M>>(
        &self,
        xs: impl Iterator<Item = B::Wire>,
        ys: impl Iterator<Item = B::Wire>,
        backend: &mut B,
    ) -> Result<()> {
        assert_eq!(self.field_type_id, std::any::TypeId::of::<F2>());
        permutation_check_binary::<M, B>(backend.lift(), xs, ys, self.ntuples, self.tuple_size)
    }

    /// Run the permutation check on two lists provided by `xs` and `ys`,
    /// utilizing the provided `backend`.
    pub(crate) fn execute<B: BackendLiftT>(
        &self,
        xs: impl Iterator<Item = B::Wire>,
        ys: impl Iterator<Item = B::Wire>,
        backend: &mut B,
    ) -> Result<()> {
        if std::any::TypeId::of::<B::FieldElement>() == std::any::TypeId::of::<F2>() {
            self.execute_binary::<B::Wire, B>(xs, ys, backend)
        } else {
            assert_ne!(self.field_type_id, std::any::TypeId::of::<F2>());
            permutation_check(backend, xs, ys, self.ntuples, self.tuple_size)
        }
    }
}

impl Plugin for PermutationCheckV1 {
    const NAME: &'static str = "permutation_check_v1";

    fn instantiate(
        operation: &str,
        params: &[PluginTypeArg],
        output_counts: &[(TypeId, WireCount)],
        input_counts: &[(TypeId, WireCount)],
        type_store: &TypeStore,
        _fun_store: &FunStore,
    ) -> Result<PluginExecution> {
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
            bail!(
                "{}: The tuple size parameter must be numeric, not a string.",
                Self::NAME
            );
        };
        // TODO: Should we assume this param fits in a u64?
        #[cfg(not(target_arch = "wasm32"))]
        let tuple_size: u64 = tuple_size.as_words()[0];

        #[cfg(target_arch = "wasm32")]
        let tuple_size: u64 = tuple_size.as_words()[0] as u64;

        ensure!(tuple_size != 0, "{}: Tuple size cannot be zero", Self::NAME);
        ensure!(
            output_counts.is_empty(),
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

        let field_type_id = match type_store.get(&type_id).unwrap() {
            TypeSpecification::Field(f) => *f,
            _ => {
                bail!("Plugin does not support plugin types");
            }
        };

        Ok(PluginExecution::PermutationCheck(PermutationCheckV1::new(
            type_id,
            field_type_id,
            ntuples as usize,
            tuple_size as usize,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::PermutationCheckV1;
    use crate::{
        backend_multifield::tests::{test_circuit, test_circuit_plaintext},
        circuit_ir::{FunStore, FuncDecl, GateM, TypeStore},
        fields::{F2_MODULUS, F61P_MODULUS},
        plugins::Plugin,
    };
    use mac_n_cheese_sieve_parser::{Number, PluginTypeArg};
    use rand::seq::SliceRandom;
    use scuttlebutt::AesRng;
    use swanky_field::PrimeFiniteField;
    use swanky_field_binary::F2;
    use swanky_field_f61p::F61p;

    fn create_gates(ntuples: u64, tuple_size: u64, modulus: Number) -> (FunStore, Vec<GateM>) {
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
        let fun_id = fun_store.insert(name.clone(), func).unwrap();
        let mut gates = vec![GateM::New(0, 0, total * 2)];
        gates.push(GateM::Witness(0, (0, total - 1)));
        gates.push(GateM::Instance(0, (total, total + total - 1)));
        gates.push(GateM::Call(Box::new((
            fun_id,
            vec![],
            vec![(0, total - 1), (total, 2 * total - 1)],
        ))));

        (fun_store, gates)
    }

    fn test_permutation<F: PrimeFiniteField>(
        ntuples: u64,
        tuple_size: u64,
        modulus: Number,
        is_good: bool,
    ) {
        let fields = vec![modulus];
        let (fun_store, gates) = create_gates(ntuples, tuple_size, modulus);

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

    // This is similar to `test_permutation` but using the plaintext evaluator and specialized for F2
    fn test_permutation_binary_plaintext<F: PrimeFiniteField>(
        ntuples: u64,
        tuple_size: u64,
        modulus: Number,
        is_good: bool,
    ) {
        let fields = vec![modulus];
        let (fun_store, gates) = create_gates(ntuples, tuple_size, modulus);

        let mut rng = AesRng::new();
        let mut v: Vec<Vec<F>> = (0..ntuples)
            .map(|_| (0..tuple_size).map(|_| F::random(&mut rng)).collect())
            .collect();

        let witnesses: Vec<Number> = v
            .clone()
            .into_iter()
            .flatten()
            .map(|x| x.into_int())
            .collect();
        v.shuffle(&mut rng);
        let mut copy_v: Vec<F> = v.into_iter().flatten().collect();
        if !is_good {
            copy_v[0] = F::ONE - copy_v[0]; // take the negative value instead of random, so that it works for binary
        }

        let instances: Vec<Number> = copy_v.into_iter().map(|x| x.into_int()).collect();

        let result =
            test_circuit_plaintext(fields, fun_store, gates, vec![instances], vec![witnesses]);
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

    #[test]
    fn permutation_of_ten_elements_plaintext_works() {
        test_permutation_binary_plaintext::<F2>(10, 1, F2_MODULUS, true);
        test_permutation_binary_plaintext::<F61p>(10, 1, F61P_MODULUS, true);
    }

    #[test]
    fn permutation_of_ten_elements_plaintext_fails() {
        test_permutation_binary_plaintext::<F2>(10, 1, F2_MODULUS, false);
        test_permutation_binary_plaintext::<F61p>(10, 1, F61P_MODULUS, false);
    }
}
