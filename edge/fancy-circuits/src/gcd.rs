use crate::{
    BinaryBundle,
    binary::{BinaryEquality, BinarySubtraction, Mux, MuxBit},
};
use core::marker::PhantomData;
use fancy_traits::{Circuit, FancyBinary, FancyConstant};
use swanky_channel::Channel;
use swanky_error::Result;
use swanky_field::FiniteRing;
use swanky_field_binary::F2;

/// Given [`BinaryBundle`]s `a` and `b`, output `GCD(a, b)`.
#[derive(Default)]
pub struct Gcd<'a, const N: usize> {
    upper_bound: usize,
    _phantom: PhantomData<&'a ()>,
}

impl<'a, const N: usize> Gcd<'a, N> {
    /// Create a new [`Gcd`] circuit using a fixed upper bound.
    ///
    /// Since the circuit needs to be oblivious, we cannot terminate the GCD
    /// algorithm by conditioning on the values of `a` or `b` as is the case in
    /// the "standard" version of GCD. Instead, we rely on an upper bound on the
    /// number of iterations we know the algorithm will terminate by. The
    /// Euclidean algorithm based on subtractions will take no more than `N` steps
    /// where `N` is the larger of the two numbers we are computing the GCD for.
    pub fn new(upper_bound: usize) -> Self {
        Self {
            upper_bound,
            _phantom: PhantomData,
        }
    }
}

impl<'a, F: FancyBinary + FancyConstant<F2>, const N: usize> Circuit<F> for Gcd<'a, N>
where
    F::Item: 'a,
{
    type Input = (&'a BinaryBundle<F::Item, N>, &'a BinaryBundle<F::Item, N>);
    type Output = BinaryBundle<F::Item, N>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (a_ref, b_ref) = inputs;
        let mut a = (*a_ref).clone();
        let mut b = (*b_ref).clone();
        let zero = backend.constant(F2::ZERO);

        for _ in 0..self.upper_bound {
            // Since the circuit is non-branching, we don't know whether `a > b`
            // and cannot branch computation based on that result of that
            // conditional. Instead, we need to perform the computation that
            // occurs for all cases of the predict "is a > b ?", i.e. (1) `a >
            // b`, and (2) `b > a`. We consider the case where `a == b`
            // separately since that is the case where we stop updating our
            // variables and find the result of the computation `gcd(a,b)`.

            // Compute `a := a - b` and check for an underflow that will help
            // determine if `a > b`.
            let (r_1, mut underflow_r_1) =
                BinarySubtraction::default().execute(backend, (&a, &b), channel)?;
            // Compute `b := b - a` and check for an underflow that will help
            // determine if `b > a`.
            let (r_2, mut underflow_r_2) =
                BinarySubtraction::default().execute(backend, (&b, &a), channel)?;

            let is_equal = BinaryEquality::default().execute(backend, (&a, &b), channel)?;

            // The `underflow` bits act as dual purpose multiplexing bits:
            // (1) If a > b then underflow_r_1 = 1 and underflow_r_2 = 0
            // (2) If b > a then underflow_r_1 = 0 and underflow_r_2 = 1
            // (3) If a == b then underflow_r_1 = underflow_r_2 = 0
            underflow_r_1 =
                MuxBit::default().execute(backend, (&is_equal, &underflow_r_1, &zero), channel)?;
            underflow_r_2 =
                MuxBit::default().execute(backend, (&is_equal, &underflow_r_2, &zero), channel)?;

            // Using the `underflow` bits we multiplex in the following way:
            // (1) If a > b, a := a - b and b := b
            // (2) If b > a, a := a  and b := b - a
            // (3) If a == b, a := a and b := b
            a = Mux::default().execute(backend, (underflow_r_1, &a, &r_1), channel)?;
            b = Mux::default().execute(backend, (underflow_r_2, &b, &r_2), channel)?;
        }

        Ok(a)
    }
}
