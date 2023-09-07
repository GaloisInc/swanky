//! This module contains a collection of circuit gadgets.
//!
//! A circuit gadget implements some computation over a (possibly
//! type-constrained) [`BackendT`]. Each gadget is encapsulated in a trait to
//! allow reusing the gadget between both the prover and the verifier.
//!
//! To "enable" a gadget for a particular implementation of [`BackendT`], add
//! the appropriate `impl GadgetName for Backend`.
//!
//! Note! A significant limitation of this design is when we need to
//! "specialize" a gadget to a particular field. For example, we need a
//! specialized gadget for a permutation check on [`F2`]. This is not possible
//! with the current design, so for something like [`F2`] we need to revert to
//! the old "copy-the-code-between-the-prover-and-verifier" approach, which is
//! not ideal. A potential fix for this is to move to using a `Party` trait
//! instead of having separate `Prover` and `Verifier` implementations. However,
//! this is a much larger refactor, and will take time. So for now, if we need
//! specialization, we copy-and-paste.

use crate::{
    backend_multifield::{DietMacAndCheeseConvProver, DietMacAndCheeseConvVerifier},
    backend_trait::BackendT,
    homcom::{MacProver, MacVerifier},
    svole_trait::SvoleT,
    DietMacAndCheeseProver, DietMacAndCheeseVerifier,
};
use eyre::{ensure, Result};
use generic_array::typenum::Unsigned;
use scuttlebutt::AbstractChannel;
use std::fmt::Debug;
use swanky_field::{
    FiniteField, FiniteRing, IsSubFieldOf, PrimeFiniteField, StatisticallySecureField,
};
use swanky_field_binary::{F40b, F2};

/// This trait defines a generic MAC, which can be realized as either a
/// [`MacProver`] or a [`MacVerifier`].
trait Mac<V: IsSubFieldOf<T>, T: FiniteField>: Clone + Copy + Debug + PartialEq
where
    T::PrimeField: IsSubFieldOf<V>,
{
}

/// A [`MacProver`] is a [`Mac`].
impl<V: IsSubFieldOf<T>, T: FiniteField> Mac<V, T> for MacProver<V, T> where
    T::PrimeField: IsSubFieldOf<V>
{
}

/// A [`MacVerifier`] is a [`Mac`].
impl<V: IsSubFieldOf<T>, T: FiniteField> Mac<V, T> for MacVerifier<T> where
    T::PrimeField: IsSubFieldOf<V>
{
}

/// This trait implements a "less-than-or-equal" circuit `a <= b` for [`F2`],
/// where `a` contains MAC'd values, and `b` is public.
pub(crate) trait GadgetLessThanEqWithPublic: BackendT<FieldElement = F2> {
    fn less_than_eq_with_public(&mut self, a: &[<Self as BackendT>::Wire], b: &[F2]) -> Result<()> {
        // act = 1;
        // r   = 0;
        // for i in 0..(n+1):
        //     act' = act(1+a+b)
        //     r'   = r + ((r+1) * act * a * (b+1))
        // assert_zero(r)
        assert_eq!(a.len(), b.len());

        let mut act = self.input_public(F2::ONE)?;
        let mut r = self.input_public(F2::ZERO)?;

        // data assumed provided in little-endian
        let l = a.len();
        for i in 0..a.len() {
            let a_i = a[l - i - 1];
            let b_i = b[l - i - 1];
            // (1+a+b)
            let a_plus_b = self.add_constant(&a_i, b_i)?;
            let one_plus_a_plus_b = self.add_constant(&a_plus_b, F2::ONE)?;

            // act' = act(1+a+b)
            let act_prime = self.mul(&act, &one_plus_a_plus_b)?;

            // r + 1
            let r_plus_one = self.add_constant(&r, F2::ONE)?;

            // p1 = a * (b+1)
            let b_1 = b_i + F2::ONE;
            let p1 = self.mul_constant(&a_i, b_1)?;

            // act * (a * (b+1))
            let act_times_p1 = self.mul(&act, &p1)?;

            // (r+1) * (act * (a * (b+1)))
            let p2 = self.mul(&r_plus_one, &act_times_p1)?;

            // r' = r + ((r+1) * act * a * (b+1))
            let r_prime = self.add(&r, &p2)?;

            act = act_prime;
            r = r_prime;
        }

        self.assert_zero(&r)
    }
}

/// Enable [`GadgetLessThanEqWithPublic`] for the DMC prover over [`F2`].
impl<C: AbstractChannel, Svole: SvoleT<(F2, F40b)>> GadgetLessThanEqWithPublic
    for DietMacAndCheeseProver<F2, F40b, C, Svole>
{
}
/// Enable [`GadgetLessThanEqWithPublic`] for the DMC verifier over [`F2`].
impl<C: AbstractChannel, Svole: SvoleT<F40b>> GadgetLessThanEqWithPublic
    for DietMacAndCheeseVerifier<F2, F40b, C, Svole>
{
}

/// This trait implements a "dotproduct" gadget.
///
/// It computes `xs · ys`, where `xs` contains MAC'd values and `ys` contains
/// public values.
///
/// This gadget works over all fields.
pub(crate) trait GadgetDotProduct: BackendT {
    fn dotproduct_with_public(
        &mut self,
        xs: &[Self::Wire],
        ys: &[Self::FieldElement],
    ) -> Result<Self::Wire> {
        let mut result = self.input_public(Self::FieldElement::ZERO)?;
        for (x, y) in xs.iter().zip(ys.iter()) {
            let tmp = self.mul_constant(x, *y)?;
            result = self.add(&result, &tmp)?;
        }
        Ok(result)
    }
}

/// Enable [`GadgetDotProduct`] for the prover over all fields.
impl<V: IsSubFieldOf<T>, T: FiniteField, C: AbstractChannel, Svole: SvoleT<(V, T)>> GadgetDotProduct
    for DietMacAndCheeseProver<V, T, C, Svole>
where
    T::PrimeField: IsSubFieldOf<V>,
{
}
/// Enable [`GadgetDotProduct`] for the verifier over all fields.
impl<V: IsSubFieldOf<T>, T: FiniteField, C: AbstractChannel, Svole: SvoleT<T>> GadgetDotProduct
    for DietMacAndCheeseVerifier<V, T, C, Svole>
where
    T::PrimeField: IsSubFieldOf<V>,
{
}
/// Enable [`GadgetDotProduct`] for the conversion prover over all fields.
impl<
        T: PrimeFiniteField,
        C: AbstractChannel,
        SvoleF2: SvoleT<(F2, F40b)>,
        SvoleFE: SvoleT<(T, T)>,
    > GadgetDotProduct for DietMacAndCheeseConvProver<T, C, SvoleF2, SvoleFE>
{
}
/// Enable [`GadgetDotProduct`] for the conversion verifier over all fields.
impl<T: PrimeFiniteField, C: AbstractChannel, SvoleF2: SvoleT<F40b>, SvoleFE: SvoleT<T>>
    GadgetDotProduct for DietMacAndCheeseConvVerifier<T, C, SvoleF2, SvoleFE>
{
}

/// This trait implements a "permutation check" gadget.
///
/// It asserts that `xs = 𝛑(ys)`, erroring out if not.
///
/// This gadget currently only works over fields larger than the statistical
/// security parameter (which we have harded at 40 bits).
pub(crate) trait GadgetPermutationCheck: BackendT + GadgetDotProduct {
    fn permutation_check(
        &mut self,
        xs: &[Self::Wire],
        ys: &[Self::Wire],
        ntuples: usize,
        tuple_size: usize,
    ) -> Result<()> {
        ensure!(
            <Self::FieldElement as FiniteField>::NumberOfBitsInBitDecomposition::USIZE >= 40,
            "Field size must be >= 40 bits"
        );

        ensure!(xs.len() == ys.len(), "Input lengths are not equal",);
        ensure!(
            xs.len() == ntuples * tuple_size,
            "Provided input length not equal to expected input length",
        );

        let minus_one = -Self::FieldElement::ONE;
        let random = self.random()?;

        // TODO: Better would be to generate random values using `random` as a seed.
        let mut acc = random;
        let mut challenges = vec![Self::FieldElement::ZERO; tuple_size];
        for challenge in challenges.iter_mut() {
            *challenge = acc;
            acc = random * random;
        }

        let challenge = self.random()?;

        let mut x = self.constant(Self::FieldElement::ONE)?;
        for i in 0..ntuples {
            let result = self
                .dotproduct_with_public(&xs[i * tuple_size..(i + 1) * tuple_size], &challenges)?;
            let tmp = self.add_constant(&result, challenge * minus_one)?;
            x = self.mul(&x, &tmp)?;
        }
        let mut y = self.constant(Self::FieldElement::ONE)?;
        for i in 0..ntuples {
            let result = self
                .dotproduct_with_public(&ys[i * tuple_size..(i + 1) * tuple_size], &challenges)?;
            let tmp = self.add_constant(&result, challenge * minus_one)?;
            y = self.mul(&y, &tmp)?;
        }
        let z = self.sub(&x, &y)?;
        self.assert_zero(&z)
    }
}

impl<
        T: PrimeFiniteField + StatisticallySecureField,
        C: AbstractChannel,
        SvoleF2: SvoleT<(F2, F40b)>,
        SvoleFE: SvoleT<(T, T)>,
    > GadgetPermutationCheck for DietMacAndCheeseConvProver<T, C, SvoleF2, SvoleFE>
{
}
impl<
        T: PrimeFiniteField + StatisticallySecureField,
        C: AbstractChannel,
        SvoleF2: SvoleT<F40b>,
        SvoleFE: SvoleT<T>,
    > GadgetPermutationCheck for DietMacAndCheeseConvVerifier<T, C, SvoleF2, SvoleFE>
{
}

/// Note: This is not correct! F2 is NOT secure! Need to use extension fields here.
impl<C: AbstractChannel, Svole: SvoleT<(F2, F40b)>> GadgetPermutationCheck
    for DietMacAndCheeseProver<F2, F40b, C, Svole>
{
}
/// Note: This is not correct! F2 is NOT secure! Need to use extension fields here.
impl<C: AbstractChannel, Svole: SvoleT<F40b>> GadgetPermutationCheck
    for DietMacAndCheeseVerifier<F2, F40b, C, Svole>
{
}
