//! This module contains a collection of circuits.
//!
//! Each circuit is encapsulated in a trait. To "enable" a circuit for a
//! particular implementation of [`BackendT`], add the appropriate `impl
//! CircuitName for Backend`.

use crate::{
    backend_trait::BackendT,
    homcom::{MacProver, MacVerifier},
    DietMacAndCheeseProver, DietMacAndCheeseVerifier,
};
use eyre::Result;
use scuttlebutt::AbstractChannel;
use std::fmt::Debug;
use swanky_field::{FiniteField, FiniteRing, IsSubFieldOf};
use swanky_field_binary::{F40b, F2};

/// This trait defines a generic MAC, which can be realized as either a
/// [`MacProver`] or a [`MacVerifier`].
pub(crate) trait Mac<V: IsSubFieldOf<T>, T: FiniteField>:
    Clone + Copy + Debug + PartialEq
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
pub(crate) trait BackendLessEqThanWithPublic<M: Mac<F2, F40b>>:
    BackendT<FieldElement = F2, Wire = M>
{
    fn less_eq_than_with_public2(&mut self, a: &[M], b: &[F2]) -> Result<()> {
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

/// Enable [`BackendLessEqThanWithPublic`] for the DMC prover over [`F2`].
impl<C: AbstractChannel> BackendLessEqThanWithPublic<MacProver<F2, F40b>>
    for DietMacAndCheeseProver<F2, F40b, C>
{
}
/// Enable [`BackendLessEqThanWithPublic`] for the DMC verifier over [`F2`].
impl<C: AbstractChannel> BackendLessEqThanWithPublic<MacVerifier<F40b>>
    for DietMacAndCheeseVerifier<F2, F40b, C>
{
}
