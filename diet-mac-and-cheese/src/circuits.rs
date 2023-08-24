//! This module contains a collection of circuits.
//!
//! Each circuit is encapsulated in a trait. To "enable" a circuit for a
//! particular implementation of [`BackendT`], add the appropriate `impl
//! CircuitName for Backend`.

use crate::{backend_trait::BackendT, homcom::Mac};
use eyre::Result;
use swanky_field::FiniteRing;
use swanky_field_binary::{F40b, F2};

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
