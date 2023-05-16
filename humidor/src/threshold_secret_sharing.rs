// Copyright (c) 2016 rust-threshold-secret-sharing developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! Packed (or ramp) variant of Shamir secret sharing,
//! allowing efficient sharing of several secrets together.

use scuttlebutt::field::polynomial::NewtonPolynomial;
use scuttlebutt::field::{fft, fft::FieldForFFT, FiniteField};

/// Generator for the packed variant of Shamir secret sharing, specifying number
/// of secrets shared together, total number of shares, and privacy threshold.
///
/// This scheme generalises
/// [Shamir's scheme](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing)
/// by simultaneously sharing several secrets, at the expense of leaving a gap
/// between the privacy threshold and the reconstruction limit.
///
/// The Fast Fourier Transform is used for efficiency reasons,
/// allowing most operations run to quasilinear time `O(n log n)` in `share_count`.
/// An implication of this is that secrets and shares are positioned on positive powers of
/// respectively an `n`-th and `m`-th principal root of unity,
/// where `n` is a power of 2 and `m` a power of 3.
///
/// As a result there exist several constraints between the various parameters:
///
/// * `prime` must be a prime large enough to hold the secrets we plan to share
/// * `share_count` must be at least `secret_count + threshold` (the reconstruction limit)
/// * `secret_count + threshold + 1` must be a power of 2
/// * `share_count + 1` must be a power of 3
/// * `omega_secrets` must be a `(secret_count + threshold + 1)`-th root of unity
/// * `omega_shares` must be a `(share_count + 1)`-th root of unity
///
/// An optional `paramgen` feature provides methods for finding suitable parameters satisfying
/// these somewhat complex requirements, in addition to several fixed parameter choices.
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct PackedSecretSharingGenerator<Field> {
    // abstract properties
    /// Maximum number of shares that can be known without exposing the secrets
    /// (privacy threshold).
    threshold: usize,
    /// Number of shares to split the secrets into.
    share_count: usize,
    /// Number of secrets to share together.
    secret_count: usize,

    // implementation configuration
    /// `m`-th principal root of unity in Zp, where `m = secret_count + threshold + 1`
    /// must be a power of 2.
    pub omega_secrets: Field,
    /// `n`-th principal root of unity in Zp, where `n = share_count + 1` must be a power of 3.
    pub omega_shares: Field,
}

impl<Field: FiniteField + FieldForFFT<2> + FieldForFFT<3>> PackedSecretSharingGenerator<Field> {
    /// Initialize a packed secret sharing generator.
    pub fn new(
        threshold: usize,
        share_count: usize,
        secret_count: usize,
        kexp: usize,
        nexp: usize,
    ) -> Self {
        // TODO: Needs some consistency checks to make sure inputs are sensible!
        let omega_secrets = <Field as FieldForFFT<2>>::roots(kexp);
        let omega_shares = <Field as FieldForFFT<3>>::roots(nexp);
        Self {
            threshold,
            share_count,
            secret_count,
            omega_secrets,
            omega_shares,
        }
    }

    /// Return the number of secrets to share together.
    pub fn secret_count(&self) -> usize {
        self.secret_count
    }

    ///
    pub fn omega_secrets(&self) -> Field {
        self.omega_secrets
    }

    ///
    pub fn omega_shares(&self) -> Field {
        self.omega_shares
    }

    /// Minimum number of shares required to reconstruct secrets.
    ///
    /// For this scheme this is always `secret_count + threshold`
    pub fn reconstruct_limit(&self) -> usize {
        self.threshold + self.secret_count
    }

    /// Generate `share_count` shares for the `secrets` vector.
    ///
    /// The length of `secrets` must be `secret_count`.
    /// It is safe to pad with anything, including zeros.
    pub fn share<R>(&self, secrets: &[Field], rng: &mut R) -> Vec<Field>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        debug_assert_eq!(secrets.len(), self.secret_count);
        // sample polynomial
        let mut poly = self.sample_polynomial(secrets, rng);
        debug_assert_eq!(poly.len(), self.reconstruct_limit() + 1);
        // .. and extend it
        poly.extend(vec![
            Field::ZERO;
            self.share_count - self.reconstruct_limit()
        ]);
        debug_assert_eq!(poly.len(), self.share_count + 1);
        // evaluate polynomial to generate shares
        self.evaluate_polynomial(&mut poly);
        // .. but remove first element since it should not be used as a share (it's always zero)
        debug_assert_eq!(poly[0], Field::ZERO);
        poly.remove(0);
        // return
        debug_assert_eq!(poly.len(), self.share_count);
        poly
    }

    fn sample_polynomial<R>(&self, secrets: &[Field], rng: &mut R) -> Vec<Field>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        debug_assert_eq!(secrets.len(), self.secret_count);
        // sample randomness using secure randomness
        let randomness: Vec<Field> = (0..self.threshold).map(|_| Field::random(rng)).collect();
        // recover polynomial
        let coefficients = self.recover_polynomial(secrets, randomness);
        debug_assert_eq!(coefficients.len(), self.reconstruct_limit() + 1);
        coefficients
    }

    fn recover_polynomial(&self, secrets: &[Field], randomness: Vec<Field>) -> Vec<Field> {
        // fix the value corresponding to point 1 (zero)
        let mut values: Vec<Field> = vec![Field::ZERO];
        // let the subsequent values correspond to the secrets
        values.extend(secrets);
        // fill in with random values
        values.extend(randomness);
        // run backward FFT to recover polynomial in coefficient representation
        debug_assert_eq!(values.len(), self.reconstruct_limit() + 1);
        fft::fft2_inverse_in_place(&mut values, self.omega_secrets);
        values
    }

    fn evaluate_polynomial(&self, coefficients: &mut Vec<Field>) {
        debug_assert_eq!(coefficients.len(), self.share_count + 1);
        fft::fft3_in_place(coefficients, self.omega_shares)
    }

    /// Reconstruct the secrets from a large enough subset of the shares.
    ///
    /// `indices` are the ranks of the known shares as output by the `share` method,
    ///  while `values` are the actual values of these shares.
    /// Both must have the same number of elements, and at least `reconstruct_limit`.
    ///
    /// The resulting vector is of length `secret_count`.
    pub fn reconstruct(&self, indices: &[usize], shares: &[Field]) -> Vec<Field> {
        debug_assert!(shares.len() == indices.len());
        debug_assert!(shares.len() >= self.reconstruct_limit());
        let mut points: Vec<Field> = indices
            .iter()
            .map(|&x| self.omega_shares.pow(x as u128 + 1))
            .collect();
        let mut values = shares.to_vec();
        // insert missing value for point 1 (zero)
        points.insert(0, Field::ONE);
        values.insert(0, Field::ZERO);
        // interpolate using Newton's method
        // TODO optimise by using Newton-equally-space variant
        let poly = NewtonPolynomial::new(points.clone());
        poly.interpolate_in_place(&mut values);
        // let poly = NewtonPolynomial::init(&points, &values);
        // evaluate at omega_secrets points to recover secrets
        // TODO optimise to avoid re-computation of power

        (1..self.reconstruct_limit())
            .map(|e| self.omega_secrets.pow(e as u128))
            .map(|point| poly.eval(&values, point))
            .take(self.secret_count)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::prelude::*;
    use scuttlebutt::field::fft::FieldForFFT;

    type TestField = scuttlebutt::field::F2e19x3e26;

    #[test]
    fn test_share_reconstruct() {
        let mut rng = StdRng::from_entropy();

        let pss: PackedSecretSharingGenerator<TestField> = PackedSecretSharingGenerator {
            /// Maximum number of shares that can be known without exposing the secrets
            /// (privacy threshold).
            threshold: 15,
            /// Number of shares to split the secrets into.
            share_count: 80,
            /// Number of secrets to share together.
            secret_count: 48,

            // implementation configuration
            /// `m`-th principal root of unity in Zp, where `m = secret_count + threshold + 1`
            /// must be a power of 2.
            omega_secrets: <TestField as FieldForFFT<2>>::roots(6),
            /// `n`-th principal root of unity in Zp, where `n = share_count + 1` must be a power of 3.
            omega_shares: <TestField as FieldForFFT<3>>::roots(4),
        };

        let secrets = (0..pss.secret_count as u64)
            .map(|n| {
                (n as u128)
                    .try_into()
                    .unwrap_or_else(|_| panic!("Conversion failure"))
            })
            .collect::<Vec<_>>();
        let shares = &pss.share(&secrets, &mut rng)[0..pss.reconstruct_limit()];
        let reconstructed =
            pss.reconstruct(&(0..pss.reconstruct_limit()).collect::<Vec<_>>(), shares);

        assert_eq!(secrets, reconstructed);
    }
}
