// Copyright (c) 2016 rust-threshold-secret-sharing developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! Packed (or ramp) variant of Shamir secret sharing,
//! allowing efficient sharing of several secrets together.

use rand::{SeedableRng, Rng};

use crate::fft::{fft2_inverse, fft3};
use rand;

type Field = crate::f2_19x3_26::F;

/// Parameters for the packed variant of Shamir secret sharing,
/// specifying number of secrets shared together, total number of shares, and privacy threshold.
///
/// This scheme generalises
/// [Shamir's scheme](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing)
/// by simultaneously sharing several secrets, at the expense of leaving a gap
/// between the privacy threshold and the reconstruction limit.
///
/// The Fast Fourier Transform is used for efficiency reasons,
/// allowing most operations run to quasilinear time `O(n.log(n))` in `share_count`.
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
#[derive(Debug,Copy,Clone,PartialEq)]
pub struct PackedSecretSharing {

    // abstract properties

    /// Maximum number of shares that can be known without exposing the secrets
    /// (privacy threshold).
    pub threshold: usize,
    /// Number of shares to split the secrets into.
    pub share_count: usize,
    /// Number of secrets to share together.
    pub secret_count: usize,

    // implementation configuration

    /// `m`-th principal root of unity in Zp, where `m = secret_count + threshold + 1`
    /// must be a power of 2.
    pub omega_secrets: Field,
    /// `n`-th principal root of unity in Zp, where `n = share_count + 1` must be a power of 3.
    pub omega_shares: Field,
}

impl PackedSecretSharing {
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
    pub fn share(&self, secrets: &[Field]) -> Vec<Field> {
        assert_eq!(secrets.len(), self.secret_count);
        // sample polynomial
        let mut poly = self.sample_polynomial(secrets);
        assert_eq!(poly.len(), self.reconstruct_limit() + 1);
        // .. and extend it
        poly.extend(vec![Field::ZERO; self.share_count - self.reconstruct_limit()]);
        assert_eq!(poly.len(), self.share_count + 1);
        // evaluate polynomial to generate shares
        let mut shares = self.evaluate_polynomial(poly);
        // .. but remove first element since it should not be used as a share (it's always zero)
        assert_eq!(shares[0], Field::ZERO);
        shares.remove(0);
        // return
        assert_eq!(shares.len(), self.share_count);
        shares
    }

    fn sample_polynomial(&self, secrets: &[Field]) -> Vec<Field> {
        assert_eq!(secrets.len(), self.secret_count);
        // sample randomness using secure randomness
        let range = rand::distributions::Uniform::from(0 .. Field::MOD);
        let mut rng = rand::rngs::StdRng::from_entropy();
        let randomness: Vec<Field> =
            (0..self.threshold).map(|_| rng.sample(rand::distributions::Standard)).collect();
        // recover polynomial
        let coefficients = self.recover_polynomial(secrets, randomness);
        assert_eq!(coefficients.len(), self.reconstruct_limit() + 1);
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
        assert_eq!(values.len(), self.reconstruct_limit() + 1);
        let mut coefficients = values.clone();
        fft2_inverse(&mut coefficients, self.omega_secrets);
        coefficients
    }

    fn evaluate_polynomial(&self, coefficients: Vec<Field>) -> Vec<Field> {
        assert_eq!(coefficients.len(), self.share_count + 1);
        let mut points = coefficients.clone();
        fft3(&mut points, self.omega_shares);
        points
    }

    /// Reconstruct the secrets from a large enough subset of the shares.
    ///
    /// `indices` are the ranks of the known shares as output by the `share` method,
    ///  while `values` are the actual values of these shares.
    /// Both must have the same number of elements, and at least `reconstruct_limit`.
    ///
    /// The resulting vector is of length `secret_count`.
    pub fn reconstruct(&self, indices: &[usize], shares: &[Field]) -> Vec<Field> {
        assert!(shares.len() == indices.len());
        assert!(shares.len() >= self.reconstruct_limit());
        let mut points: Vec<Field> =
            indices.iter()
            .map(|&x| self.omega_shares.pow(x as u64 + 1))
            .collect();
        let mut values = shares.to_vec();
        // insert missing value for point 1 (zero)
        points.insert(0, Field::ONE);
        values.insert(0, Field::ZERO);
        // interpolate using Newton's method
        use crate::numtheory::{newton_interpolation_general, newton_evaluate};
        // TODO optimise by using Newton-equally-space variant
        let poly = newton_interpolation_general(&points, &values);
        // evaluate at omega_secrets points to recover secrets
        // TODO optimise to avoid re-computation of power
        let secrets = (1..self.reconstruct_limit())
            .map(|e| self.omega_secrets.pow(e as u64))
            .map(|point| newton_evaluate(&poly, point))
            .take(self.secret_count)
            .collect();
        secrets
    }
}


//#[cfg(test)]
//mod tests {
//
//    use super::*;
//    use numtheory::*;
//
//    #[test]
//    fn test_recover_polynomial() {
//        let ref pss = PSS_4_8_3;
//        let secrets = vec![1, 2, 3];
//        let randomness = vec![8, 8, 8, 8];  // use fixed randomness
//        let poly = pss.recover_polynomial(&secrets, randomness);
//        assert_eq!(
//            positivise(&poly, pss.prime),
//            positivise(&[113, -382, -172, 267, -325, 432, 388, -321], pss.prime)
//        );
//    }
//
//    #[test]
//    #[cfg_attr(rustfmt, rustfmt_skip)]
//    fn test_evaluate_polynomial() {
//        let ref pss = PSS_4_26_3;
//        let poly = vec![113,  51, 261, 267, 108, 432, 388, 112,   0,
//                          0,   0,   0,   0,   0,   0,   0,   0,   0,
//                          0,   0,   0,   0,   0,   0,   0,   0,   0];
//        let points = &pss.evaluate_polynomial(poly);
//        assert_eq!(
//            positivise(points, pss.prime),
//            vec![   0, 77, 230,  91, 286, 179, 337,  83, 212,
//                   88, 406, 58, 425, 345, 350, 336, 430, 404,
//                   51, 60, 305, 395,  84, 156, 160, 112, 422]
//        );
//    }
//
//    #[test]
//    #[cfg_attr(rustfmt, rustfmt_skip)]
//    fn test_share() {
//        let ref pss = PSS_4_26_3;
//
//        // do sharing
//        let secrets = vec![5, 6, 7];
//        let mut shares = pss.share(&secrets);
//
//        // manually recover secrets
//        use numtheory::{fft3_inverse, mod_evaluate_polynomial};
//        shares.insert(0, 0);
//        let poly = fft3_inverse(&shares, PSS_4_26_3.omega_shares, PSS_4_26_3.prime);
//        let recovered_secrets: Vec<i128> = (1..secrets.len() + 1)
//            .map(|i| {
//                mod_evaluate_polynomial(&poly,
//                                        mod_pow(PSS_4_26_3.omega_secrets,
//                                                i as u64,
//                                                PSS_4_26_3.prime),
//                                        PSS_4_26_3.prime)
//            })
//            .collect();
//
//        use numtheory::positivise;
//        assert_eq!(positivise(&recovered_secrets, pss.prime), secrets);
//    }
//
//    #[test]
//    fn test_large_share() {
//        let ref pss = PSS_155_19682_100;
//        let secrets = vec![5 ; pss.secret_count];
//        let shares = pss.share(&secrets);
//        assert_eq!(shares.len(), pss.share_count);
//    }
//
//    #[test]
//    fn test_share_reconstruct() {
//        let ref pss = PSS_4_26_3;
//        let secrets = vec![5, 6, 7];
//        let shares = pss.share(&secrets);
//
//        use numtheory::positivise;
//
//        // reconstruction must work for all shares
//        let indices: Vec<usize> = (0..shares.len()).collect();
//        let recovered_secrets = pss.reconstruct(&indices, &shares);
//        assert_eq!(positivise(&recovered_secrets, pss.prime), secrets);
//
//        // .. and for only sufficient shares
//        let indices: Vec<usize> = (0..pss.reconstruct_limit()).collect();
//        let recovered_secrets = pss.reconstruct(&indices, &shares[0..pss.reconstruct_limit()]);
//        print!("lenght is {:?}", indices.len());
//        assert_eq!(positivise(&recovered_secrets, pss.prime), secrets);
//    }
//
//    #[test]
//    fn test_share_additive_homomorphism() {
//        let ref pss = PSS_4_26_3;
//
//        let secrets_1 = vec![1, 2, 3];
//        let secrets_2 = vec![4, 5, 6];
//        let shares_1 = pss.share(&secrets_1);
//        let shares_2 = pss.share(&secrets_2);
//
//        // add shares pointwise
//        let shares_sum: Vec<i128> =
//            shares_1.iter().zip(shares_2).map(|(a, b)| (a + b) % pss.prime).collect();
//
//        // reconstruct sum, using same reconstruction limit
//        let reconstruct_limit = pss.reconstruct_limit();
//        let indices: Vec<usize> = (0..reconstruct_limit).collect();
//        let shares = &shares_sum[0..reconstruct_limit];
//        let recovered_secrets = pss.reconstruct(&indices, shares);
//
//        use numtheory::positivise;
//        assert_eq!(positivise(&recovered_secrets, pss.prime), vec![5, 7, 9]);
//    }
//
//    #[test]
//    fn test_share_multiplicative_homomorphism() {
//        let ref pss = PSS_4_26_3;
//
//        let secrets_1 = vec![1, 2, 3];
//        let secrets_2 = vec![4, 5, 6];
//        let shares_1 = pss.share(&secrets_1);
//        let shares_2 = pss.share(&secrets_2);
//
//        // multiply shares pointwise
//        let shares_product: Vec<i128> =
//            shares_1.iter().zip(shares_2).map(|(a, b)| (a * b) % pss.prime).collect();
//
//        // reconstruct product, using double reconstruction limit
//        let reconstruct_limit = pss.reconstruct_limit() * 2;
//        let indices: Vec<usize> = (0..reconstruct_limit).collect();
//        let shares = &shares_product[0..reconstruct_limit];
//        let recovered_secrets = pss.reconstruct(&indices, shares);
//
//        use numtheory::positivise;
//        assert_eq!(positivise(&recovered_secrets, pss.prime), vec![4, 10, 18]);
//    }
//
//}
