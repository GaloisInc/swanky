/*!
Implementation of algorithms related to consistency checks.
 *
*/
#![allow(clippy::needless_range_loop)]
use std::iter::repeat_n;

use crate::parameters::{
    B, FLambda, Params, RepetitionParam, SecurityParam, SecurityParamBytes, SecurityParamPadded,
};
use crate::vole::commit_reconstruct::l_hat;
use crate::vole::crypto_primitives::Chall1;
use hybrid_array::Array;
use hybrid_array::ArraySize;
use hybrid_array::typenum::{U2, Unsigned};
use itertools::izip;
use rayon::prelude::*;
use swanky_field::{FiniteField, FiniteRing};
use swanky_field_binary::{F2, F8b};
use swanky_serialization::CanonicalSerialize;

/// Packs bits of the input into `FLambda<P>`s. This does not do a field-to-field transformation;
/// it uses `FLambda<P>` as a representation of $`\lambda`$ bits, not as a polynomial!
fn pack_flambda<P: Params>(arrs: &[Array<F8b, RepetitionParam<P>>]) -> Vec<FLambda<P>> {
    arrs.into_par_iter()
        .map(|xi| {
            let xi_bytes: Array<_, SecurityParamBytes<P>> = Array::from_fn(|j| xi[j].to_bytes()[0]);
            FLambda::<P>::from_bytes(&xi_bytes)
        })
        .collect::<Result<_, _>>()
        .unwrap()
}

fn transpose_u8_matrix<Lin: ArraySize, Col: ArraySize>(
    input: &Array<Array<u8, Col>, Lin>,
    output: &mut Array<Array<u8, Lin>, Col>,
) {
    // This double loop is optimal that way to maximize the cache hit for reads.
    // The writes will be batched on write-back
    for i in 0..Lin::USIZE {
        for k in 0..Col::USIZE {
            output[k][i] = input[i][k];
        }
    }
}

/// Take a sequence of [`FLambda<P>`] values, interpret every value into its bit decomposition, that
/// becomes a n*128 boolean matrix where n is the length of the sequence. Apply `to_field_flambda`
/// (which includes padding) to every column in lock step and emit a sequence of
/// 128 [`FLambda<P>`] values.
#[inline(never)]
#[allow(dead_code)]
fn to_field_flambda_and_pad_lockstep<P: Params>(
    x: &[FLambda<P>],
) -> Vec<Array<FLambda<P>, SecurityParam<P>>> {
    let floor = x.len() / SecurityParam::<P>::USIZE;
    let how_many = floor
        + if (x.len() - (floor) * SecurityParam::<P>::USIZE) != 0 {
            1
        } else {
            0
        };
    let mut out = Vec::with_capacity(how_many);

    let mut b_lambda: Array<Array<u8, SecurityParamBytes<P>>, SecurityParam<P>> = Array::default();
    let mut b_lambda_alt: Array<Array<u8, SecurityParam<P>>, SecurityParamBytes<P>> = Array::default();
    let mut byte_num = 0;
    let mut bit_num: usize = 0;
    for b in x.iter() {
        let bs = b.bit_decomposition();
        let hot_bit = 1 << bit_num;
        let mut b_vec: Array<u8, SecurityParam<P>> = Array::default();
        for (p, b) in b_vec.iter_mut().zip(bs.iter()) {
            *p = u8::from(*b).wrapping_neg() & hot_bit;
        }

        let t = &mut b_lambda_alt[byte_num];
        for (e, b_lambda_alt_byte_num_i) in t.iter_mut().enumerate() {
            *b_lambda_alt_byte_num_i |= b_vec[e];
        }

        if bit_num == 7 {
            bit_num = 0; // restart at the beginning of byte
            if byte_num == SecurityParamBytes::<P>::USIZE - 1 {
                // NOTE: this loop is the bottle-neck in this function
                transpose_u8_matrix(&b_lambda_alt, &mut b_lambda);

                let arr: Array<FLambda<P>, SecurityParam<P>> =
                    b_lambda.map(|v| FLambda::<P>::from_bytes(&v).unwrap());
                out.push(arr);

                // reset
                byte_num = 0;
                // reset
                b_lambda = Array::default();
                b_lambda_alt = Array::default();
            } else {
                byte_num += 1;
            }
        } else {
            bit_num += 1;
        }
    }

    // Still have to push a last value if the previous loop terminated before processing `SecurityParam::<P>::USIZE` bits.
    if (bit_num != 0) | (byte_num != 0) {
        // transpose from b_lambda_alt to b_lambda
        transpose_u8_matrix(&b_lambda_alt, &mut b_lambda);

        let arr: Array<FLambda<P>, SecurityParam<P>> =
            b_lambda.map(|v| FLambda::<P>::from_bytes(&v).unwrap());
        out.push(arr);
    }

    assert_eq!(out.len(), how_many);
    out
}

struct ColumnEnumState<'a, P: Params> {
    x: &'a [Array<F8b, RepetitionParam<P>>],
    index: usize,
    length: usize,
}

impl<'a, P: Params> ColumnEnumState<'a, P> {
    #[allow(dead_code)]
    pub fn new(x: &'a [Array<F8b, RepetitionParam<P>>]) -> Self {
        Self {
            x,
            index: 0,
            length: x.len(),
        }
    }
}

impl<P: Params> Iterator for ColumnEnumState<'_, P> {
    type Item = Array<FLambda<P>, SecurityParam<P>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index == self.length {
            return None;
        }

        let mut b_lambda: Array<Array<u8, SecurityParamBytes<P>>, SecurityParam<P>> = Array::default();
        let mut b_lambda_alt: Array<Array<u8, SecurityParam<P>>, SecurityParamBytes<P>> =
            Array::default();
        let mut byte_num = 0;
        let mut bit_num: usize = 0;

        let mut out: Array<FLambda<P>, SecurityParam<P>> = Array::from_fn(|_| FLambda::<P>::ZERO);
        for _j in 0..SecurityParam::<P>::USIZE {
            let b = self.x[self.index].clone();
            // Advance immediately so the iterator consumes exactly the inputs it processes,
            // even when we early-break on a full 128-block.
            self.index += 1;

            let hot_bit = 1 << bit_num;
            let mut b_vec: Array<u8, SecurityParam<P>> = Array::default();
            let mut col = 0;
            for b8 in b {
                let bs = b8.bit_decomposition();
                for b1 in bs.iter() {
                    b_vec[col] = u8::from(*b1).wrapping_neg() & hot_bit;
                    col += 1;
                }
            }

            let t = &mut b_lambda_alt[byte_num];
            for (e, b_lambda_alt_byte_num_i) in t.iter_mut().enumerate() {
                *b_lambda_alt_byte_num_i |= b_vec[e];
            }

            if bit_num == 7 {
                bit_num = 0; // restart at the beginning of byte
                if byte_num == SecurityParamBytes::<P>::USIZE - 1 {
                    // This double loop is optimal that way to maximize the cache hit for reads.
                    // The writes will be batched on write-back
                    // NOTE: this loop is the bottle-neck in this function
                    transpose_u8_matrix(&b_lambda_alt, &mut b_lambda);

                    let arr: Array<FLambda<P>, SecurityParam<P>> =
                        b_lambda.map(|v| FLambda::<P>::from_bytes(&v).unwrap());
                    out = arr;
                    break;
                } else {
                    byte_num += 1;
                }
            } else {
                bit_num += 1;
            }

            if self.length == self.index {
                // Still have to push a last value if the previous loop terminated before processing `SECURITY_PARAMETER` bits.
                if (bit_num != 0) | (byte_num != 0) {
                    // transpose from b_lambda_alt to b_lambda
                    transpose_u8_matrix(&b_lambda_alt, &mut b_lambda);

                    let arr: Array<FLambda<P>, SecurityParam<P>> =
                        b_lambda.map(|v| FLambda::<P>::from_bytes(&v).unwrap());
                    out = arr;
                    break;
                }
            }
        }

        Some(out)
    }
}

/// Hash as produced by [`vole_hash`].
#[derive(Clone, Debug, Default)]
#[repr(transparent)]
pub(crate) struct HashConsistency<P: Params>(Array<F2, SecurityParamPadded<P>>);

impl<P: Params> IntoIterator for &HashConsistency<P> {
    type Item = F2;
    type IntoIter = <Array<F2, SecurityParamPadded<P>> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.clone().into_iter()
    }
}

impl<P: Params> HashConsistency<P> {
    pub(crate) fn len(&self) -> usize {
        SecurityParamPadded::<P>::USIZE
    }

    /// Convert a consistency hash to a vector of bytes
    ///
    /// packing the `F2` values in `u8`.
    #[cfg(test)]
    pub(crate) fn pack_to_bytes(&self) -> Vec<u8> {
        let mut out = vec![];
        for chunk in self.0.chunks(8) {
            let mut byte = 0u8;
            for (i, &b) in chunk.iter().enumerate() {
                if b == F2::ONE {
                    byte |= 1 << i;
                }
            }
            out.push(byte);
        }
        out
    }

    /// Convert a [`HashConsistency`] to a list of bytes, without packing.
    pub(crate) fn as_bytes(&self) -> Array<u8, SecurityParamPadded<P>> {
        self.0.clone().map(|f2| f2.to_bytes()[0])
    }
}

/// Precomputation for the VOLE-Hash.
///
/// Drawn from FAEST spec v1.1, Fig 4.4, with some modifications (noted inline).
pub(crate) struct VoleHasher<P: Params> {
    r0: FLambda<P>,
    r1: FLambda<P>,
    r2: FLambda<P>,
    r3: FLambda<P>,
    s0: FLambda<P>,
    s1: FLambda<P>,
    ell: usize,
    ell_prime: usize,
}

impl<P: Params> VoleHasher<P> {
    pub(crate) fn from_seed(seed: Chall1<P>, ell: usize) -> Self {
        // Lines 2 - 5. The seed is six `FLambda<P>`s worth of bytes, laid out as
        // `r0 || r1 || r2 || r3 || s || t`.
        //
        // Note: In the spec, `t` is 64 bits; here it's called `s1` and is a full field element,
        // which is why `CHALL1_LENGTH` is 6 * lambda bits rather than the spec's 5 * lambda + 64.
        let field_at = |i: usize| {
            // These panics/unwraps are unreachable: `CHALL1_LENGTH` is exactly six times the byte
            // length of an `FLambda<P>`, and deserializing a binary field element cannot fail.
            let bytes: Array<u8, SecurityParamBytes<P>> = Array::try_from(
                &seed[i * SecurityParamBytes::<P>::USIZE..(i + 1) * SecurityParamBytes::<P>::USIZE],
            )
            .unwrap();
            FLambda::<P>::from_bytes(&bytes).unwrap()
        };
        // Note: `s0` and `s1` are called `s` and `t` in the spec.
        let [r0, r1, r2, r3, s0, s1] = core::array::from_fn(field_at);

        // Line 6.
        let lambda = SecurityParam::<P>::USIZE;
        let ell_prime = lambda * (ell + lambda).div_ceil(lambda);

        Self {
            r0,
            r1,
            r2,
            r3,

            s0,
            s1,

            ell,
            ell_prime,
        }
    }

    pub(crate) fn hash(&self, x: &[F2]) -> HashConsistency<P> {
        assert_eq!(x.len(), l_hat::<P>(self.ell));
        let (x0, x1) = x.split_at(self.ell + SecurityParam::<P>::USIZE);

        // Line 7. This pads and converts to a field -- it is called `y_hat` in the spec.
        let x0_vec = self.to_field_lambda(x0);

        // Line 10 and 11.
        // This differs from the FAEST spec where the powers are in reverse order; this is also valid!
        // This differs from the FAEST spec because it uses a different field for `s1`.
        let mut h0 = FLambda::<P>::ZERO;
        let mut h1 = FLambda::<P>::ZERO;
        let mut s0_powers = self.s0;
        let mut s1_powers = self.s1;
        for x0_i in x0_vec.iter() {
            h0 += s0_powers * *x0_i;
            h1 += s1_powers * *x0_i;
            s0_powers *= self.s0;
            s1_powers *= self.s1;
        }

        // Line 13.
        let h2 = self.r0 * h0 + self.r1 * h1;
        let h3 = self.r2 * h0 + self.r3 * h1;

        // Line 14 (call ToBits).
        let h2_bits = h2.bit_decomposition();
        let h3_bits = h3.bit_decomposition();

        // Line 14 (truncate and append).
        let all_bits: Array<bool, SecurityParamPadded<P>> = Array::try_from_iter(
            h2_bits
                .iter()
                .copied()
                .chain(h3_bits.iter().copied().take(B::USIZE)),
        )
        .expect("wrong number of h2 and h3 bits");

        // Line 14 (XOR with x1). This unwrap is safe because the two inputs must be the expected length.
        let out: Array<F2, SecurityParamPadded<P>> = Array::try_from_iter(
            izip!(all_bits, x1)
                .map(|(b1, b2)| F2::from(b1) + b2)
                .collect::<Vec<_>>(),
        )
        .expect("wrong number of x1, x2, and x3 bits");

        HashConsistency(out)
    }

    // Padding plus ToField (Fig 3.1) from FAEST, where `k` is fixed to the security parameter (128).
    fn to_field_lambda(&self, x: &[F2]) -> Vec<FLambda<P>> {
        let padding = repeat_n(
            F2::ZERO,
            self.ell_prime - (self.ell + SecurityParam::<P>::USIZE),
        )
        .collect::<Vec<_>>();

        let x_padded = [x, &padding].concat();

        // We should never hit this because we just padded.
        if x_padded.len() % SecurityParam::<P>::USIZE != 0 {
            panic!(
                "Expected a multiple of {}, but got {}",
                SecurityParam::<P>::USIZE,
                x_padded.len()
            );
        }

        x_padded
            .chunks(SecurityParam::<P>::USIZE)
            .map(|xi| {
                assert_eq!(SecurityParam::<P>::USIZE, xi.len());
                P::f2_form_superfield(xi.try_into().unwrap())
            })
            .collect()
    }

    /// Function doing linear hashing of the column of bits in lock-step.
    ///
    /// There are `RepetitionParam` tracks where one group of bits is provided as a [`FLambda<P>`] value.
    pub(crate) fn hash_matrix(
        &self,
        xs: &[Array<F8b, RepetitionParam<P>>],
    ) -> Array<HashConsistency<P>, SecurityParam<P>> {
        assert_eq!(xs.len(), l_hat::<P>(self.ell));
        let (x0, x1) = xs.split_at(self.ell + SecurityParam::<P>::USIZE);

        // There are different **options** to hashing the elements. The most runtime effective option is option #2, and the
        // most memory efficient option is option #3 because it is streaming the columns.

        // OPTION #1: naive
        // This option simply create the enumerator for the columns transposed of the field values and hashes with powers the columns sequentially.
        /*
        let packed_x0 = pack_flambda(x0);
        let x0_vec = ColumnEnumState::new(&packed_x0);
        let mut w0 = s0;
        let mut w1 = s1;
        let mut h0 = [FLambda::<P>::ZERO; SECURITY_PARAM];
        let mut h1 = [FLambda::<P>::ZERO; SECURITY_PARAM];

        for x0 in x0_vec {
            for (j, x_j) in x0.iter().enumerate() {
                h0[j] += w0 * x_j;
                h1[j] += w1 * x_j;
            }
            w0 *= s0;
            w1 *= s1;
        }
        */
        /* END OPTION #1 */

        // OPTION #2: par_iter()
        // This option transposes the field values into a vector before hashing with powers the columns in parallel using rayon.
        // One downside of this option is that it needs the vector of values to be explicitly and it cannot just use the enumerator.

        /*
        let x0_vec = to_field_flambda_and_pad_lockstep(&pack_flambda(x0));
        fn powers(base: FLambda<P>, n: usize) -> Vec<FLambda<P>> {
            let mut out = Vec::with_capacity(n);
            let mut p = base;
            for _ in 0..n {
                out.push(p);
                p *= base;
            }
            out
        }
        fn accumulate_cols(
            x0_vec: &[[FLambda<P>; SECURITY_PARAM]],
            s0: FLambda<P>,
            s1: FLambda<P>,
        ) -> ([FLambda<P>; SECURITY_PARAM], [FLambda<P>; SECURITY_PARAM]) {
            let how_many = x0_vec.len();
            let w0 = powers(s0, how_many);
            let w1 = powers(s1, how_many);

            let mut h0 = [FLambda::<P>::ZERO; SECURITY_PARAM];
            let mut h1 = [FLambda::<P>::ZERO; SECURITY_PARAM];

            // Parallelize over (h0[j], h1[j]) pairs; each thread owns disjoint &mut slots.
            h0[..]
                .par_iter_mut()
                .zip(h1[..].par_iter_mut())
                .enumerate()
                .for_each(|(j, (h0j, h1j))| {
                    let mut acc0 = FLambda::<P>::ZERO;
                    let mut acc1 = FLambda::<P>::ZERO;
                    for i in 0..how_many {
                        let x = x0_vec[i][j]; // strided access across rows
                        acc0 += w0[i] * x;
                        acc1 += w1[i] * x;
                    }
                    *h0j = acc0;
                    *h1j = acc1;
                });

            (h0, h1)
        }

        let (h0, h1) = accumulate_cols(&x0_vec, s0, s1);
        */
        // END OPTION #2

        // OPTION #3: parallel producer/consumer
        // This option creates an enumerator for the column of the transposed field values and then splits the columns in
        // N blocks and spawn threads to do the hashing with powers.

        // use std::sync::mpsc::Sender; // unbounded buffers for messages
        use std::sync::mpsc::{SyncSender, sync_channel}; // SyncChannel uses fixed size buffers, which is useful to control memory.
        use std::{sync::mpsc::channel, thread};

        let x0_vec = ColumnEnumState::<P>::new(x0);

        type N = U2; // number of threads

        let mut senders: Vec<SyncSender<Vec<FLambda<P>>>> = Vec::with_capacity(N::USIZE);
        let mut receivs = Vec::with_capacity(N::USIZE);
        let (result_sender, result_receiver) = channel();
        for _ in 0..N::USIZE {
            let (tx, rx) = sync_channel(100);
            senders.push(tx);
            receivs.push(rx);
        }
        let mut handles = Vec::new();

        let s0 = self.s0;
        let s1 = self.s1;
        for (num, recv) in receivs.into_iter().enumerate() {
            let send_i = result_sender.clone();
            let handle = thread::spawn(move || {
                let i = num;
                let mut w0 = s0;
                let mut w1 = s1;
                let mut h0 = vec![FLambda::<P>::ZERO; SecurityParam::<P>::USIZE / N::USIZE];
                let mut h1 = vec![FLambda::<P>::ZERO; SecurityParam::<P>::USIZE / N::USIZE];
                for slice in recv.iter() {
                    for (j, v) in slice.iter().enumerate() {
                        h0[j] += *v * w0;
                        h1[j] += *v * w1;
                    }

                    w0 *= s0;
                    w1 *= s1;
                }
                send_i.send((i, h0, h1)).unwrap();
            });
            handles.push(handle);
        }

        let stride = SecurityParam::<P>::USIZE / N::USIZE;
        for arr in x0_vec {
            for (i, _) in (0..N::USIZE).enumerate() {
                senders[i]
                    .send(arr[i * stride..(i + 1) * stride].to_vec())
                    .unwrap();
            }
        }
        drop(senders);

        let mut h0 = Array::<_, SecurityParam<P>>::from_fn(|_| FLambda::<P>::ZERO);
        let mut h1 = Array::<_, SecurityParam<P>>::from_fn(|_| FLambda::<P>::ZERO);
        for _ in 0..N::USIZE {
            let (i, h0_i, h1_i) = result_receiver.recv().unwrap();
            h0[i * stride..(i + 1) * stride].copy_from_slice(&h0_i);
            h1[i * stride..(i + 1) * stride].copy_from_slice(&h1_i);
        }

        // END OPTION #3

        let mut h2 = Array::<_, SecurityParam<P>>::from_fn(|_| FLambda::<P>::ZERO);
        let mut h3 = Array::<_, SecurityParam<P>>::from_fn(|_| FLambda::<P>::ZERO);
        for j in 0..SecurityParam::<P>::USIZE {
            h2[j] = self.r0 * h0[j] + self.r1 * h1[j];
            h3[j] = self.r2 * h0[j] + self.r3 * h1[j];
        }

        let mut out: Array<HashConsistency<P>, SecurityParam<P>> = Default::default();

        let x1_packed = pack_flambda::<P>(x1);

        let mut x1_bits: Array<Array<bool, SecurityParamPadded<P>>, SecurityParam<P>> =
            Default::default();
        for col in 0..SecurityParamPadded::<P>::USIZE {
            let decomp = x1_packed[col].bit_decomposition();
            for j in 0..SecurityParam::<P>::USIZE {
                x1_bits[j][col] = decomp[j];
            }
        }
        for j in 0..SecurityParam::<P>::USIZE {
            // Line 14 (call ToBits).
            let h2_bits = h2[j].bit_decomposition();
            let h3_bits = h3[j].bit_decomposition();

            // Line 14 (truncate and append).
            let all_bits: Array<bool, SecurityParamPadded<P>> = Array::try_from_iter(
                h2_bits
                    .iter()
                    .copied()
                    .chain(h3_bits.iter().copied().take(B::USIZE)),
            )
            .unwrap();

            // Line 14 (XOR with x1).
            let single_out = izip!(all_bits, x1_bits[j].clone())
                .map(|(b1, b2)| F2::from(b1) + F2::from(b2))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();
            out[j] = HashConsistency(single_out);
        }
        out
    }
}

#[cfg(test)]
mod test {
    use crate::parameters::{Binary128Bit, Binary256Bit, Params};

    use std::iter::repeat_with;
    use std::iter::zip;

    use crate::parameters::{B, FLambda, SecurityParam, SecurityParamBytes};
    use crate::vole::commit_reconstruct::l_hat;
    use crate::vole::consistency_check::VoleHasher;
    use crate::vole::crypto_primitives::Chall1;
    use hybrid_array::Array;
    use hybrid_array::typenum::Unsigned;
    use rand::rng;
    use swanky_field::FiniteRing;
    use swanky_field_binary::F2;
    use swanky_serialization::CanonicalSerialize;

    fn test_padding_of_to_field_flambda_and_pad<P: Params>() {
        // Called with an `ell`-length input, `to_field_lambda` pads up to a multiple of lambda and
        // emits one field element per lambda-bit chunk, so there are `ceil(ell / lambda)` of them.
        for ell in [
            1000,
            SecurityParam::<P>::USIZE,
            SecurityParam::<P>::USIZE + 1,
        ] {
            let v = vec![F2::ZERO; ell];
            let hasher = VoleHasher::<P>::from_seed(Chall1::<P>::default(), ell);
            let t = hasher.to_field_lambda(&v);
            assert_eq!(
                t.len(),
                ell.div_ceil(SecurityParam::<P>::USIZE),
                "ell = {ell}"
            );
        }

        // Bit `i` of the input becomes the coefficient of `x^(i mod lambda)` in chunk
        // `i / lambda`, so bit 0 gives 1 in the first chunk and bit lambda+1 gives x in the second.
        let mut v = vec![F2::ZERO; SecurityParam::<P>::USIZE + 2];
        v[0] = F2::ONE;
        v[SecurityParam::<P>::USIZE + 1] = F2::ONE;
        let hasher =
            VoleHasher::<P>::from_seed(Chall1::<P>::default(), SecurityParam::<P>::USIZE + 2);
        let t = hasher.to_field_lambda(&v);
        let mut res1 = Array::<u8, SecurityParamBytes<P>>::default();
        res1[0] = 1u8;
        assert_eq!(t[0], FLambda::<P>::from_bytes(&res1).unwrap());
        let mut res2 = Array::<u8, SecurityParamBytes<P>>::default();
        res2[0] = 2u8;
        assert_eq!(t[1], FLambda::<P>::from_bytes(&res2).unwrap());
        // TODO: Could generate random values and decompose the generated FLambda<P> and check the equivalence
    }

    // Test that [`vole_hash`] returns 0 when all the inputs are 0.
    fn test_vole_hash_zero<P: Params>() {
        let seeds = Chall1::<P>::default();

        const HOW_MANY: usize = 1000;
        let x = vec![F2::ZERO; HOW_MANY + 2 * SecurityParam::<P>::USIZE + B::USIZE];

        let hasher = VoleHasher::<P>::from_seed(seeds, HOW_MANY);
        let v = hasher.hash(&x);

        for b in v.0.iter() {
            assert_eq!(*b, F2::ZERO);
        }
    }

    // Test the xor part at the end of [`vole_hash`]
    fn test_vole_hash_last_xor<P: Params>() {
        let seeds = Chall1::<P>::default();

        const HOW_MANY: usize = 1000;
        let mut x = vec![F2::ZERO; HOW_MANY + 2 * SecurityParam::<P>::USIZE + B::USIZE];
        let pos = 13;
        x[HOW_MANY + SecurityParam::<P>::USIZE + pos] = F2::ONE;

        let hasher = VoleHasher::<P>::from_seed(seeds, HOW_MANY);
        let v = hasher.hash(&x);

        for (i, b) in v.0.iter().enumerate() {
            if i == pos {
                assert_eq!(*b, F2::ONE);
            } else {
                assert_eq!(*b, F2::ZERO);
            }
        }
    }

    // Test the xor part at the end of [`vole_hash`]
    fn test_vole_hash_is_linear<P: Params>() {
        let rng = &mut rng();

        let seeds = Chall1::<P>::from_fn(|_| 1u8);

        const HOW_MANY: usize = 1000;
        let x0: Vec<F2> = repeat_with(|| F2::random(rng))
            .take(l_hat::<P>(HOW_MANY))
            .collect();
        let x1: Vec<F2> = repeat_with(|| F2::random(rng))
            .take(l_hat::<P>(HOW_MANY))
            .collect();
        let x2: Vec<F2> = zip(&x0, &x1).map(|(a, b)| a + b).collect();

        let hasher = VoleHasher::<P>::from_seed(seeds, HOW_MANY);
        let v0 = hasher.hash(&x0);
        let v1 = hasher.hash(&x1);
        let v2 = hasher.hash(&x2);

        for ((a, b), c) in v0.0.iter().zip(v1.0.iter()).zip(v2.0.iter()) {
            assert_eq!(*a + *b, *c);
        }
    }

    fn test_transpose_lockstep_equals_enumerator<P: Params>() {
        use super::{ColumnEnumState, pack_flambda, to_field_flambda_and_pad_lockstep};
        use swanky_field_binary::F8b;

        fn f8(x: u8) -> F8b {
            F8b::from_bytes(&[x].into()).unwrap()
        }

        // Try different lengths
        let lengths = [
            0usize, 1, 15, 16, 17, 127, 128, 129, 200, 255, 256, 511, 512, 513,
        ];

        for &len in &lengths {
            // Build len rows of 16 bytes each to pack into Flambda values
            let mut rows: Vec<Array<F8b, crate::parameters::RepetitionParam<P>>> =
                Vec::with_capacity(len);
            for i in 0..len {
                let mut row = Array::from_fn(|_| F8b::ZERO);
                for (j, cell) in row.iter_mut().enumerate() {
                    // Deterministic, non-trivial pattern
                    let byte = (i as u8)
                        .wrapping_mul(31)
                        .wrapping_add(j as u8)
                        .wrapping_mul(17);
                    *cell = f8(byte);
                }
                rows.push(row);
            }

            let packed = pack_flambda::<P>(&rows);

            let via_lockstep = to_field_flambda_and_pad_lockstep::<P>(&packed);
            let via_enum: Vec<Array<FLambda<P>, SecurityParam<P>>> =
                ColumnEnumState::<P>::new(&rows).collect();

            assert_eq!(
                via_lockstep.len(),
                via_enum.len(),
                "mismatched chunk count for len={}",
                len
            );
            for (i, (a, b)) in via_lockstep.iter().zip(via_enum.iter()).enumerate() {
                for j in 0..SecurityParam::<P>::USIZE {
                    assert_eq!(
                        a[j], b[j],
                        "mismatch at len={}, chunk={}, col={} ",
                        len, i, j
                    );
                }
            }
        }
    }

    macro_rules! make_tests {
        (mod $name:ident { params = $params:ty $(,)? }) => {
            mod $name {
                use super::*;
                #[test]
                fn test_padding_of_to_field_flambda_and_pad() {
                    super::test_padding_of_to_field_flambda_and_pad::<$params>();
                }
                #[test]
                fn test_vole_hash_zero() {
                    super::test_vole_hash_zero::<$params>();
                }
                #[test]
                fn test_vole_hash_last_xor() {
                    super::test_vole_hash_last_xor::<$params>();
                }
                #[test]
                fn test_vole_hash_is_linear() {
                    super::test_vole_hash_is_linear::<$params>();
                }
                #[test]
                fn test_transpose_lockstep_equals_enumerator() {
                    super::test_transpose_lockstep_equals_enumerator::<$params>();
                }
            }
        };
    }

    make_tests! { mod binary_128_bit { params = Binary128Bit } }
    make_tests! { mod binary_256_bit { params = Binary256Bit } }
}
