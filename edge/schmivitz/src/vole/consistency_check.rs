/*!
Implementation of algorithms related to consistency checks.
 *
*/
#![allow(clippy::needless_range_loop)]
use std::iter::repeat_n;

use crate::parameters::{FLambda, REPETITION_PARAM, SECURITY_PARAM};
use crate::vole::commit_reconstruct::B;
use crate::vole::crypto_primitives::CHALL1_LENGTH;
use generic_array::sequence::Concat;
use generic_array::{GenericArray, sequence::Split, typenum::U16};
use itertools::izip;
use rayon::prelude::*;
use swanky_field::{FiniteField, FiniteRing, IsSubFieldOf};
use swanky_field_binary::{F2, F8b};
use swanky_serialization::CanonicalSerialize;

/// Packs bits of the input into `FLambda`s. This does not do a field-to-field transformation;
/// it uses `FLambda` as a representation of $`\lambda`$ bits, not as a polynomial!
fn pack_flambda(arrs: &[[F8b; REPETITION_PARAM]]) -> Vec<FLambda> {
    arrs.into_par_iter()
        .map(|xi| {
            let xi_bytes = xi.map(|xij| xij.to_bytes()[0]);
            FLambda::from_bytes(&xi_bytes.into())
        })
        .collect::<Result<_, _>>()
        .unwrap()
}

fn transpose_u8_matrix<const LIN: usize, const COL: usize>(
    input: &[[u8; COL]; LIN],
    output: &mut [[u8; LIN]; COL],
) {
    // This double loop is optimal that way to maximize the cache hit for reads.
    // The writes will be batched on write-back
    for i in 0..LIN {
        for k in 0..COL {
            output[k][i] = input[i][k];
        }
    }
}

/// Take a sequence of [`FLambda`] values, interpret every value into its bit decomposition, that
/// becomes a n*128 boolean matrix where n is the length of the sequence. Apply `to_field_flambda`
/// (which includes padding) to every column in lock step and emit a sequence of
/// 128 [`FLambda`] values.
#[inline(never)]
#[allow(dead_code)]
fn to_field_flambda_and_pad_lockstep(x: &[FLambda]) -> Vec<[FLambda; SECURITY_PARAM]> {
    let floor = x.len() / SECURITY_PARAM;
    let how_many = floor
        + if (x.len() - (floor) * SECURITY_PARAM) != 0 {
            1
        } else {
            0
        };
    let mut out = Vec::with_capacity(how_many);

    let mut b_128 = [[0u8; SECURITY_PARAM / 8]; SECURITY_PARAM];
    let mut b_128_alt = [[0u8; SECURITY_PARAM]; SECURITY_PARAM / 8];
    let mut byte_num = 0;
    let mut bit_num: usize = 0;
    for b in x.iter() {
        let bs = b.bit_decomposition();
        let hot_bit = 1 << bit_num;
        let mut b_vec = [0u8; SECURITY_PARAM];
        for (p, b) in b_vec.iter_mut().zip(bs.iter()) {
            *p = u8::from(*b).wrapping_neg() & hot_bit;
        }

        let t = &mut b_128_alt[byte_num];
        for (e, b_128_alt_byte_num_i) in t.iter_mut().enumerate() {
            *b_128_alt_byte_num_i |= b_vec[e];
        }

        if bit_num == 7 {
            bit_num = 0; // restart at the beginning of byte
            if byte_num == (SECURITY_PARAM / 8) - 1 {
                // NOTE: this loop is the bottle-neck in this function
                transpose_u8_matrix(&b_128_alt, &mut b_128);

                let arr: [FLambda; SECURITY_PARAM] =
                    b_128.map(|v| FLambda::from_bytes(&v.into()).unwrap());
                out.push(arr);

                // reset
                byte_num = 0;
                // reset
                b_128 = [[0u8; SECURITY_PARAM / 8]; SECURITY_PARAM];
                b_128_alt = [[0u8; SECURITY_PARAM]; SECURITY_PARAM / 8];
            } else {
                byte_num += 1;
            }
        } else {
            bit_num += 1;
        }
    }

    // Still have to push a last value if the previous loop terminated before processing `SECURITY_PARAMETER` bits.
    if (bit_num != 0) | (byte_num != 0) {
        // transpose from b_128_alt to b_128
        transpose_u8_matrix(&b_128_alt, &mut b_128);

        let arr: [FLambda; SECURITY_PARAM] = b_128.map(|v| FLambda::from_bytes(&v.into()).unwrap());
        out.push(arr);
    }

    assert_eq!(out.len(), how_many);
    out
}

struct ColumnEnumState<'a> {
    x: &'a [[F8b; REPETITION_PARAM]],
    index: usize,
    length: usize,
}

impl<'a> ColumnEnumState<'a> {
    #[allow(dead_code)]
    pub fn new(x: &'a [[F8b; REPETITION_PARAM]]) -> Self {
        Self {
            x,
            index: 0,
            length: x.len(),
        }
    }
}

impl<'a> Iterator for ColumnEnumState<'a> {
    type Item = [FLambda; SECURITY_PARAM];

    fn next(&mut self) -> Option<Self::Item> {
        if self.index == self.length {
            return None;
        }

        let mut b_128 = [[0u8; SECURITY_PARAM / 8]; SECURITY_PARAM];
        let mut b_128_alt = [[0u8; SECURITY_PARAM]; SECURITY_PARAM / 8];
        let mut byte_num = 0;
        let mut bit_num: usize = 0;

        let mut out = [FLambda::ZERO; SECURITY_PARAM];
        for _j in 0..SECURITY_PARAM {
            let b = self.x[self.index];
            // Advance immediately so the iterator consumes exactly the inputs it processes,
            // even when we early-break on a full 128-block.
            self.index += 1;

            let hot_bit = 1 << bit_num;
            let mut b_vec = [0u8; SECURITY_PARAM];
            let mut col = 0;
            for b8 in b {
                let bs = b8.bit_decomposition();
                for b1 in bs.iter() {
                    b_vec[col] = u8::from(*b1).wrapping_neg() & hot_bit;
                    col += 1;
                }
            }

            let t = &mut b_128_alt[byte_num];
            for (e, b_128_alt_byte_num_i) in t.iter_mut().enumerate() {
                *b_128_alt_byte_num_i |= b_vec[e];
            }

            if bit_num == 7 {
                bit_num = 0; // restart at the beginning of byte
                if byte_num == (SECURITY_PARAM / 8) - 1 {
                    // This double loop is optimal that way to maximize the cache hit for reads.
                    // The writes will be batched on write-back
                    // NOTE: this loop is the bottle-neck in this function
                    transpose_u8_matrix(&b_128_alt, &mut b_128);

                    let arr: [FLambda; SECURITY_PARAM] =
                        b_128.map(|v| FLambda::from_bytes(&v.into()).unwrap());
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
                    // transpose from b_128_alt to b_128
                    transpose_u8_matrix(&b_128_alt, &mut b_128);

                    let arr: [FLambda; SECURITY_PARAM] =
                        b_128.map(|v| FLambda::from_bytes(&v.into()).unwrap());
                    out = arr;
                    break;
                }
            }
        }

        Some(out)
    }
}

/// Hash as produced by [`vole_hash`].
#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub(crate) struct HashConsistency([F2; SECURITY_PARAM + B]);

impl Default for HashConsistency {
    fn default() -> Self {
        Self([Default::default(); SECURITY_PARAM + B])
    }
}

impl IntoIterator for &HashConsistency {
    type Item = F2;
    type IntoIter = <[F2; SECURITY_PARAM + B] as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl HashConsistency {
    pub(crate) fn len(&self) -> usize {
        SECURITY_PARAM + B
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
    pub(crate) fn as_bytes(&self) -> [u8; SECURITY_PARAM + B] {
        self.0.map(|f2| f2.to_bytes()[0])
    }
}

/// Precomputation for the VOLE-Hash.
///
/// Drawn from FAEST spec v1.1, Fig 4.4, with some modifications (noted inline).
pub(crate) struct VoleHasher {
    r0: FLambda,
    r1: FLambda,
    r2: FLambda,
    r3: FLambda,
    s0: FLambda,
    s1: FLambda,
    ell: usize,
    ell_prime: usize,
}

impl VoleHasher {
    pub(crate) fn from_seed(seed: [u8; CHALL1_LENGTH], ell: usize) -> Self {
        // Lines 2 - 5. The seed is six `FLambda`s worth of bytes, laid out as
        // `r0 || r1 || r2 || r3 || s || t`.
        //
        // Note: In the spec, `t` is 64 bits; here it's called `s1` and is a full field element,
        // which is why `CHALL1_LENGTH` is 6 * lambda bits rather than the spec's 5 * lambda + 64.
        let field_at = |i: usize| {
            let bytes = &seed[i * (SECURITY_PARAM / 8)..(i + 1) * (SECURITY_PARAM / 8)];
            // These panics/unwraps are unreachable: `CHALL1_LENGTH` is exactly six times the byte
            // length of an `FLambda`, and deserializing a binary field element cannot fail.
            FLambda::from_bytes(GenericArray::from_slice(bytes)).unwrap()
        };
        // Note: `s0` and `s1` are called `s` and `t` in the spec.
        let [r0, r1, r2, r3, s0, s1] = core::array::from_fn(field_at);

        // Line 6.
        let ell_prime = SECURITY_PARAM * (ell + SECURITY_PARAM).div_ceil(SECURITY_PARAM);

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

    pub(crate) fn hash(&self, x: &[F2]) -> HashConsistency {
        assert_eq!(x.len(), self.ell + 2 * SECURITY_PARAM + B);
        let (x0, x1) = x.split_at(self.ell + SECURITY_PARAM);

        // Line 7. This pads and converts to a field -- it is called `y_hat` in the spec.
        let x0_vec = self.to_field_lambda(x0);

        // Line 10 and 11.
        // This differs from the FAEST spec where the powers are in reverse order; this is also valid!
        // This differs from the FAEST spec because it uses a different field for `s1`.
        let mut h0 = FLambda::ZERO;
        let mut h1 = FLambda::ZERO;
        let mut s0_powers = self.s0;
        let mut s1_powers = self.s1;
        for x0_i in x0_vec.iter() {
            h0 += s0_powers * x0_i;
            h1 += s1_powers * x0_i;
            s0_powers *= self.s0;
            s1_powers *= self.s1;
        }

        // Line 13.
        let h2 = self.r0 * h0 + self.r1 * h1;
        let h3 = self.r2 * h0 + self.r3 * h1;

        // Line 14 (call ToBits and truncate).
        let h2_bits = h2.bit_decomposition();
        let (h3_bits, _unused): (GenericArray<bool, U16>, _) = h3.bit_decomposition().split();

        // Line 14 (append).
        let all_bits: [bool; SECURITY_PARAM + B] = h2_bits.concat(h3_bits).into();

        // Line 14 (XOR with x1). This unwrap is safe because the two inputs must be the expected length.
        let out: [F2; SECURITY_PARAM + B] = izip!(all_bits, x1)
            .map(|(b1, b2)| F2::from(b1) + b2)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        HashConsistency(out)
    }

    // Padding plus ToField (Fig 3.1) from FAEST, where `k` is fixed to the security parameter (128).
    fn to_field_lambda(&self, x: &[F2]) -> Vec<FLambda> {
        let padding =
            repeat_n(F2::ZERO, self.ell_prime - (self.ell + SECURITY_PARAM)).collect::<Vec<_>>();

        let x_padded = [x, &padding].concat();

        // We should never hit this because we just padded.
        if x_padded.len() % SECURITY_PARAM != 0 {
            panic!(
                "Expected a multiple of {}, but got {}",
                SECURITY_PARAM,
                x_padded.len()
            );
        }

        x_padded
            .chunks(SECURITY_PARAM)
            .map(|xi| {
                assert_eq!(SECURITY_PARAM, xi.len());
                F2::form_superfield(xi.try_into().unwrap())
            })
            .collect()
    }

    /// Function doing linear hashing of the column of bits in lock-step.
    ///
    /// There are `REPETITION_PARAM` tracks where one group of bits is provided as a [`FLambda`] value.
    pub(crate) fn hash_matrix(
        &self,
        xs: &[[F8b; REPETITION_PARAM]],
    ) -> [HashConsistency; SECURITY_PARAM] {
        assert_eq!(xs.len(), self.ell + 2 * SECURITY_PARAM + B);
        let (x0, x1) = xs.split_at(self.ell + SECURITY_PARAM);

        // There are different **options** to hashing the elements. The most runtime effective option is option #2, and the
        // most memory efficient option is option #3 because it is streaming the columns.

        // OPTION #1: naive
        // This option simply create the enumerator for the columns transposed of the field values and hashes with powers the columns sequentially.
        /*
        let packed_x0 = pack_flambda(x0);
        let x0_vec = ColumnEnumState::new(&packed_x0);
        let mut w0 = s0;
        let mut w1 = s1;
        let mut h0 = [FLambda::ZERO; SECURITY_PARAM];
        let mut h1 = [FLambda::ZERO; SECURITY_PARAM];

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
        fn powers(base: FLambda, n: usize) -> Vec<FLambda> {
            let mut out = Vec::with_capacity(n);
            let mut p = base;
            for _ in 0..n {
                out.push(p);
                p *= base;
            }
            out
        }
        fn accumulate_cols(
            x0_vec: &[[FLambda; SECURITY_PARAM]],
            s0: FLambda,
            s1: FLambda,
        ) -> ([FLambda; SECURITY_PARAM], [FLambda; SECURITY_PARAM]) {
            let how_many = x0_vec.len();
            let w0 = powers(s0, how_many);
            let w1 = powers(s1, how_many);

            let mut h0 = [FLambda::ZERO; SECURITY_PARAM];
            let mut h1 = [FLambda::ZERO; SECURITY_PARAM];

            // Parallelize over (h0[j], h1[j]) pairs; each thread owns disjoint &mut slots.
            h0[..]
                .par_iter_mut()
                .zip(h1[..].par_iter_mut())
                .enumerate()
                .for_each(|(j, (h0j, h1j))| {
                    let mut acc0 = FLambda::ZERO;
                    let mut acc1 = FLambda::ZERO;
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

        let x0_vec = ColumnEnumState::new(x0);

        const N: usize = 2; // number of threads
        let mut senders: Vec<SyncSender<[FLambda; SECURITY_PARAM / N]>> = Vec::with_capacity(N);
        let mut receivs = Vec::with_capacity(N);
        let (result_sender, result_receiver) = channel();
        for _ in 0..N {
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
                let mut h0 = [FLambda::ZERO; SECURITY_PARAM / N];
                let mut h1 = [FLambda::ZERO; SECURITY_PARAM / N];
                for slice in recv.iter() {
                    for (j, v) in slice.iter().enumerate() {
                        h0[j] += v * w0;
                        h1[j] += v * w1;
                    }

                    w0 *= s0;
                    w1 *= s1;
                }
                send_i.send((i, h0, h1)).unwrap();
            });
            handles.push(handle);
        }

        for arr in x0_vec {
            for (i, _) in (0..N).enumerate() {
                senders[i]
                    .send(
                        arr[i * (SECURITY_PARAM / N)..(i + 1) * (SECURITY_PARAM / N)]
                            .try_into()
                            .unwrap(),
                    )
                    .unwrap();
            }
        }
        drop(senders);

        let mut h0 = [FLambda::ZERO; SECURITY_PARAM];
        let mut h1 = [FLambda::ZERO; SECURITY_PARAM];
        for _ in 0..N {
            let (i, h0_i, h1_i) = result_receiver.recv().unwrap();
            h0[i * (SECURITY_PARAM / N)..(i + 1) * (SECURITY_PARAM / N)].copy_from_slice(&h0_i);
            h1[i * (SECURITY_PARAM / N)..(i + 1) * (SECURITY_PARAM / N)].copy_from_slice(&h1_i);
        }

        // END OPTION #3

        let mut h2 = [FLambda::ZERO; SECURITY_PARAM];
        let mut h3 = [FLambda::ZERO; SECURITY_PARAM];
        for j in 0..SECURITY_PARAM {
            h2[j] = self.r0 * h0[j] + self.r1 * h1[j];
            h3[j] = self.r2 * h0[j] + self.r3 * h1[j];
        }

        let mut out = [HashConsistency::default(); SECURITY_PARAM];

        let x1_packed = pack_flambda(x1);

        for j in 0..SECURITY_PARAM {
            // Line 14 (call ToBits and truncate).
            let h2_bits = h2[j].bit_decomposition();
            let (h3_bits, _unused): (GenericArray<bool, U16>, _) =
                h3[j].bit_decomposition().split();

            // Line 14 (append).
            let all_bits: [bool; SECURITY_PARAM + B] = h2_bits.concat(h3_bits).into();

            let mut x1_bits = [false; SECURITY_PARAM + B];
            for col in 0..SECURITY_PARAM + B {
                x1_bits[col] = x1_packed[col].bit_decomposition()[j];
            }

            // Line 14 (XOR with x1).
            let single_out = izip!(all_bits, x1_bits)
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
    use std::iter::repeat_with;
    use std::iter::zip;

    use crate::parameters::{FLambda, SECURITY_PARAM};
    use crate::vole::commit_reconstruct::B;
    use crate::vole::commit_reconstruct::l_hat;
    use crate::vole::consistency_check::VoleHasher;
    use crate::vole::crypto_primitives::CHALL1_LENGTH;
    use rand::rng;
    use swanky_field::FiniteRing;
    use swanky_field_binary::F2;
    use swanky_serialization::CanonicalSerialize;

    #[test]
    fn test_padding_of_to_field_flambda_and_pad() {
        // Called with an `ell`-length input, `to_field_lambda` pads up to a multiple of lambda and
        // emits one field element per lambda-bit chunk, so there are `ceil(ell / lambda)` of them.
        for ell in [1000, SECURITY_PARAM, SECURITY_PARAM + 1] {
            let v = vec![F2::ZERO; ell];
            let hasher = VoleHasher::from_seed([0; CHALL1_LENGTH], ell);
            let t = hasher.to_field_lambda(&v);
            assert_eq!(t.len(), ell.div_ceil(SECURITY_PARAM), "ell = {ell}");
        }

        // Bit `i` of the input becomes the coefficient of `x^(i mod lambda)` in chunk
        // `i / lambda`, so bit 0 gives 1 in the first chunk and bit lambda+1 gives x in the second.
        let mut v = vec![F2::ZERO; SECURITY_PARAM + 2];
        v[0] = F2::ONE;
        v[SECURITY_PARAM + 1] = F2::ONE;
        let hasher = VoleHasher::from_seed([0; CHALL1_LENGTH], SECURITY_PARAM + 2);
        let t = hasher.to_field_lambda(&v);
        let mut res1 = [0u8; SECURITY_PARAM / 8];
        res1[0] = 1u8;
        assert_eq!(t[0], FLambda::from_bytes(&res1.into()).unwrap());
        let mut res2 = [0u8; SECURITY_PARAM / 8];
        res2[0] = 2u8;
        assert_eq!(t[1], FLambda::from_bytes(&res2.into()).unwrap());
        // TODO: Could generate random values and decompose the generated FLambda and check the equivalence
    }

    // Test that [`vole_hash`] returns 0 when all the inputs are 0.
    #[test]
    fn test_vole_hash_zero() {
        let seeds = [0u8; (SECURITY_PARAM * 6) / 8];

        const HOW_MANY: usize = 1000;
        let x = [F2::ZERO; HOW_MANY + 2 * SECURITY_PARAM + B];

        let hasher = VoleHasher::from_seed(seeds, HOW_MANY);
        let v = hasher.hash(&x);

        for b in v.0.iter() {
            assert_eq!(*b, F2::ZERO);
        }
    }

    // Test the xor part at the end of [`vole_hash`]
    #[test]
    fn test_vole_hash_last_xor() {
        let seeds = [0u8; (SECURITY_PARAM * 6) / 8];

        const HOW_MANY: usize = 1000;
        let mut x = [F2::ZERO; HOW_MANY + 2 * SECURITY_PARAM + B];
        let pos = 13;
        x[HOW_MANY + SECURITY_PARAM + pos] = F2::ONE;

        let hasher = VoleHasher::from_seed(seeds, HOW_MANY);
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
    #[test]
    fn test_vole_hash_is_linear() {
        let rng = &mut rng();

        let seeds = [1u8; (SECURITY_PARAM * 6) / 8];

        const HOW_MANY: usize = 1000;
        let x0: Vec<F2> = repeat_with(|| F2::random(rng))
            .take(l_hat(HOW_MANY))
            .collect();
        let x1: Vec<F2> = repeat_with(|| F2::random(rng))
            .take(l_hat(HOW_MANY))
            .collect();
        let x2: Vec<F2> = zip(&x0, &x1).map(|(a, b)| a + b).collect();

        let hasher = VoleHasher::from_seed(seeds, HOW_MANY);
        let v0 = hasher.hash(&x0);
        let v1 = hasher.hash(&x1);
        let v2 = hasher.hash(&x2);

        for ((a, b), c) in v0.0.iter().zip(v1.0.iter()).zip(v2.0.iter()) {
            assert_eq!(*a + *b, *c);
        }
    }

    #[test]
    fn test_transpose_lockstep_equals_enumerator() {
        use super::{ColumnEnumState, pack_flambda, to_field_flambda_and_pad_lockstep};
        use crate::parameters::REPETITION_PARAM;
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
            let mut rows: Vec<[F8b; REPETITION_PARAM]> = Vec::with_capacity(len);
            for i in 0..len {
                let mut row = [F8b::ZERO; REPETITION_PARAM];
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

            let packed = pack_flambda(&rows);

            let via_lockstep = to_field_flambda_and_pad_lockstep(&packed);
            let via_enum: Vec<[FLambda; SECURITY_PARAM]> = ColumnEnumState::new(&rows).collect();

            assert_eq!(
                via_lockstep.len(),
                via_enum.len(),
                "mismatched chunk count for len={}",
                len
            );
            for (i, (a, b)) in via_lockstep.iter().zip(via_enum.iter()).enumerate() {
                for j in 0..SECURITY_PARAM {
                    assert_eq!(
                        a[j], b[j],
                        "mismatch at len={}, chunk={}, col={} ",
                        len, i, j
                    );
                }
            }
        }
    }
}
