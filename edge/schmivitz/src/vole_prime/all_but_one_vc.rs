#![allow(dead_code)]
// line WORKS AND TESTED!!
// line Deals with all the BAVC stuff

use std::iter::zip;

use crate::vole::crypto_primitives::{Com, Key, Seed, IV};
use crate::vole_prime::crypto_primitives::{h0, h1, H1, pPRG};
use swanky_field::PrimeFiniteField;
use rand::Rng;

/// Converts chall Fp to u8 vector accoridng to the bit len of chall Fp.
pub(crate) fn chall_fp_vec_to_bytes_vec<Fp: PrimeFiniteField>(chall_fp: Vec<Fp>) -> Vec<u8> {
    assert!(Fp::ZERO.bit_decomposition().len() >= 32);

    let chall_fp_vec_len = chall_fp.len();
    let chall_fp_byte_len = chall_fp[0].to_bytes().to_vec().len();

    let mut chall_bytes = Vec::with_capacity(chall_fp_vec_len * chall_fp_byte_len);

    for chall_i in chall_fp.clone() {
        chall_bytes.extend(chall_i.to_bytes().to_vec());
    }
    return chall_bytes;
}

/// Pass the u8 vector of the Fp chall. Returns the correct u8 chall for the ith tree.
pub(crate) fn get_chall_for_ith_tree(
    chall_bytes: Vec<u8>,
    tree_idx: usize,
    t0: usize,
    Fp_bit_len: usize,
) -> Vec<u8> {
    let mut ret_chall_bytes = vec![0u8; (Fp_bit_len + 7) / 8];

    // NOTE: So for example if we have 127 bits, we will take 128 bits, else the chall goes crazy!
    let tree_start_bit_idx = tree_idx * ((Fp_bit_len + 7) / 8) * 8;
    let tree_end_bit_idx = tree_start_bit_idx + ((Fp_bit_len + 7) / 8) * 8;

    for i in tree_start_bit_idx..tree_end_bit_idx {
        ret_chall_bytes[(i - tree_start_bit_idx) / 8] |= chall_bytes[i / 8] & (0x01 << i % 8);
    }

    return ret_chall_bytes;
}

/// Takes the BAVC comms and returns H1
pub(crate) fn h1_on_coms(coms: &[Com]) -> H1 {
    let mut inp = vec![];
    for com in coms {
        inp.extend(com);
    }
    h1(&inp)
}

#[derive(Clone, Default)]
pub struct Keys(Vec<Key>);
impl Keys {
    fn get(&self, depth: usize, idx: usize) -> Key {
        let layer_start = (1 << depth) - 1;
        self.0[layer_start + idx]
    }

    fn set(&mut self, depth: usize, idx: usize, k: Key) {
        let layer_start = (1 << depth) - 1;
        self.0[layer_start + idx] = k;
    }

    fn get_layer(&self, depth: usize) -> &[Key] {
        let layer_start = (1 << depth) - 1;
        let layer_end = (1 << (depth + 1)) - 1;
        &self.0[layer_start..layer_end]
    }
}

pub(crate) type Decom = (Keys, Vec<Com>);
pub(crate) type Pdecom = (Vec<Key>, Com);

/// Compute all the internal keys, bottom seeds and commitments at a given depth.
///
/// This function is not present in the FAEST spec but it is a code fragment identified in
/// both VC.commmit and VC.reconstruct that can be factorized.
/// This function is used in [`commit()`] and [`reconstruct`].
fn tree(iv: IV, r: Key, depth: usize) -> (Keys, Vec<Seed>, Vec<Com>) {
    let n = 1 << depth;

    let mut ks = Keys(vec![Key::default(); 2 * n - 1]);
    // initialize the first key
    ks.set(0, 0, r);

    for d in 1..depth + 1 {
        let n_previous_level = 1 << (d - 1);
        for j in 0..n_previous_level {
            let mut prg = pPRG::new(ks.get(d - 1, j), iv);
            let (t1, t2) = prg.encrypt_double();
            ks.set(d, j * 2, t1);
            ks.set(d, j * 2 + 1, t2);
        }
    }

    // Set the bottom seeds and commitments:
    let mut seeds = Vec::with_capacity(n);
    let mut coms = Vec::with_capacity(n);
    for k in ks.get_layer(depth) {
        let (sd, com) = h0(*k, iv);
        seeds.push(sd);
        coms.push(com);
    }

    (ks, seeds, coms)
}

#[inline(never)]
pub(crate) fn commit(r: Key, iv: IV, depth: usize) -> (H1, Decom, Vec<Seed>) {
    let (ks, seeds, coms) = tree(iv, r, depth);

    let h = h1_on_coms(&coms);

    (h, (ks, coms), seeds)
}

/// Pass u8 vector chall derived from Fp vec chall. Returns the leaf position on the tree
pub(crate) fn num_rec(chall_bytes: Vec<u8>, tree_depth: usize) -> usize {
    let mut r = 0;
    let mut pow2 = 1;
    for d in 0..tree_depth {
        let b = (chall_bytes[d / 8] >> d % 8) & 1;
        r += (if b == 1 { 1 } else { 0 }) * pow2; // TODO: make constant time!
        pow2 *= 2;
    }
    r
}

pub(crate) fn open(decom: &Decom, chall_as_bytes: Vec<u8>, tree_depth: usize) -> Pdecom {
    assert_eq!(
        decom.1.len(),
        1 << tree_depth,
        "Open function from all-but-one vector commitment scheme failed because of incompatible lengths of decommitment and index to open."
    );

    let chall_num = num_rec(chall_as_bytes.clone(), tree_depth);
    let mut cop: Vec<Key> = Vec::with_capacity(tree_depth);

    let (ks, coms) = decom;
    let mut a: usize = 0;

    let mut chall_as_bits: Vec<bool> = Vec::with_capacity(tree_depth);
    for d in 0..tree_depth {
        chall_as_bits.push((chall_as_bytes[d / 8] >> d % 8) & 1 == 1);
    }

    for d in 0..tree_depth {
        let b = chall_as_bits[(tree_depth - 1) - d]; // iter.rev
        let b_num = if b { 1 } else { 0 };
        let idx: usize = (2 * a) + (1 - b_num);
        cop.push(ks.get(d + 1, idx));

        a = (2 * a) + b_num;
    }
    debug_assert_eq!(chall_num, a);
    (cop, coms[chall_num])
}

pub(crate) fn reconstruct(
    pdecom: Pdecom,
    delta_as_bytes: Vec<u8>,
    iv: IV,
    depth: usize,
) -> (H1, Vec<Seed>) {
    let mut coms = vec![Com::default(); 1 << depth];
    let mut seeds = vec![Seed::default(); 1 << depth];

    let (cop, com_j) = pdecom;

    let mut delta_as_bits: Vec<bool> = Vec::with_capacity(depth);
    for i in 0..depth {
        delta_as_bits.push(((delta_as_bytes[i / 8] >> i % 8) & 1) == 1)
    }

    let mut pos = 0;

    for (i, (b, k)) in zip(delta_as_bits.iter().rev(), cop).enumerate() {
        let how_many: usize = 1 << (depth - i - 1);

        let (_keys, seeds_subtree, coms_subtree) = tree(iv, k, depth - i - 1);
        let copy_start = if *b { pos } else { pos + how_many };

        coms[copy_start..(copy_start + how_many)].copy_from_slice(&coms_subtree[..how_many]);
        seeds[copy_start..(copy_start + how_many)].copy_from_slice(&seeds_subtree[..how_many]);

        pos = if *b { pos + how_many } else { pos };
    }
    debug_assert_eq!(pos, num_rec(delta_as_bytes.clone(), depth));
    coms[pos] = com_j;

    let h_alpha = h1_on_coms(&coms);

    (h_alpha, seeds)
}

#[cfg(test)]
mod test {

    use super::{commit, open, reconstruct, Key, Pdecom, IV};
    use crate::vole_prime::all_but_one_vc::{
        chall_fp_vec_to_bytes_vec, get_chall_for_ith_tree, num_rec, Seed,
    };
    use proptest::prelude::*;
    use rand::Rng;
    use swanky_field::{FiniteField, PrimeFiniteField};
    use swanky_field_ff_primes::{Frs127p, F128p, F256p, F32p, F64p};

    fn test_num_rec<Fp>()
    where
        Fp: FiniteField + PrimeFiniteField + swanky_field_fft::FieldForFFT<2>,
        <Fp as TryFrom<u128>>::Error: std::fmt::Debug,
    {
        let mut depth = 4;
        let mut chall = 0;
        let mut chall_fp = Vec::with_capacity(1);
        chall_fp.push(Fp::try_from(chall).expect("encode failed"));
        let mut chall_as_bytes = chall_fp_vec_to_bytes_vec(chall_fp);

        let mut a = num_rec(chall_as_bytes, depth);
        assert_eq!(a, chall as usize);

        depth = 4;
        chall = 15;
        let mut chall_fp = Vec::with_capacity(1);
        chall_fp.push(Fp::try_from(chall).expect("encode failed"));
        chall_as_bytes = chall_fp_vec_to_bytes_vec(chall_fp);

        a = num_rec(chall_as_bytes, depth);
        assert_eq!(a, chall as usize);

        depth = 8;
        chall = (1 << 8) - 1;
        let mut chall_fp = Vec::with_capacity(1);
        chall_fp.push(Fp::try_from(chall).expect("encode failed"));
        chall_as_bytes = chall_fp_vec_to_bytes_vec(chall_fp);

        a = num_rec(chall_as_bytes, depth);
        assert_eq!(a, chall as usize);
    }

    #[test]
    fn test_num_rec_frs127p() {
        test_num_rec::<Frs127p>();
    }
    #[test]
    fn test_num_rec_f128p() {
        test_num_rec::<F128p>();
    }

    // Testing vc correctness for ith tree from the full chall
    fn test_1_vc_correctness_with_ith_tree<Fp: PrimeFiniteField>(
        r: Key,
        iv: IV,
        chall_fp: Vec<Fp>,
        tree_depth: usize,
        tree_idx: usize,
        t0: usize,
        chall_byte_len: usize,
    ) -> Result<(), TestCaseError> {
        // prover side
        let (h, decom, _) = commit(r, iv, tree_depth);
        let chall_bytes: Vec<u8> = chall_fp_vec_to_bytes_vec(chall_fp);
        let Fp_bit_len = Fp::ZERO.bit_decomposition().len();
        assert_eq!(chall_bytes.len(), chall_byte_len);
        let n_tree_chall_bytes = get_chall_for_ith_tree(chall_bytes, tree_idx, t0, Fp_bit_len);
        let pdecom: Pdecom = open(&decom, n_tree_chall_bytes.clone(), tree_depth);

        // verifier side
        let (h1, _) = reconstruct(pdecom, n_tree_chall_bytes, iv, tree_depth);
        assert_eq!(h, h1);
        println!(
            "Passed: tree_count:{} tree_idx:{} tree_depth:{}",
            t0 * 2,
            tree_idx,
            tree_depth
        );

        Ok(())
    }

    fn test_1_vc_depth_n_ith_tree<Fp>(bit_len: usize)
    where
        Fp: FiniteField + PrimeFiniteField + swanky_field_fft::FieldForFFT<2>,
        <Fp as TryFrom<u128>>::Error: std::fmt::Debug,
    {
        let iv = [1u8; 16];
        let r: [u8; 16] = [2u8; 16];
        let Fp_bit_len = bit_len;
        let Fp_byte_len = (Fp_bit_len + 7) / 8;

        // Checking for each security level
        for tree_count in (16..=32).step_by(8) {
            let t0: usize = tree_count / 2;
            let d0: usize = (tree_count * 8) / t0;

            for tree_idx in (0..t0).step_by(3) {
                for tree_depth in (2..d0).step_by(6) {
                    let chall_Fp_len = tree_count;
                    let chall_byte_len = chall_Fp_len * Fp_byte_len;
                    let mut chall_fp = Vec::with_capacity(chall_Fp_len);

                    for _ in 0..chall_Fp_len {
                        let chall = rand::thread_rng().gen_range(0..(1 << tree_depth) - 1);
                        chall_fp.push(Fp::try_from(chall).expect("encode failed"));
                    }

                    test_1_vc_correctness_with_ith_tree(
                        r,
                        iv,
                        chall_fp,
                        tree_depth,
                        tree_idx,
                        t0,
                        chall_byte_len,
                    )
                    .unwrap();
                }
            }
        }
    }

    #[test]
    fn test_1_vc_depth_n_ith_tree_f128p() {
        test_1_vc_depth_n_ith_tree::<F128p>(128);
    }

    fn test_1_vc_correctness<Fp: PrimeFiniteField>(
        r: Key,
        iv: IV,
        chall_fp: Vec<Fp>,
        tree_depth: usize,
    ) -> Result<(), TestCaseError> {
        // prover side
        let (h, decom, _) = commit(r, iv, tree_depth);
        let chall_bytes = chall_fp_vec_to_bytes_vec(chall_fp);
        let pdecom: Pdecom = open(&decom, chall_bytes.clone(), tree_depth);

        // verifier side
        let (h1, _) = reconstruct(pdecom, chall_bytes, iv, tree_depth);
        assert_eq!(h[..], h1[..]);

        Ok(())
    }

    fn test_1_vc_depth_n<Fp>()
    where
        Fp: FiniteField + PrimeFiniteField + swanky_field_fft::FieldForFFT<2>,
        <Fp as TryFrom<u128>>::Error: std::fmt::Debug,
    {
        // let iv = [1u8; 16];
        // let r: [u8; 16] = [2u8; 16];

        let mut ur = [0u8; 32];
        rand::thread_rng().fill(&mut ur);
        let iv: IV = ur[0..16].try_into().unwrap();
        let r: Seed = ur[16..32].try_into().unwrap();

        for tree_depth in (2..16).step_by(4) {
            let chall = rand::thread_rng().gen_range(0..(1 << tree_depth) - 1);
            let mut chall_fp = Vec::with_capacity(1);
            chall_fp.push(Fp::try_from(chall).expect("encode failed"));
            test_1_vc_correctness(r, iv, chall_fp, tree_depth).unwrap();
        }
    }

    #[test]
    fn test_1_vc_depth_n_f32p() {
        test_1_vc_depth_n::<F32p>();
    }
    #[test]
    fn test_1_vc_depth_n_f64p() {
        test_1_vc_depth_n::<F64p>();
    }
    #[test]
    fn test_1_vc_depth_n_frs127p() {
        test_1_vc_depth_n::<Frs127p>();
    }
    #[test]
    fn test_1_vc_depth_n_f128p() {
        test_1_vc_depth_n::<F128p>();
    }
    #[test]
    fn test_1_vc_depth_n_f256p() {
        test_1_vc_depth_n::<F256p>();
    }
}
