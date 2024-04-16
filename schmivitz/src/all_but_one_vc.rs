/*!
All-but-one vector commitment implementation.

The implementation follows the [the FAEST spec](https://faest.info/faest-spec-v1.1.pdf).
The elements from the spec that are implemented are the cryptographic primitives
the FAEST spec, page 16:
  * PRG, implemented as [`PRG`]
  * H0, implemented as [`h0`]
  * H1, implemented as [`h1`]

And the functions composing the all-but-one vector commitment
scheme the FAEST spec, Figure 5.1, page 27:
   * `VC.Commit()`, implemented as [`commit`]
   * `VC.Open()`, implemented as [`open`]
   * `VC.Reconstruct()`, implemented as [`reconstruct`]
   * `VC.Verify()`, implemented as [`verify`]
It also implements the helper function `num_rec` Fig 3.2, page 16.

We assume the $`\lambda`$ security parameter in the spec to be 128 as set in
[`SECURITY_PARAM`](crate::parameters::SECURITY_PARAM).

For convenience we abbreviate "all-but-one vector commitment" to "1-VC".
*/
#![allow(dead_code)]
use crate::crypto_primitives::{h0, h1, Com, Key, Seed, H1, IV, PRG};
use eyre::{bail, Result};

/// Hash function hashing a sequence of [`Com`]mitments and returns a hash [`H1`].
///
/// This function is applied on the leaves commitments of the Tree-PRG/GGM-tree.
/// This function corresponds to the H1 function in the FAEST spec, defined page 16.
fn h1_on_coms(coms: &[Com]) -> H1 {
    let mut inp = vec![];
    for com in coms {
        inp.extend(com);
    }

    h1(&inp)
}

/// Type storing all the [`Key`]s associated with the Tree-PRG/GGM-tree.
///
/// Its internal structure uses a vector as opposed to a binary-tree.
/// A node in the tree is addressed by its depth in the tree and its position
/// in the sequence of nodes at this depth. The mapping between the tree indexing
/// and the underlying vector indexing follows a breadth-first traversal.
/// That is the element at depth `d` and position `p`, corresponds to the vector index $`2^d + p-1`$.
pub struct Keys(Vec<Key>);

impl Keys {
    /// Get a key in the tree at `depth` and index `idx` in the associated layer.
    fn get(&self, depth: usize, idx: usize) -> Key {
        let layer_start = (1 << depth) - 1;
        self.0[layer_start + idx]
    }

    /// Set a key in the tree at `depth` and index `idx` in the associated layer.
    fn set(&mut self, depth: usize, idx: usize, k: Key) {
        let layer_start = (1 << depth) - 1;
        self.0[layer_start + idx] = k;
    }

    /// Get a full layer as a slice of keys.
    fn get_layer(&self, depth: usize) -> &[Key] {
        let layer_start = (1 << depth) - 1;
        let layer_end = (1 << (depth + 1)) - 1;
        &self.0[layer_start..layer_end]
    }
}

/// Full decommitment as computed by the prover.
///
/// It is a pair of Keys composing the GGM tree and the commitments associated with the leaves of the GGM tree.
/// It corresponds to values like $`(k^i_j, com_j\in[0..n])`$ from the FAEST spec.
pub(crate) type Decom = (Keys, Vec<Com>);

/// Partial decommitment as received by the verifier from the prover.
///
/// It is a pair of Keys and a Commitment.
/// The keys are the siblings keys collected on the path from the root of the GGM tree to a specific leaf.
/// The commitment is the one associated with the specific leaf.
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
            let mut prg = PRG::new(ks.get(d - 1, j), iv);
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

/// Commitment algorithm for the 1-VC scheme (VC.Commit from Fig. 5.1 in the spec).
///
/// Generates a hash for the vector commitment [`H1`] of length `2^depth` to the given seed `r`.
/// This also produces the the full decommitment information that a prover can later use to
/// [`open()`] the commitment and the full set of [`Seed`]s.
#[inline(never)]
pub fn commit(r: Key, iv: IV, depth: usize) -> (H1, Decom, Vec<Seed>) {
    let (ks, seeds, coms) = tree(iv, r, depth);

    // compute the h
    let h = h1_on_coms(&coms);

    (h, (ks, coms), seeds)
}

/// Convert a sequence of bool into a number.
///
/// It implements the `NumRec` function from Fig. 3.2, page 16 of the spec.
pub(crate) fn num_rec(j: &[bool]) -> usize {
    let mut r = 0;
    let mut pow2 = 1;
    for b in j.iter() {
        r += (if *b { 1 } else { 0 }) * pow2;
        pow2 *= 2;
    }
    r
}

/// Open algorithm for the 1-VC scheme (VC.Open from Fig. 5.1 in the spec).
///
/// Generates a partial decommitment [`Pdecom`] given a full decommitment `decom`. This
/// partial decommitment is produced by the prover and will be sent to the verifier to reconstruct
/// all but one seeds using [`reconstruct`] and verify the commitment using [`verify`].
pub fn open(decom: &Decom, j: Vec<bool>) -> Pdecom {
    assert_eq!(
        decom.1.len(),
        1 << j.len(),
        "Open function from all-but-one vector commitment scheme failed because of incompatible lengths of decommitment and index to open."
    );
    let j_num = num_rec(&j);
    let mut cop: Vec<Key> = Vec::with_capacity(j.len());

    // The algorithm works by traversing the tree of keys from top to bottom, and collect
    // all the sibling keys along the path from the root to the bottom key associated with `j`.
    // The variable `a` below computes iteratively the index, at the current depth, of the subtree
    // containing `j`.
    let (ks, coms) = decom;
    let mut a = 0;
    for (i, b) in j.iter().rev().enumerate() {
        // `idx` is the index of the subtree that does not contain `j` at a given depth.
        let b_num = if *b { 1 } else { 0 };
        let idx = 2 * a + (1 - b_num);
        // The key associated with this node is stored
        cop.push(ks.get(i + 1, idx));

        // Update to the start index
        a = 2 * a + b_num;
    }
    // At the end of the loop, it turns out that `a` is equal to `j_num`.
    debug_assert_eq!(j_num, a);
    (cop, coms[j_num])
}

/// Reconstruct algorithm for the 1-VC scheme (VC.Reconstruct from Fig. 5.1 in the spec).
///
/// Generates a full hash [`H1`] and all-but-one seeds given a [`Pdecom`] and index `j` and
/// an initial vector `iv`. The seeds are used later in the VOLE-it-HEAD protocol to generate VOLEs.
/// This function is used by the verifier after receiving the [`Pdecom`] from the prover.
pub(crate) fn reconstruct(pdecom: Pdecom, j: Vec<bool>, iv: IV) -> (H1, Vec<Seed>) {
    assert_eq!(
        pdecom.0.len(),
        j.len(),
        "Incompatible partial decommitment length with index binary decomposition length"
    );
    let d = j.len();

    let (cop, com_j) = pdecom;

    let mut coms = vec![Com::default(); 1 << d];
    // The seeds computed by `reconstruct` have one less entry than coms
    let mut seeds = vec![Seed::default(); (1 << d) - 1];

    let mut pos = 0;
    for (i, (b, k)) in std::iter::zip(j.iter().rev(), cop).enumerate() {
        let how_many = 1 << (d - i - 1);
        let (_keys, seeds_subtree, coms_subtree) = tree(iv, k, d - i - 1);
        let copy_start = if *b { pos } else { pos + how_many };

        // if the boolean is one then the hidden seed in on the left,
        // and then the start to copy the seed is shifted by one.
        let copy_start_seeds = if *b { copy_start } else { copy_start - 1 };

        // copy commitments from the subtree into the array of all coms
        coms[copy_start..(copy_start + how_many)].copy_from_slice(&coms_subtree[..how_many]);

        seeds[copy_start_seeds..(copy_start_seeds + how_many)]
            .copy_from_slice(&seeds_subtree[..how_many]);

        pos = if *b { pos + how_many } else { pos };
    }
    // After computing all the commitments, except com_j, it is finally setup in
    // the right spot.
    debug_assert_eq!(pos, num_rec(&j));
    coms[pos] = com_j;

    // compute the hash using H1
    let h_computed = h1_on_coms(&coms);

    debug_assert_eq!(seeds.len(), (1 << d) - 1);
    (h_computed, seeds)
}

/// Verify algorithm for the 1-VC scheme (VC.Verify from Fig. 5.1 in the spec).
///
/// Verify the correctness of the full hash of commitments `h_com` using the partial decommitment `pdecom`,
/// at an index `j`, and the initial vector `iv`. This function is run by the verifier and relies on
/// [`reconstruct`] for its internal computation.
pub(crate) fn verify(h_com: H1, pdecom: Pdecom, j: Vec<bool>, iv: IV) -> Result<()> {
    assert_eq!(
        pdecom.0.len(),
        j.len(),
        "Incompatible length of partial decommitment with index binary decomposition length"
    );
    let (reconstructed_hash, _seeds) = reconstruct(pdecom, j, iv);
    if h_com != reconstructed_hash {
        bail!(
            "Verify algotithm for all-but-one vector commitment scheme failed:
            recomputed hash of commitments differs from received hash from prover."
        );
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use super::{commit, num_rec, open, reconstruct, verify, Key, Seed, IV};
    use proptest::prelude::*;

    #[test]
    fn test_num_rec_at_len_4() {
        let v = num_rec(&[false, false, false, false]);
        assert_eq!(v, 0);
        let v = num_rec(&[true, false, false, false]);
        assert_eq!(v, 1);
        let v = num_rec(&[true, true, true, true]);
        assert_eq!(v, 15);
        let v = num_rec(&[false, true, true, true]);
        assert_eq!(v, 14);
        let v = num_rec(&[true, false, true, true]);
        assert_eq!(v, 13);
    }

    #[test]
    fn test_num_rec_at_len_8() {
        let v = num_rec(&[false, false, false, false, false, false, false, false]);
        assert_eq!(v, 0);
        let v = num_rec(&[true, false, false, false, false, false, false, false]);
        assert_eq!(v, 1);
        let v = num_rec(&[true, true, true, true, true, true, true, true]);
        assert_eq!(v, 255);
        let v = num_rec(&[false, true, true, true, true, true, true, true]);
        assert_eq!(v, 254);
        let v = num_rec(&[true, false, true, true, false, false, false, false]);
        assert_eq!(v, 13);
        let v = num_rec(&[true, false, true, true, false, true, false, true]);
        assert_eq!(v, 173);
    }

    // Test the correctness of values computed by commit/open/verify/reconstruct
    fn test_1_vc_correctness(r: Key, iv: IV, j: Vec<bool>) -> Result<(), TestCaseError> {
        let depth = j.len();
        // prover side
        let (h, decom, sd) = commit(r, iv, depth);
        let (cop, com_j) = open(&decom, j.clone());

        // verifier side
        let j_num = num_rec(&j);
        let r = verify(h, (cop.clone(), com_j), j.clone(), iv);
        if r.is_err() {
            return Err(TestCaseError::fail(r.err().unwrap().to_string()));
        }

        // test that the seeds from the prover are the same as the ones found by the verifier
        let (_, seeds) = reconstruct((cop, com_j), j, iv);

        let mut prv_i = 0;
        for (vrf_i, seed) in seeds.iter().enumerate() {
            if vrf_i == j_num {
                // if the index is equal to j then we skip a seed in the prover
                prv_i += 1;
            }
            prop_assert_eq!(sd[prv_i], *seed);
            prv_i += 1;
        }
        Ok(())
    }

    #[test]
    fn test_1_vc_works_unit_depth_2() {
        let iv = IV::default();
        let r = Key::default();

        let j = vec![false, true];
        test_1_vc_correctness(r, iv, j).unwrap();
    }

    #[test]
    fn test_1_vc_works_unit_depth_3() {
        let iv = IV::default();
        let r = Key::default();

        let j = vec![true, true, false];
        test_1_vc_correctness(r, iv, j).unwrap();
    }

    #[test]
    fn test_1_vc_works_unit_depth_8() {
        let iv = IV::default();
        let r = Key::default();

        let j = vec![false, true, true, false, false, true, true, true];
        test_1_vc_correctness(r, iv, j).unwrap();
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1000))]

        #[test]
        fn test_1_vc_works_on_randomized_input(
            ref j in prop::collection::vec(any::<bool>(), 8),
            ref rand_arr in prop::array::uniform32(any::<u8>()))
        {
            // setup random iv and r:
            let iv : IV = rand_arr[0..16].try_into().unwrap() ;
            let r : Seed = rand_arr[16..32].try_into().unwrap();

            // Test
            test_1_vc_correctness(r, iv, j.to_vec())?;
        }
    }
}
