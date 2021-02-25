use crypto::sha3::Sha3;
use crypto::digest::Digest as CD;
use ndarray::{ArrayView1, ArrayView2};

//
// XXX: Use a silly field for now.
//
type Field = crate::f5038849::F;

const HBYTES: usize = 32; // Use 256-bit hash for now
const HZERO: Digest = [0u8; HBYTES];
const HFUNC: fn() -> Sha3 = Sha3::sha3_256;

type Store = merkletree::store::VecStore<Digest>;
pub type Digest = [u8; HBYTES];
pub type Tree = merkletree::merkle::MerkleTree<Digest, HashAlgo, Store>;
pub type Proof = merkletree::proof::Proof<Digest>;

pub struct HashAlgo(Sha3);

impl HashAlgo { fn new() -> Self { Self(HFUNC()) } }

impl Default for HashAlgo { fn default() -> Self { Self::new() } }

impl std::hash::Hasher for HashAlgo {
    #[inline]
    fn write(&mut self, msg: &[u8]) { self.0.input(msg) }

    // From merkletree docs: "Algorithm breaks the Hasher contract at
    // finish(), but that is intended."
    fn finish(&self) -> u64 { unimplemented!() }
}

impl merkletree::hash::Algorithm<Digest> for HashAlgo {
    #[inline]
    fn hash(&mut self) -> [u8; HBYTES] {
        let mut h = [0u8; 32];
        self.0.result(&mut h);
        h
    }

    #[inline]
    fn reset(&mut self) { self.0.reset() }
}

pub fn hash_col(a: ArrayView1<Field>) -> Digest {
    let mut hash = HFUNC();

    for f in a {
        hash.input(&f.bytes());
    }

    let mut res = HZERO;
    hash.result(&mut res);
    res
}

pub fn make_tree(m: ArrayView2<Field>) -> Tree {
    let mut leaves = vec![];
    let ncols = m.ncols();

    for c in 0 .. ncols {
        // XXX: Is having digests as leaves OK?
        leaves.push(hash_col(m.column(c)));
    }

    for _ in ncols .. ncols.next_power_of_two() {
        // XXX: Is padding the rest of the leaves with zeroes OK?
        leaves.push(HZERO);
    }

    Tree::try_from_iter(leaves.into_iter().map(Ok))
        .expect("Failed to generate Merkle tree")
}
