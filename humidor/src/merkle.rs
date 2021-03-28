use ndarray::{Array1, ArrayView1, ArrayView2};
use crypto::digest::Digest as CryptoDigest;

#[cfg(test)]
use proptest::{*, prelude::*, collection::vec as pvec};

//
// XXX: Use a silly field for now.
//
type Field = crate::f2_19x3_26::F;

pub type H = K12;
pub type Digest = <H as MerkleHash>::Digest;
pub type Tree = merkle_cbt::MerkleTree<Digest, MHMerge<H>>;
pub type Proof = merkle_cbt::MerkleProof<Digest, MHMerge<H>>;

pub trait MerkleHash: tiny_keccak::Hasher {
    type Digest;

    const HBYTES: usize = std::mem::size_of::<Self::Digest>();
    const HZERO: Self::Digest;

    fn new() -> Self;

    fn digest_into_bytes(d: &Self::Digest) -> Box<[u8]>;
    fn digest_from_bytes(b: &[u8]) -> Self::Digest;
}

pub struct MHMerge<H> {
    phantom: std::marker::PhantomData<H>,
}

impl<H: MerkleHash> merkle_cbt::merkle_tree::Merge for MHMerge<H> {
    type Item = H::Digest;
    fn merge(left: &Self::Item, right: &Self::Item) -> Self::Item {
        let mut hash = H::new();

        hash.update(&H::digest_into_bytes(left));
        hash.update(&H::digest_into_bytes(right));

        let mut res = H::digest_into_bytes(&H::HZERO);
        hash.finalize(&mut res);
        H::digest_from_bytes(&res)
    }
}

// Hash a full interleaved-codeword column.
pub fn hash_column<H: MerkleHash>(a: ArrayView1<Field>) -> H::Digest {
    let mut hash = H::new();

    a.iter().for_each(|f| hash.update(&f.bytes()));

    let mut res = H::digest_into_bytes(&H::HZERO);
    hash.finalize(&mut res);
    H::digest_from_bytes(&res)
}

pub struct Sha256 (crypto::sha2::Sha256);

impl tiny_keccak::Hasher for Sha256 {
    fn update(&mut self, bs: &[u8]) { self.0.input(bs) }
    fn finalize(self, bs: &mut [u8]) { self.0.clone().result(bs) }
}

impl MerkleHash for Sha256 {
    type Digest = [u8; 32];

    const HZERO: Self::Digest = [0u8; Self::HBYTES];

    fn new() -> Self { Self(crypto::sha2::Sha256::new()) }

    #[inline]
    fn digest_into_bytes(d: &Self::Digest) -> Box<[u8]> { Box::new(*d) }

    #[inline]
    fn digest_from_bytes(b: &[u8]) -> Self::Digest {
        use std::convert::TryInto;
        b.try_into().expect("Slice of wrong length in digest_from_bytes")
    }
}

pub struct Sha3(tiny_keccak::Sha3);

impl tiny_keccak::Hasher for Sha3 {
    fn update(&mut self, bs: &[u8]) { self.0.update(bs) }
    fn finalize(self, bs: &mut [u8]) { self.0.finalize(bs) }
}

impl MerkleHash for Sha3 {
    type Digest = [u8; 32];

    const HZERO: Self::Digest = [0u8; Self::HBYTES];

    fn new() -> Self { Self(tiny_keccak::Sha3::v256()) }

    #[inline]
    fn digest_into_bytes(d: &Self::Digest) -> Box<[u8]> { Box::new(*d) }

    #[inline]
    fn digest_from_bytes(b: &[u8]) -> Self::Digest {
        use std::convert::TryInto;
        b.try_into().expect("Slice of wrong length in digest_from_bytes")
    }
}

pub struct K12(tiny_keccak::KangarooTwelve<[u8; 16]>);

impl tiny_keccak::Hasher for K12 {
    fn update(&mut self, bs: &[u8]) { self.0.update(bs) }
    fn finalize(self, bs: &mut [u8]) { self.0.finalize(bs) }
}

impl MerkleHash for K12 {
    type Digest = [u8; 16];

    const HZERO: Self::Digest = [0u8; Self::HBYTES];

    fn new() -> Self { Self(tiny_keccak::KangarooTwelve::new(Self::HZERO)) }

    #[inline]
    fn digest_into_bytes(d: &Self::Digest) -> Box<[u8]> { Box::new(*d) }

    #[inline]
    fn digest_from_bytes(b: &[u8]) -> Self::Digest {
        use std::convert::TryInto;
        b.try_into().expect("Slice of wrong length in digest_from_bytes")
    }
}

pub struct DummyHash ([u8;8]);

impl tiny_keccak::Hasher for DummyHash {
    fn update(&mut self, bs: &[u8]) {
        for c in bs.chunks(std::mem::size_of_val(&self.0)) {
            for i in 0..c.len() {
                self.0[i] = self.0[i].wrapping_add(c[i])
            }
        }
    }

    fn finalize(self, bs: &mut [u8]) {
        for i in 0..std::mem::size_of_val(&self.0) {
            bs[i] = self.0[i];
        }
    }
}

impl MerkleHash for DummyHash {
    type Digest = [u8;8];

    const HZERO: Self::Digest = [0u8; Self::HBYTES];

    fn new() -> Self { Self(Self::HZERO) }

    #[inline]
    fn digest_into_bytes<'a>(d: &Self::Digest) -> Box<[u8]> { Box::new(*d) }

    #[inline]
    fn digest_from_bytes<'a>(b: &[u8]) -> Self::Digest {
        use std::convert::TryInto;
        b.try_into().expect("Slice of wrong length in digest_from_bytes")
    }
}

#[derive(Debug, Clone)]
pub struct Lemma {
    columns: Vec<Array1<Field>>,
    lemmas: Vec<Digest>,
    indices: Vec<u32>,
}

#[allow(non_snake_case)]
impl Lemma {
    pub fn new(
        tree: &Tree,
        U: ArrayView2<Field>,
        some_indices: &Vec<usize>
    ) -> Self {
        let some_indices_u32 = some_indices
            .iter()
            .map(|&j| j as u32)
            .collect::<Vec<u32>>();
        let proof = tree.build_proof(&some_indices_u32)
            .expect("Failed to build proof with indices");
        let some_columns = some_indices
            .iter()
            .map(|&j| U.column(j).to_owned())
            .collect::<Vec<Array1<Field>>>();

        Self {
            columns: some_columns,
            lemmas: proof.lemmas().to_vec(),
            indices: proof.indices().to_vec(),
        }
    }

    #[inline]
    pub fn columns(&self) -> &[Array1<Field>] {
        &self.columns
    }

    pub fn verify(&self, root: &Digest) -> bool {
        let leaves = self.columns
            .iter()
            .map(|c| hash_column::<H>(c.view()))
            .collect::<Vec<Digest>>();
        let proof = Proof::new(self.indices.clone(), self.lemmas.clone());

        proof.verify(root, &leaves)
    }
}

#[cfg(test)]
proptest! {
    #[test]
    fn test_merkle_lemma(
        values in pvec(any::<Field>(), 50 * 50),
        indices in pvec(0usize..50, 20),
    ) {
        use ndarray::Array2;

        let arr = Array2::from_shape_vec((50,50), values).unwrap();
        let leaves = arr
            .gencolumns()
            .into_iter()
            .map(|c| hash_column::<H>(c.view()))
            .collect::<Vec<Digest>>();
        let tree = merkle_cbt::CBMT::build_merkle_tree(&leaves);
        let lemma = Lemma::new(&tree, arr.view(), &indices);

        lemma.verify(&tree.root());
    }
}

pub fn make_tree(m: ArrayView2<Field>) -> Tree {
    merkle_cbt::CBMT::build_merkle_tree(
        &m.gencolumns()
            .into_iter()
            .map(|c| hash_column::<H>(c))
            .collect::<Vec<Digest>>()
    )
}
