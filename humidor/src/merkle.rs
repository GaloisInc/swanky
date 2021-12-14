// This file is part of `humidor`.
// Copyright © 2021 Galois, Inc.
// See LICENSE for licensing information.

//! Helper functions for generating Merkle trees and proofs. Note that this
//! library is just a thin wrapper around the `merkle_cbt` and `tiny_keccak`
//! libraries.

// TODO: Eliminate excessive use of vectors in anonymous functions, function
// return values, etc.

use blake_hash::digest::{FixedOutputDirty, Update};
use crypto::digest::Digest as CryptoDigest;
use generic_array::GenericArray;
use ndarray::{Array2, ArrayView1, ArrayView2};
use scuttlebutt::field::FiniteField;

#[cfg(test)]
use crate::util::{arb_test_field, TestField};
#[cfg(test)]
use proptest::{collection::vec as pvec, *};

/// A hash digest, assumed to be 256 bits long.
pub type Digest = [u8; HBYTES];

/// A Merkle tree based on the hash function H.
pub type Tree<H> = merkle_cbt::MerkleTree<Digest, MHMerge<H>>;

/// A Merkle proof based on the hash function H.
type Proof<H> = merkle_cbt::MerkleProof<Digest, MHMerge<H>>;

/// Number of bytes in a 256-bit hash digest.
pub const HBYTES: usize = 32;

/// A zeroed-out hash digest
pub const HZERO: Digest = [0; HBYTES];

/// Trait for hash functions that can be used in Merkle trees. This wraps
/// `tiny_keccak::Hasher` to add a generic `new` function.
pub trait MerkleHash: tiny_keccak::Hasher {
    /// Create a new hasher.
    fn new() -> Self;
}

/// Dummy struct for generically implementing `merkle_cbt::merkle_tree::Merge`.
pub struct MHMerge<H> {
    phantom: std::marker::PhantomData<H>,
}

impl<H: MerkleHash> merkle_cbt::merkle_tree::Merge for MHMerge<H> {
    type Item = Digest;
    fn merge(left: &Self::Item, right: &Self::Item) -> Self::Item {
        let mut hash = H::new();

        hash.update(left);
        hash.update(right);

        let mut res = HZERO;
        hash.finalize(&mut res);
        res
    }
}

/// Hash a full interleaved-codeword column.
pub fn hash_column<H, Field>(a: ArrayView1<Field>) -> Digest
where
    H: MerkleHash,
    Field: FiniteField,
{
    let mut hash = H::new();

    a.iter().for_each(|f| hash.update(&f.to_bytes()));

    let mut res = HZERO;
    hash.finalize(&mut res);
    res
}

/// Sha256 for Merkle trees.
#[derive(Clone)]
pub struct Sha256(crypto::sha2::Sha256);

impl tiny_keccak::Hasher for Sha256 {
    fn update(&mut self, bs: &[u8]) {
        self.0.input(bs)
    }
    fn finalize(self, bs: &mut [u8]) {
        self.0.clone().result(bs)
    }
}

impl MerkleHash for Sha256 {
    fn new() -> Self {
        Self(crypto::sha2::Sha256::new())
    }
}

/// Sha3 for Merkle trees.
#[derive(Clone)]
pub struct Sha3(tiny_keccak::Sha3);

impl tiny_keccak::Hasher for Sha3 {
    fn update(&mut self, bs: &[u8]) {
        self.0.update(bs)
    }
    fn finalize(self, bs: &mut [u8]) {
        self.0.finalize(bs)
    }
}

impl MerkleHash for Sha3 {
    fn new() -> Self {
        Self(tiny_keccak::Sha3::v256())
    }
}

/// Blake for Merkle trees.
#[derive(Clone)]
pub struct Blake256(blake_hash::Blake256);

impl tiny_keccak::Hasher for Blake256 {
    fn update(&mut self, bs: &[u8]) {
        self.0.update(bs)
    }
    fn finalize(mut self, bs: &mut [u8]) {
        self.0.finalize_into_dirty(GenericArray::from_mut_slice(bs))
    }
}

impl MerkleHash for Blake256 {
    fn new() -> Self {
        Self(blake_hash::Blake256::default())
    }
}

/// Merkle proof of t-column inclusion, along with the t public columns.
#[derive(Debug, Clone)]
pub struct Lemma<Field, H> {
    phantom: std::marker::PhantomData<H>,

    /// Public columns of the interleaved codeword.
    pub columns: Array2<Field>,
    lemmas: Vec<Digest>,
    indices: Vec<u32>,
}

#[allow(non_snake_case)]
impl<Field: FiniteField + num_traits::Zero, H: MerkleHash> Lemma<Field, H> {
    /// Create a new proof based on a tree of interleaved-codeoword columns.
    pub fn new(tree: &Tree<H>, U: ArrayView2<Field>, some_indices: &[usize]) -> Self {
        let some_indices_u32 = some_indices.iter().map(|&j| j as u32).collect::<Vec<u32>>();
        let proof = tree
            .build_proof(&some_indices_u32)
            .expect("Failed to build proof with indices");

        let mut some_columns = Array2::zeros((U.nrows(), 0));
        some_indices
            .iter()
            .for_each(|&j| some_columns.push_column(U.column(j)).unwrap());

        Self {
            phantom: std::marker::PhantomData,

            columns: some_columns,
            lemmas: proof.lemmas().to_vec(),
            indices: proof.indices().to_vec(),
        }
    }

    /// Numver of digests in this `Lemma`.
    pub fn nlemmas(&self) -> usize {
        self.lemmas.len()
    }

    /// Verify that this lemma matches a given root.
    pub fn verify(&self, root: &Digest) -> bool {
        let leaves = self
            .columns
            .columns()
            .into_iter()
            .map(|c| hash_column::<H, Field>(c.view()))
            .collect::<Vec<Digest>>();
        let proof: Proof<H> = Proof::new(self.indices.clone(), self.lemmas.clone());

        proof.verify(root, &leaves)
    }

    /// Size in bytes of this lemma.
    pub fn size(&self) -> usize {
        self.columns.len() * std::mem::size_of::<Field>()
            + self.lemmas.len() * std::mem::size_of::<Digest>()
            + self.indices.len() * std::mem::size_of::<u32>()
    }
}

#[cfg(test)]
proptest! {
    #[test]
    fn test_merkle_lemma(
        values in pvec(arb_test_field(), 50 * 50),
        indices in pvec(0usize..50, 20),
    ) {
        use ndarray::Array2;

        let arr = Array2::from_shape_vec((50,50), values).unwrap();
        let leaves = arr
            .columns()
            .into_iter()
            .map(|c| hash_column::<Blake256, TestField>(c.view()))
            .collect::<Vec<Digest>>();
        let tree = merkle_cbt::CBMT::build_merkle_tree(&leaves);
        let lemma: Lemma<_, Blake256> = Lemma::new(&tree, arr.view(), &indices);

        lemma.verify(&tree.root());
    }
}

/// Create a Merkle-tree root out of an interleaved codeword.
pub fn make_tree<Field: FiniteField, H: MerkleHash>(m: ArrayView2<Field>) -> Tree<H> {
    merkle_cbt::CBMT::build_merkle_tree(
        &m.columns()
            .into_iter()
            .map(|c| hash_column::<H, Field>(c))
            .collect::<Vec<Digest>>(),
    )
}
