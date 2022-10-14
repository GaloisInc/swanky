//! Helper functions for generating Merkle trees and proofs. Note that this
//! library is just a thin wrapper around the `merkle_cbt` library.

// TODO: Eliminate excessive use of vectors in anonymous functions, function
// return values, etc.

use digest::Digest as CryptoDigest;
use ndarray::{Array2, ArrayView1, ArrayView2};
use scuttlebutt::field::FiniteField;

type HashOutput<T> = digest::Output<T>;

/// A Merkle tree based on the hash function `H`.
pub type Tree<H> = merkle_cbt::MerkleTree<HashOutput<H>, MHMerge<H>>;

/// A Merkle proof based on the hash function `H`.
type Proof<H> = merkle_cbt::MerkleProof<HashOutput<H>, MHMerge<H>>;

/// Dummy struct for generically implementing `merkle_cbt::merkle_tree::Merge`.
pub struct MHMerge<H> {
    phantom: std::marker::PhantomData<H>,
}

impl<H: CryptoDigest> merkle_cbt::merkle_tree::Merge for MHMerge<H> {
    type Item = HashOutput<H>;
    fn merge(left: &Self::Item, right: &Self::Item) -> Self::Item {
        let mut hash = H::new();

        hash.update(left);
        hash.update(right);

        hash.finalize()
    }
}

/// Hash a full interleaved-codeword column.
pub fn hash_column<H, Field>(a: ArrayView1<Field>) -> HashOutput<H>
where
    H: CryptoDigest,
    Field: FiniteField,
{
    let mut hash = H::new();

    a.iter().for_each(|f| hash.update(&f.to_bytes()));

    hash.finalize()
}

/// Merkle proof of t-column inclusion, along with the t public columns.
#[derive(Debug, Clone)]
pub struct Lemma<Field, H: CryptoDigest> {
    /// Public columns of the interleaved codeword.
    pub columns: Array2<Field>,
    lemmas: Vec<HashOutput<H>>,
    indices: Vec<u32>,
}

#[allow(non_snake_case)]
impl<Field: FiniteField, H: CryptoDigest> Lemma<Field, H> {
    /// Create a new proof based on a tree of interleaved-codeword columns.
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
            columns: some_columns,
            lemmas: proof.lemmas().to_vec(),
            indices: proof.indices().to_vec(),
        }
    }

    /// Number of digests in this `Lemma`.
    pub fn nlemmas(&self) -> usize {
        self.lemmas.len()
    }

    /// Verify that this lemma matches a given root.
    pub fn verify(&self, root: &HashOutput<H>) -> bool {
        let leaves = self
            .columns
            .columns()
            .into_iter()
            .map(|c| hash_column::<H, Field>(c.view()))
            .collect::<Vec<HashOutput<H>>>();
        let proof: Proof<H> = Proof::new(self.indices.clone(), self.lemmas.clone());

        proof.verify(root, &leaves)
    }

    /// Size in bytes of this lemma.
    pub fn size(&self) -> usize {
        self.columns.len() * std::mem::size_of::<Field>()
            + self.lemmas.len() * std::mem::size_of::<HashOutput<H>>()
            + self.indices.len() * std::mem::size_of::<u32>()
    }
}

/// Create a Merkle-tree root out of an interleaved codeword.
pub fn make_tree<Field: FiniteField, H: CryptoDigest>(m: ArrayView2<Field>) -> Tree<H> {
    merkle_cbt::CBMT::build_merkle_tree(
        &m.columns()
            .into_iter()
            .map(|c| hash_column::<H, Field>(c))
            .collect::<Vec<HashOutput<H>>>(),
    )
}

#[cfg(test)]
use crate::util::{arb_test_field, TestField};
#[cfg(test)]
use proptest::{collection::vec as pvec, *};

#[cfg(test)]
proptest! {
    #[test]
    fn test_merkle_lemma(
        values in pvec(arb_test_field(), 50 * 50),
        indices in pvec(0usize..50, 20),
    ) {
        use sha2::Sha256;
        use ndarray::Array2;

        let arr = Array2::from_shape_vec((50,50), values).unwrap();
        let leaves = arr
            .columns()
            .into_iter()
            .map(|c| hash_column::<Sha256, TestField>(c.view()))
            .collect::<Vec<HashOutput<Sha256>>>();
        let tree = merkle_cbt::CBMT::build_merkle_tree(&leaves);
        let lemma: Lemma<_, Sha256> = Lemma::new(&tree, arr.view(), &indices);

        lemma.verify(&tree.root());
    }
}
