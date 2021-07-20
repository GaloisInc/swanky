use ndarray::{Array1, ArrayView1, ArrayView2};
use crypto::digest::Digest as CryptoDigest;
use scuttlebutt::field::FiniteField;

#[cfg(test)]
use proptest::{*, collection::vec as pvec};
#[cfg(test)]
use crate::util::{TestField, arb_test_field};

pub type Digest = [u8; HBYTES];
pub type Tree<H> = merkle_cbt::MerkleTree<Digest, MHMerge<H>>;
pub type Proof<H> = merkle_cbt::MerkleProof<Digest, MHMerge<H>>;

pub const HBYTES: usize = 32;
pub const HZERO: Digest = [0; HBYTES];

pub trait MerkleHash: tiny_keccak::Hasher {
    fn empty() -> Self;
}

pub struct MHMerge<H> {
    phantom: std::marker::PhantomData<H>,
}

impl<H: MerkleHash> merkle_cbt::merkle_tree::Merge for MHMerge<H> {
    type Item = Digest;
    fn merge(left: &Self::Item, right: &Self::Item) -> Self::Item {
        let mut hash = H::empty();

        hash.update(left);
        hash.update(right);

        let mut res = HZERO;
        hash.finalize(&mut res);
        res
    }
}

// Hash a full interleaved-codeword column.
pub fn hash_column<H, Field>(a: ArrayView1<Field>) -> Digest
    where H: MerkleHash, Field: FiniteField
{
    let mut hash = H::empty();

    a.iter().for_each(|f| hash.update(&f.to_bytes()));

    let mut res = HZERO;
    hash.finalize(&mut res);
    res
}

pub struct Sha256 (crypto::sha2::Sha256);

impl tiny_keccak::Hasher for Sha256 {
    fn update(&mut self, bs: &[u8]) { self.0.input(bs) }
    fn finalize(self, bs: &mut [u8]) { self.0.clone().result(bs) }
}

impl MerkleHash for Sha256 {
    fn empty() -> Self { Self(crypto::sha2::Sha256::new()) }
}

pub struct Sha3(tiny_keccak::Sha3);

impl tiny_keccak::Hasher for Sha3 {
    fn update(&mut self, bs: &[u8]) { self.0.update(bs) }
    fn finalize(self, bs: &mut [u8]) { self.0.finalize(bs) }
}

impl MerkleHash for Sha3 {
    fn empty() -> Self { Self(tiny_keccak::Sha3::v256()) }
}

pub struct DummyHash ();

impl tiny_keccak::Hasher for DummyHash {
    fn update(&mut self, _bs: &[u8]) {}

    fn finalize(self, bs: &mut [u8]) {
        for b in bs { *b = 0; }
    }
}

impl MerkleHash for DummyHash {
    fn empty() -> Self { Self() }
}

#[derive(Debug, Clone)]
pub struct Lemma<Field, H> {
    phantom: std::marker::PhantomData<H>,

    columns: Vec<Array1<Field>>,
    lemmas: Vec<Digest>,
    indices: Vec<u32>,
}

#[allow(non_snake_case)]
impl<Field: FiniteField, H: MerkleHash> Lemma<Field, H> {
    pub fn new(
        tree: &Tree<H>,
        U: ArrayView2<Field>,
        some_indices: &[usize]
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
            phantom: std::marker::PhantomData,

            columns: some_columns,
            lemmas: proof.lemmas().to_vec(),
            indices: proof.indices().to_vec(),
        }
    }

    #[inline]
    pub fn columns(&self) -> &[Array1<Field>] {
        &self.columns
    }

    pub fn nlemmas(&self) -> usize { self.lemmas.len() }

    pub fn verify(&self, root: &Digest) -> bool {
        let leaves = self.columns
            .iter()
            .map(|c| hash_column::<H, Field>(c.view()))
            .collect::<Vec<Digest>>();
        let proof: Proof<H> = Proof::new(self.indices.clone(), self.lemmas.clone());

        proof.verify(root, &leaves)
    }

    pub fn size(&self) -> usize {
        self.columns.iter().map(|c| c.len()).sum::<usize>() * std::mem::size_of::<Field>() +
        self.lemmas.len() * std::mem::size_of::<Digest>() +
        self.indices.len() * std::mem::size_of::<u32>()
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
            .gencolumns()
            .into_iter()
            .map(|c| hash_column::<Sha256, TestField>(c.view()))
            .collect::<Vec<Digest>>();
        let tree = merkle_cbt::CBMT::build_merkle_tree(&leaves);
        let lemma: Lemma<_, Sha256> = Lemma::new(&tree, arr.view(), &indices);

        lemma.verify(&tree.root());
    }
}

pub fn make_tree<Field: FiniteField, H: MerkleHash>(
    m: ArrayView2<Field>
) -> Tree<H> {
    merkle_cbt::CBMT::build_merkle_tree(
        &m.gencolumns()
            .into_iter()
            .map(|c| hash_column::<H, Field>(c))
            .collect::<Vec<Digest>>()
    )
}
