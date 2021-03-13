use crypto::sha3::Sha3;
use crypto::digest::Digest as CD;
use ndarray::{Array1, ArrayView1, ArrayView2};

#[cfg(test)]
use proptest::{*, prelude::*};
use proptest::collection::vec as pvec;

//
// XXX: Use a silly field for now.
//
type Field = crate::f2_19x3_26::F;

const HBYTES: usize = 32; // Use 256-bit hash for now
const HZERO: Digest = [0u8; HBYTES];
const HFUNC: fn() -> Sha3 = Sha3::sha3_256;

pub type Digest = [u8; HBYTES];
pub type Tree = merkle_cbt::MerkleTree<Digest, Sha3Merge>;
pub type Proof = merkle_cbt::MerkleProof<Digest, Sha3Merge>;

pub struct Sha3Merge {}

impl merkle_cbt::merkle_tree::Merge for Sha3Merge {
    type Item = Digest;
    fn merge(left: &Self::Item, right: &Self::Item) -> Self::Item {
        let mut hash = HFUNC();

        hash.input(left);
        hash.input(right);

        let mut res = HZERO;
        hash.result(&mut res);
        res
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
            .map(|c| hash_column(c.view()))
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
            .map(|c| hash_column(c.view()))
            .collect::<Vec<Digest>>();
        let tree = merkle_cbt::CBMT::build_merkle_tree(&leaves);
        let lemma = Lemma::new(&tree, arr.view(), &indices);

        lemma.verify(&tree.root());
    }
}

// Hash a full interleaved-codeword column.
pub fn hash_column(a: ArrayView1<Field>) -> Digest {
    let mut hash = HFUNC();

    hash.input(&a.iter()
        .flat_map(|f| f.bytes())
        .collect::<Vec<u8>>());

    let mut res = HZERO;
    hash.result(&mut res);
    res
}

pub fn make_tree(m: ArrayView2<Field>) -> Tree {
    merkle_cbt::CBMT::build_merkle_tree(
        &m.gencolumns()
            .into_iter()
            .map(|c| hash_column(c))
            .collect::<Vec<Digest>>()
    )
}
