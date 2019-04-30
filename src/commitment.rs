use sha2::{Sha256,Digest};

pub trait Commitment {
    type Seed;
    type Output;

    fn new(seed: Self::Seed) -> Self;
    fn input(&mut self, input: &[u8]) -> ();
    fn finish(self) -> Self::Output;
    fn check(comm1: &Self::Output, comm2: &Self::Output) -> bool;
}

pub struct OracleCommitment  {
    pub seed: Vec<u8>,
    commit: Sha256,
}

impl Commitment for OracleCommitment {
    type Seed = Vec<u8>;
    type Output = [u8; 32];

    fn new(seed: Vec<u8>) -> Self {
        let mut commit = Sha256::new();
        commit.input(&seed);

        OracleCommitment { seed, commit }
    }

    fn input(&mut self, input: &[u8]) {
        self.commit.input(input);
    }

    fn finish(self) -> [u8; 32] {
        let mut a = [0u8; 32];
        a.copy_from_slice(&self.commit.result());
        a
    }

    fn check(comm1: &[u8; 32], comm2: &[u8; 32]) -> bool {
        comm1 == comm2
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_hello_world() {
        let mut commit = OracleCommitment::new(b"hello".to_vec());
        commit.input(b" world");
        
        let result = commit.finish();
        println!("{:?}", result);
        
        assert_eq!(hex::encode(result), "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
    }

}


