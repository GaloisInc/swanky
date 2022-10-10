//! A trait defining a Commitment Scheme and an implementation in the random
//! oracle model using SHA256.
//!
//! # Usage
//! ```rust
//! use crate::scuttlebutt::commitment::{Commitment, ShaCommitment};
//!
//! // define a seed
//! let seed = [0u8; 32];
//!
//! // create a commitment object
//! let mut commit = ShaCommitment::new(seed);
//!
//! // write input messages
//! commit.input(b"hello ");
//! commit.input(b"world");
//!
//! // finish commitment
//! let commitment = commit.finish();
//!
//! // check a commitment
//! let seed = [0u8; 32];
//! let msg = b"hello world";
//! let mut commit_ = ShaCommitment::new(seed);
//! commit_.input(msg);
//! let commitment_ = commit_.finish();
//!
//! assert!(ShaCommitment::check(&commitment,&commitment_));
//! ```

use sha2::{Digest, Sha256};

/// Generic commitment scheme.
pub trait Commitment {
    /// The type used to initialize a commitment.
    type Seed;
    /// The output type of the commitment.
    type Output;

    /// A new commitment initialized with `seed`.
    fn new(seed: Self::Seed) -> Self;
    /// A method to add data to the commitment.
    fn input(&mut self, input: &[u8]);
    /// Complete the commitment.
    fn finish(self) -> Self::Output;
    /// Check if two commitments are equal.
    fn check(comm1: &Self::Output, comm2: &Self::Output) -> bool;
}

/// A commitment in the random oracle model using SHA256.
pub struct ShaCommitment {
    /// The seed used to initialize the commitment.
    pub seed: [u8; 32],
    commit: Sha256,
}

impl Commitment for ShaCommitment {
    type Seed = [u8; 32];
    type Output = [u8; 32];

    fn new(seed: Self::Seed) -> Self {
        let commit = Sha256::new();
        Self { seed, commit }
    }

    fn input(&mut self, input: &[u8]) {
        self.commit.update(input);
    }

    fn finish(mut self) -> [u8; 32] {
        self.commit.update(&self.seed);
        let mut a = [0u8; 32];
        a.copy_from_slice(&self.commit.finalize());
        a
    }

    fn check(comm1: &Self::Output, comm2: &Self::Output) -> bool {
        comm1 == comm2
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    #[test]
    fn commit_hello_world() {
        let mut commit = ShaCommitment::new([0u8; 32]);
        commit.input(b"Hello ");
        commit.input(b"world!");

        let result = commit.finish();

        assert_eq!(
            hex::encode(result),
            "9652d7ad97478403f26e4a9e64eaee024b9c75fe9e699a6a2e3f1b85d40d1c0d"
        );
    }

    #[test]
    fn commit_check() {
        // define a seed
        let seed: _ = rand::thread_rng().gen::<[u8; 32]>();
        let mut seed_ = [0u8; 32];
        seed_.copy_from_slice(&seed);

        // create a commitment object
        let mut commit = ShaCommitment::new(seed);

        // write input messages
        commit.input(b"hello ");
        commit.input(b"world");

        // finish commitment
        let commitment = commit.finish();

        // check a commitment
        let msg = b"hello world";
        let mut commit_ = ShaCommitment::new(seed_);
        commit_.input(msg);
        let commitment_ = commit_.finish();

        assert!(ShaCommitment::check(&commitment, &commitment_));
    }
}
