// -*- mode: rust; -*-
//
// This file is part of `scuttlebutt`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! A trait defining a Commitment Scheme and an implementation in the random
//! oracle model using SHA256.
//!
//! # Usage
//! ```rust
//! use crate::scuttlebutt::commitment::{Commitment, OracleCommitment};
//!
//! // define a seed
//! let seed = b"seed".to_vec();
//!
//! // create a commitment object
//! let mut commit = OracleCommitment::new(seed);
//!
//! // write input messages
//! commit.input(b"hello ");
//! commit.input(b"world");
//!
//! // finish commitment
//! let commitment = commit.finish();
//!
//! // check a commitment
//! let seed = b"seed".to_vec();
//! let msg = b"hello world";
//! let mut commit_ = OracleCommitment::new(seed);
//! commit_.input(msg);
//! let commitment_ = commit_.finish();
//!
//! assert!(OracleCommitment::check(&commitment,&commitment_));
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
    fn input(&mut self, input: &[u8]) -> ();
    /// Complete the commitment.
    fn finish(self) -> Self::Output;
    /// Check if two commitments are equal.
    fn check(comm1: &Self::Output, comm2: &Self::Output) -> bool;
}

/// A commitment in the random oracle model using SHA256.
pub struct OracleCommitment {
    /// The seed used to initialize the commitment.
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

        assert_eq!(
            hex::encode(result),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn commit_check() {
        // define a seed
        let seed = b"seed".to_vec();

        // create a commitment object
        let mut commit = OracleCommitment::new(seed);

        // write input messages
        commit.input(b"hello ");
        commit.input(b"world");

        // finish commitment
        let commitment = commit.finish();

        // check a commitment
        let seed = b"seed".to_vec();
        let msg = b"hello world";
        let mut commit_ = OracleCommitment::new(seed);
        commit_.input(msg);
        let commitment_ = commit_.finish();

        assert!(OracleCommitment::check(&commitment, &commitment_));
    }
}
