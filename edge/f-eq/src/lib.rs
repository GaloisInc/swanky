#![deny(missing_docs)]
//! Two-party function $`\mathcal{F}_{\mathsf{eq}}`$ that allows parties to check if their inputs are equal in an oblivious manner.
//!
//! In the literature this is typically handled by an ideal functionality $`\mathcal{F}_{\mathsf{eq}}`$ which receives
//! the inputs and return the valuation of the equality check.
//!
//! In practice,
//! 1. Party A and Party B use the same hash function to locally hash their inputs, we
//!    use SHA256 in our implementation. Each party may update their local hash with as
//!    many inputs as they would like: by doing so we batch calls to $`\mathcal{F}_{\mathsf{eq}}`$ so that any one
//!    equality triggers a failure. We do not care about logging which input caused the
//!    failure because any failure is an effect of cheating behavior and the protocol should
//!    terminate.
//! 2. Party A commits to their input by salting it and sends the commitment to Party B.
//!    In our code, SHA256 is updated with a random salt and the salted value is sent over
//!    to Party B.
//! 3. Party B sends their hashed value after receiving A's commitment.
//! 4. Party A may abort at this point. If they behave honestly, they open their commitment and
//!    check the equality. In our code, we decommit by sending the salt to Party B.
//! 5. Party B receives the decommited value and checks the equality (similarly to Party A).
//!
//! This functionality is commonly used in several cryptographic protocols including Garbled Circuits.
//!
//! Notes:
//! 1. Party A can abort after receiving Party B's value.
//! 2. The bashed hashing does not separate values. Meaning that:
//!    $`\mathcal{F}_{\mathsf{eq}}(0x1234 || 0x5678)`$ is the same as $`\mathcal{F}_{\mathsf{eq}}(0x12 || 0x345678)`$.
//!    This is not a concern for our use cases.

use rand::{CryptoRng, RngExt};
use sha2::{Digest, Sha256};
use swanky_channel::Channel;
use swanky_error::ErrorKind;
use swanky_party::{GenericParty, GenericWhichParty, Party0, private::PartyPrivate};

/// The equality functionality.
///
/// See [`crate`] for details.
pub struct EqualityFunctionality<P: GenericParty> {
    hash: Sha256,
    commitment_salt: PartyPrivate<Party0<P>, P, [u8; 32]>,
}

impl<P: GenericParty> EqualityFunctionality<P> {
    /// Create a new [`EqualityFunctionality`].
    pub fn new<RNG>(rng: &mut RNG) -> Self
    where
        RNG: CryptoRng,
    {
        match P::GENERIC_WHICH {
            GenericWhichParty::Party0(_e) => EqualityFunctionality {
                hash: Sha256::new(),
                commitment_salt: PartyPrivate::new(rng.random()),
            },
            GenericWhichParty::Party1(e) => EqualityFunctionality {
                hash: Sha256::new(),
                commitment_salt: PartyPrivate::empty(e),
            },
        }
    }
    /// Add a sequence of bytes to the sequence of values to perform equality on.
    pub fn input<T: AsRef<[u8]>>(&mut self, value: T) {
        self.hash.update(value);
    }
    /// Runs the equality check on all the inputs provided in [`input(&mut self, value: &[u8])`].
    pub fn finalize(self, channel: &mut Channel) -> swanky_error::Result<()> {
        match P::GENERIC_WHICH {
            GenericWhichParty::Party0(e) => {
                // Sender computes the commitment as H(H(value)||salt)
                let mut salted_hash = Sha256::new();
                salted_hash.update(self.hash.finalize());
                salted_hash.update(self.commitment_salt.as_ref().into_inner(e));
                // Sender sends commitment
                let sender_commitment = salted_hash.finalize();
                channel.write_bytes(sender_commitment.as_slice())?;
                // Sender receives receiver_hash
                let receiver_hash: [u8; 32] = channel.read()?;
                // Sender sends the commitment salt as a way to decommit. The sender
                // can abhort and skip this step and this protocol allows that.
                channel.write_bytes(self.commitment_salt.as_ref().into_inner(e))?;
                // The Sender salts the Receiver's value
                let mut receiver_salted = Sha256::new();
                receiver_salted.update(receiver_hash);
                receiver_salted.update(self.commitment_salt.as_ref().into_inner(e));
                // The Sender compares the salted values
                swanky_error::ensure!(
                    sender_commitment == receiver_salted.finalize(),
                    ErrorKind::OtherError,
                    "Validation check failed"
                );
                Ok(())
            }
            GenericWhichParty::Party1(_e) => {
                let hash_receiver = self.hash.finalize();
                // Receiver receives commitment
                let sender_commitment: [u8; 32] = channel.read()?;
                // Receiver sends hash
                channel.write_bytes(hash_receiver.as_slice())?;
                // Receiver receives decommitment
                let sender_salt: [u8; 32] = channel.read()?;
                //The Receiver salts its value
                let mut receiver_salted = Sha256::new();
                receiver_salted.update(hash_receiver);
                receiver_salted.update(sender_salt);
                //The Receiver compares the salted valuesS
                swanky_error::ensure!(
                    sender_commitment == *receiver_salted.finalize(),
                    ErrorKind::OtherError,
                    "Validation check failed"
                );
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use proptest::test_runner::TestRunner;
    use rand::SeedableRng;
    use swanky_party::party_system;
    use swanky_rng::SwankyRng;

    party_system! {
        mod ps {
            PartyA,
            PartyB,
        }
    }
    use ps::{PartyA, PartyB};

    fn check_equality(input_pr: &[u8], input_vr: &[u8]) -> swanky_error::Result<()> {
        swanky_channel::local::local_channel_pair(
            |c| {
                let mut rng = SwankyRng::new();
                let mut f_eq = EqualityFunctionality::<PartyA>::new(&mut rng);
                f_eq.input(input_pr);
                f_eq.finalize(c)
            },
            |c| {
                let mut rng = SwankyRng::new();
                let mut f_eq = EqualityFunctionality::<PartyB>::new(&mut rng);
                f_eq.input(input_vr);
                f_eq.finalize(c)
            },
        )?;
        Ok(())
    }

    fn batched_check_equality(
        inputs_pr: &[[u8; 32]],
        inputs_vr: &[[u8; 32]],
    ) -> swanky_error::Result<()> {
        swanky_channel::local::local_channel_pair(
            |c| {
                let mut rng = SwankyRng::new();
                let mut f_eq = EqualityFunctionality::<PartyA>::new(&mut rng);
                for input_pr in inputs_pr.iter() {
                    f_eq.input(input_pr);
                }
                f_eq.finalize(c)
            },
            |c| {
                let mut rng = SwankyRng::new();
                let mut f_eq = EqualityFunctionality::<PartyB>::new(&mut rng);
                for input_vr in inputs_vr.iter() {
                    f_eq.input(input_vr);
                }
                f_eq.finalize(c)
            },
        )?;
        Ok(())
    }

    proptest! {
        #[test]
        fn same_inputs_work(input in any::<[u8; 32]>()) {
            let res = check_equality(&input, &input);
            prop_assert!(res.is_ok());
        }
    }

    #[test]
    fn different_inputs_fail() {
        let mut runner = TestRunner::default();
        runner
            .run(
                &(any::<[u8; 32]>(), any::<[u8; 32]>()),
                |(input_pr, input_vr)| {
                    let res = check_equality(&input_pr, &input_vr);
                    prop_assert!(res.is_err());
                    Ok(())
                },
            )
            .unwrap();
    }
    proptest! {
        #[test]
        fn batched_same_inputs_work(ninputs in 1..10, seed in any::<u128>()) {
            let mut rng = SwankyRng::from_seed(seed.into());
            let inputs: Vec<[u8; 32]> = (0..ninputs).map(|_| rng.random::<[u8; 32]>()).collect();
            let res = batched_check_equality(&inputs, &inputs);
            prop_assert!(res.is_ok());
        }
    }
    proptest! {
        #[test]
        fn batched_different_inputs_fail(ninputs in 1..10, seed in any::<u128>()) {
            let mut rng = SwankyRng::from_seed(seed.into());
            let inputs_pr: Vec<[u8; 32]> = (0..ninputs).map(|_| rng.random::<[u8; 32]>()).collect();
            let inputs_vr: Vec<[u8; 32]> = (0..ninputs).map(|_| rng.random::<[u8; 32]>()).collect();
            let res = batched_check_equality(&inputs_pr, &inputs_vr);
            prop_assert!(res.is_err());
        }
    }
}
