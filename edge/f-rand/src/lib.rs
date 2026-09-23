//! Two-party functionality $`\mathcal{F}_{\mathsf{Rand}}`$ for generating
//! unbiased random values.
//!
//! This crate implements a two-party instantiation of the
//! $`\mathcal{F}_{\mathsf{Rand}}`$ functionality as defined below:
//!
//! 1. Upon receiving $`(\mathsf{Rand}, \mathcal{S})`$ from all parties, where
//!    $`\mathcal{S}`$ is some finite set with an efficient sampling algorithm,
//!    output $`r \from_\$ \mathcal{S}`$.
//!
//! There are two instantiations of this functionality. [`random`] allows the
//! generation of a random value of any type `T` that implements
//! [`Distribution`]. [`random_seed`] allows the generation of values of type
//! [`U8x16`], which is more efficient than using [`random`] for `T = U8x16`.
//!
//! # Security
//!
//! The implementation is secure in the random oracle model under the assumption
//! that [Blake3](https://en.wikipedia.org/wiki/BLAKE_(hash_function)#BLAKE3) is
//! indistinguishable from a random oracle.
//!
//! # Round Complexity
//!
//! The protocol requires 1.5 rounds of communication.
#![deny(missing_docs)]

use rand::{CryptoRng, RngExt, SeedableRng, distr::StandardUniform, prelude::Distribution};
use swanky_channel::Channel;
use swanky_error::ErrorKind;
#[cfg(test)]
use swanky_malicious_hooks::{run_with_entry_point, test_entry_point};
use swanky_party::{GenericParty, GenericWhichParty};
use swanky_rng::SwankyRng;
use swanky_serialization::CanonicalSerialize;
use vectoreyes::U8x16;

#[cfg(test)]
/// Entry points used for testing malicious behavior.
mod entry_points {
    use swanky_malicious_hooks::new_entry_point;
    use vectoreyes::U8x16;

    new_entry_point!(PROVER_WRITE_COMMITMENT, [u8; 32]);
    new_entry_point!(PROVER_WRITE_SEED, U8x16);
}

/// Generate a random value of type `T`.
pub fn random<P: GenericParty, T, RNG: CryptoRng>(
    channel: &mut Channel,
    rng: &mut RNG,
) -> swanky_error::Result<T>
where
    StandardUniform: Distribution<T>,
{
    // The protocol works as follows:
    //
    // 1. Run `random_seed` to generate a random seed.
    // 2. Use this to seed a RNG which we then use to generate a random `T`.
    let seed = random_seed::<P, _>(channel, rng)?;
    let mut rng_new = SwankyRng::from_seed(seed);
    Ok(rng_new.random::<T>())
}

/// Generate a random seed (that is, a 128-bit value).
pub fn random_seed<P: GenericParty, RNG: CryptoRng>(
    channel: &mut Channel,
    rng: &mut RNG,
) -> swanky_error::Result<U8x16> {
    // The protocol works as follows:
    //
    // 1. The sender generates its seed `s₀`, computes `c ← H(s₀)`, and sends
    //    `c` to the receiver. Since `s₀` is random we can view `H` as a
    //    commitment scheme (in the random oracle model).
    // 2. The receiver generates its seed `s₁` and sends `s₁` to the sender.
    // 3. The sender sends `s₀` to the receiver, who checks that `H(s₀) = c`,
    //    aborting if not.
    // 4. Both parties output `s₀ ⊕ s₁`.
    let seed_mine = rng.random::<U8x16>();
    let seed = match P::GENERIC_WHICH {
        GenericWhichParty::Party0(_) => {
            let com = *blake3::hash(&seed_mine.to_bytes()).as_bytes();
            #[cfg(test)]
            let com = test_entry_point(com, &entry_points::PROVER_WRITE_COMMITMENT);
            channel.write(&com)?;
            let seed_theirs = channel.read::<U8x16>()?;
            #[cfg(test)]
            let seed_mine = test_entry_point(seed_mine, &entry_points::PROVER_WRITE_SEED);
            channel.write(&seed_mine)?;
            seed_mine ^ seed_theirs
        }
        GenericWhichParty::Party1(_) => {
            let com = channel.read::<[u8; 32]>()?;
            channel.write(&seed_mine)?;
            let seed_theirs = channel.read::<U8x16>()?;
            let com_ = *blake3::hash(&seed_theirs.to_bytes()).as_bytes();
            swanky_error::ensure!(
                com_ == com,
                ErrorKind::OtherError,
                "Commitment check failed"
            );
            seed_mine ^ seed_theirs
        }
    };
    Ok(seed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use swanky_party::party_system;
    use vectoreyes::{SimdBase, array_utils::ArrayUnrolledExt};

    party_system! {
        mod ps {
            PartyA,
            PartyB,
        }
    }
    use ps::{PartyA, PartyB};

    proptest! {
        #[test]
        fn random_seed_works(seed_a in any::<u128>(),
                             seed_b in any::<u128>()) {
            let mut rng_a = SwankyRng::from_seed(seed_a.into());
            let mut rng_b = SwankyRng::from_seed(seed_b.into());
            let (result_a, result_b) = swanky_channel::local::local_channel_pair(
                |c| random_seed::<PartyA, _>(c, &mut rng_a),
                |c| random_seed::<PartyB, _>(c, &mut rng_b),
            )
            .unwrap();
            assert_eq!(result_a, result_b);
        }
    }

    proptest! {
        #[test]
        fn bad_prover_commitment_fails(seed_a in any::<u128>(),
                                       seed_b in any::<u128>()) {
            let mut rng_a = SwankyRng::from_seed(seed_a.into());
            let mut rng_b = SwankyRng::from_seed(seed_b.into());
            let result = swanky_channel::local::local_channel_pair(
                |c| {
                    run_with_entry_point(
                        || random_seed::<PartyA, _>(c, &mut rng_a),
                        |old| old.array_map(|byte| !byte),
                        &entry_points::PROVER_WRITE_COMMITMENT
                    )
                },
                |c| random_seed::<PartyB, _>(c, &mut rng_b),
            );
            assert!(result.is_err());
        }
    }

    proptest! {
        #[test]
        fn bad_prover_decommitment_fails(seed_a in any::<u128>(),
                                         seed_b in any::<u128>()) {
            let mut rng_a = SwankyRng::from_seed(seed_a.into());
            let mut rng_b = SwankyRng::from_seed(seed_b.into());
            let result = swanky_channel::local::local_channel_pair(
                |c| {
                    run_with_entry_point(
                        || random_seed::<PartyA, _>(c, &mut rng_a),
                        |old: U8x16| old.as_array().array_map(|byte| !byte).into(),
                        &entry_points::PROVER_WRITE_SEED,
                    )
                },
                |c| random_seed::<PartyB, _>(c, &mut rng_b),
            );
            assert!(result.is_err());
        }
    }

    proptest! {
        #[test]
        fn random_i32_works(seed_a in any::<u128>(),
                            seed_b in any::<u128>()) {
            let mut rng_a = SwankyRng::from_seed(seed_a.into());
            let mut rng_b = SwankyRng::from_seed(seed_b.into());
            let (result_a, result_b) = swanky_channel::local::local_channel_pair(
                |c| random::<PartyA, i32, _>(c, &mut rng_a),
                |c| random::<PartyB, i32, _>(c, &mut rng_b),
            )
            .unwrap();
            assert_eq!(result_a, result_b);
        }
    }
}
