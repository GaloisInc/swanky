//! Authenticated shares.
//!
//! An authenticated share $`\langle x \rangle := \langle x_1 | x_2 \rangle`$
//! is a pair of authenticated bits $`[x_1]_A`$, $`[x_2]_B`$, where $`[x_1]_A`$
//! denotes that $`[x_1]`$ is an authenticated bit held by Party A, and likewise,
//! $`[x_2]_B`$ is an authenticated bit held by Party B. We define $`x = x_1
//! \oplus x_2`$.
//!
//! This module provides authenticated shares through the [`AuthShare`] type,
//! alongside [`AuthShareGenerator`] for generating such shares.
//!
//! # Details
//!
//! [`AuthShare`]s are simply pairs of [`AuthBit`]s where each party plays the
//! role of the prover for one of the bits, and verifier for the other.
//!
//! # Example
//!
//! ```
//! # use rand::Rng;
//! # use swanky_authenticated_bits::authshares::{AuthShare, AuthShareGenerator};
//! # use swanky_field_binary::F2;
//! # use swanky_party::party_system;
//! # party_system! {
//! #     mod ps {
//! #         PartyA,
//! #         PartyB,
//! #     }
//! # }
//! # use ps::{PartyA, PartyB};
//! # fn main() -> swanky_error::Result<()> {
//! let nshares = 1000;
//! let (bits_a, bits_b) = swanky_channel::local::local_channel_pair(
//!     |c| {
//!         // Party A (the prover).
//!         let mut rng = swanky_rng::SwankyRng::new();
//!         let mut authshares: Vec<AuthShare<PartyA>> = vec![];
//!         let mut bits: Vec<F2> = vec![];
//!         let mut generator: AuthShareGenerator<_> = AuthShareGenerator::new(c, &mut rng)?;
//!         generator.generate(nshares, &mut authshares, c, &mut rng)?;
//!         generator.open(&authshares, &mut bits, c)?;
//!         Ok(bits)
//!     },
//!     |c| {
//!         // Party B (the verifier).
//!         let mut rng = swanky_rng::SwankyRng::new();
//!         let mut authshares: Vec<AuthShare<PartyB>> = vec![];
//!         let mut bits: Vec<F2> = vec![];
//!         let mut generator: AuthShareGenerator<_> = AuthShareGenerator::new(c, &mut rng)?;
//!         generator.generate(nshares, &mut authshares, c, &mut rng)?;
//!         generator.open(&authshares, &mut bits, c)?;
//!         Ok(bits)
//!     }
//! )?;
//! assert_eq!(bits_a, bits_b);
//! # Ok(())
//! # }
//! ```

use crate::authbits::{AuthBit, AuthBitGenerator};
use rand::{CryptoRng, RngExt};
use std::{iter::Copied, slice::Iter};
use swanky_channel::Channel;
use swanky_field::FiniteRing;
use swanky_field_binary::F2;
use swanky_party::{
    GenericParty, GenericWhichParty, Party0, Party1,
    either::{PartyEither, PartyEitherCopy},
    private::{PartyPrivate, PartyPrivateCopy},
    ty_eq::Witness,
};
use vectoreyes::U8x16;

/// An authenticated share.
///
/// See [`crate::authshares`] for details. [`AuthShare`]s can be generated using
/// [`AuthShareGenerator`].
#[derive(Clone, Copy, Default)]
pub struct AuthShare<P: GenericParty> {
    /// Party A's side of the authenticated share.
    party_a: PartyEitherCopy<P, AuthBit<Party0<P>>, AuthBit<Party1<P>>>,
    /// Party B's side of the authenticated share.
    party_b: PartyEitherCopy<P, AuthBit<Party1<P>>, AuthBit<Party0<P>>>,
}

impl<P: GenericParty> AuthShare<P> {
    /// The given party's bit.
    ///
    /// This corresponds to $`x_1`$ for Party A (the prover), and $`x_2`$
    /// for Party B (the verifier).
    pub fn bit(self) -> F2 {
        match P::GENERIC_WHICH {
            GenericWhichParty::Party0(ev) => self
                .party_a
                .into_inner(ev)
                .bit()
                .into_inner(Witness::EQUAL_TYPES),
            GenericWhichParty::Party1(ev) => self
                .party_b
                .into_inner(ev)
                .bit()
                .into_inner(Witness::EQUAL_TYPES),
        }
    }

    /// The given party's key.
    ///
    /// This corresponds to $`K[x_2]`$ for Party A (the prover), and
    /// $`K[x_1]`$ for Party B (the verifier).
    pub fn key(self) -> U8x16 {
        match P::GENERIC_WHICH {
            GenericWhichParty::Party0(ev) => self
                .party_b
                .into_inner(ev)
                .key()
                .into_inner(Witness::EQUAL_TYPES),
            GenericWhichParty::Party1(ev) => self
                .party_a
                .into_inner(ev)
                .key()
                .into_inner(Witness::EQUAL_TYPES),
        }
    }

    /// The given party's MAC.
    ///
    /// This corresponds to $`M[x_1]`$ for Party A, and
    /// $`M[x_2]`$ for Party B.
    pub fn mac(self) -> U8x16 {
        match P::GENERIC_WHICH {
            GenericWhichParty::Party0(ev) => self
                .party_a
                .into_inner(ev)
                .mac()
                .into_inner(Witness::EQUAL_TYPES),
            GenericWhichParty::Party1(ev) => self
                .party_b
                .into_inner(ev)
                .mac()
                .into_inner(Witness::EQUAL_TYPES),
        }
    }

    /// Compute $`c \cdot \langle x \rangle`$, where $`c`$ is a public constant.
    pub fn mul_with_const(self, constant: F2) -> Self {
        Self {
            party_a: self.party_a.map(
                |authbit| authbit.mul_with_const(constant),
                |authbit| authbit.mul_with_const(constant),
            ),
            party_b: self.party_b.map(
                |authbit| authbit.mul_with_const(constant),
                |authbit| authbit.mul_with_const(constant),
            ),
        }
    }
}

impl<P: GenericParty> core::ops::BitXor for AuthShare<P> {
    type Output = Self;
    fn bitxor(self, rhs: Self) -> Self::Output {
        AuthShare {
            party_a: self
                .party_a
                .zip(rhs.party_a)
                .map(|(lhs, rhs)| lhs ^ rhs, |(lhs, rhs)| lhs ^ rhs),
            party_b: self
                .party_b
                .zip(rhs.party_b)
                .map(|(lhs, rhs)| lhs ^ rhs, |(lhs, rhs)| lhs ^ rhs),
        }
    }
}

/// A type for generating [`AuthShare`]s.
pub struct AuthShareGenerator<P: GenericParty> {
    party_a: PartyEither<P, AuthBitGenerator<Party0<P>>, AuthBitGenerator<Party1<P>>>,
    party_b: PartyEither<P, AuthBitGenerator<Party1<P>>, AuthBitGenerator<Party0<P>>>,
}

impl<P: GenericParty> AuthShareGenerator<P> {
    /// Create a new [`AuthShareGenerator`].
    pub fn new<RNG: CryptoRng>(channel: &mut Channel, mut rng: RNG) -> swanky_error::Result<Self> {
        let delta = rng.random::<U8x16>();
        Self::new_with_delta(delta, channel, rng)
    }

    /// Create a new [`AuthShareGenerator`] with a supplied $`\Delta`$ value.
    pub fn new_with_delta<RNG: CryptoRng>(
        delta: U8x16,
        channel: &mut Channel,
        mut rng: RNG,
    ) -> swanky_error::Result<Self> {
        match P::GENERIC_WHICH {
            GenericWhichParty::Party0(ev) => {
                let party_a = AuthBitGenerator::<Party0<P>>::new(channel, &mut rng)?;
                let party_b = AuthBitGenerator::<Party1<P>>::new_with_delta(
                    PartyPrivateCopy::new(delta),
                    channel,
                    &mut rng,
                )?;
                Ok(AuthShareGenerator {
                    party_a: PartyEither::new(ev, party_a),
                    party_b: PartyEither::new(ev, party_b),
                })
            }
            GenericWhichParty::Party1(ev) => {
                let party_a = AuthBitGenerator::<Party1<P>>::new_with_delta(
                    PartyPrivateCopy::new(delta),
                    channel,
                    &mut rng,
                )?;
                let party_b = AuthBitGenerator::<Party0<P>>::new(channel, &mut rng)?;
                Ok(AuthShareGenerator {
                    party_a: PartyEither::new(ev, party_a),
                    party_b: PartyEither::new(ev, party_b),
                })
            }
        }
    }

    /// Generate a vector of authenticated shares.
    ///
    /// The `nshares` generated shares are [`Vec::extend`]ed into `shares`.
    pub fn generate<RNG: CryptoRng>(
        &mut self,
        nshares: usize,
        shares: &mut Vec<AuthShare<P>>,
        channel: &mut Channel,
        rng: &mut RNG,
    ) -> swanky_error::Result<()> {
        let bits: Vec<_> = (0..nshares).map(|_| rng.random::<F2>()).collect();

        let mut party_a_auth_bits = Vec::with_capacity(nshares);
        let mut party_b_auth_bits = Vec::with_capacity(nshares);

        let bits = PartyEither::new(Witness::EQUAL_TYPES, bits.iter().copied());
        let nshares: PartyEither<_, Copied<Iter<'_, F2>>, _> =
            PartyEither::new(Witness::EQUAL_TYPES, nshares);
        match P::GENERIC_WHICH {
            GenericWhichParty::Party0(ev) => {
                let party_a = self.party_a.as_mut().into_inner(ev);
                let party_b = self.party_b.as_mut().into_inner(ev);

                party_a.generate(bits, &mut party_a_auth_bits, channel, rng)?;
                party_b.generate(nshares, &mut party_b_auth_bits, channel, rng)?;

                shares.extend(party_a_auth_bits.into_iter().zip(party_b_auth_bits).map(
                    |(party_a_val, party_b_val)| AuthShare {
                        party_a: PartyEitherCopy::new(ev, party_a_val),
                        party_b: PartyEitherCopy::new(ev, party_b_val),
                    },
                ));
            }
            GenericWhichParty::Party1(ev) => {
                let party_a = self.party_a.as_mut().into_inner(ev);
                let party_b = self.party_b.as_mut().into_inner(ev);

                party_a.generate(nshares, &mut party_b_auth_bits, channel, rng)?;
                party_b.generate(bits, &mut party_a_auth_bits, channel, rng)?;

                shares.extend(party_a_auth_bits.into_iter().zip(party_b_auth_bits).map(
                    |(party_a_val, party_b_val)| AuthShare {
                        party_a: PartyEitherCopy::new(ev, party_b_val),
                        party_b: PartyEitherCopy::new(ev, party_a_val),
                    },
                ));
            }
        }
        Ok(())
    }

    /// Open the authenticated shares in `shares`.
    ///
    /// This corresponds to opening all the authenticated bits that make up the
    /// authenticated shares. The resulting opened combined shares are
    /// [`Vec::push`]ed to `outputs`.
    pub fn open(
        &self,
        shares: &[AuthShare<P>],
        outputs: &mut Vec<F2>,
        channel: &mut Channel,
    ) -> swanky_error::Result<()> {
        AuthShareGenerator::open_with_delta(shares, self.delta(), outputs, channel)
    }

    /// Open the authenticated shares in `shares` using a supplied $`\Delta`$
    /// value.
    ///
    /// See [`AuthShareGenerator::open`] for details.
    pub fn open_with_delta(
        shares: &[AuthShare<P>],
        delta: U8x16,
        outputs: &mut Vec<F2>,
        channel: &mut Channel,
    ) -> swanky_error::Result<()> {
        // We only want to use the bits that are added to `outputs`, so we grab the
        // initial length here and use it to avoid touching anything already
        // existing in `outputs`.
        let output_starting_len = outputs.len();
        let (party_a_shares, party_b_shares): (Vec<_>, Vec<_>) = shares
            .iter()
            .map(|authshare| (authshare.party_a, authshare.party_b))
            .unzip();
        match P::GENERIC_WHICH {
            GenericWhichParty::Party0(ev) => {
                let party_a_shares =
                    PartyEitherCopy::pull_either_outside(&party_a_shares).into_inner(ev);
                AuthBitGenerator::open_with_delta(
                    party_a_shares,
                    PartyPrivateCopy::empty(Witness::EQUAL_TYPES),
                    PartyPrivate::empty(Witness::EQUAL_TYPES),
                    channel,
                )?;
                let party_b_shares =
                    PartyEitherCopy::pull_either_outside(&party_b_shares).into_inner(ev);
                AuthBitGenerator::open_with_delta(
                    party_b_shares,
                    PartyPrivateCopy::new(delta),
                    PartyPrivate::new(outputs),
                    channel,
                )?;
                for (bit_a, bit_b) in party_a_shares
                    .iter()
                    .zip(outputs[output_starting_len..].iter_mut())
                {
                    *bit_b += bit_a.bit().into_inner(Witness::EQUAL_TYPES);
                }
            }
            GenericWhichParty::Party1(ev) => {
                let party_a_shares =
                    PartyEitherCopy::pull_either_outside(&party_a_shares).into_inner(ev);
                AuthBitGenerator::open_with_delta(
                    party_a_shares,
                    PartyPrivateCopy::new(delta),
                    PartyPrivate::new(outputs),
                    channel,
                )?;
                let party_b_shares =
                    PartyEitherCopy::pull_either_outside(&party_b_shares).into_inner(ev);
                AuthBitGenerator::open_with_delta(
                    party_b_shares,
                    PartyPrivateCopy::empty(Witness::EQUAL_TYPES),
                    PartyPrivate::empty(Witness::EQUAL_TYPES),
                    channel,
                )?;
                for (bit_a, bit_b) in outputs[output_starting_len..]
                    .iter_mut()
                    .zip(party_b_shares.iter())
                {
                    *bit_a += bit_b.bit().into_inner(Witness::EQUAL_TYPES);
                }
            }
        }
        Ok(())
    }

    /// Open this party's shares.
    ///
    /// This reveals _this_ party's shares to the other party.
    pub fn open_my_shares(
        shares: &[AuthShare<P>],
        channel: &mut Channel,
    ) -> swanky_error::Result<()> {
        match P::GENERIC_WHICH {
            GenericWhichParty::Party0(ev) => AuthBitGenerator::open_with_delta(
                &shares
                    .iter()
                    .map(|share| share.party_a.into_inner(ev))
                    .collect::<Vec<_>>(),
                PartyPrivateCopy::empty(Witness::EQUAL_TYPES),
                PartyPrivate::empty(Witness::EQUAL_TYPES),
                channel,
            ),
            GenericWhichParty::Party1(ev) => AuthBitGenerator::open_with_delta(
                &shares
                    .iter()
                    .map(|share| share.party_b.into_inner(ev))
                    .collect::<Vec<_>>(),
                PartyPrivateCopy::empty(Witness::EQUAL_TYPES),
                PartyPrivate::empty(Witness::EQUAL_TYPES),
                channel,
            ),
        }
    }

    /// Open the other party's shares.
    ///
    /// This reveals the other party's shares to _this_ party.
    pub fn open_their_shares(
        &self,
        shares: &[AuthShare<P>],
        outputs: &mut Vec<F2>,
        channel: &mut Channel,
    ) -> swanky_error::Result<()> {
        AuthShareGenerator::open_their_shares_with_delta(shares, self.delta(), outputs, channel)
    }

    /// Open the other party's shares using a supplied $`\Delta`$ value.
    ///
    /// See [`AuthShareGenerator::open_their_shares`] for details.
    pub fn open_their_shares_with_delta(
        shares: &[AuthShare<P>],
        delta: U8x16,
        outputs: &mut Vec<F2>,
        channel: &mut Channel,
    ) -> swanky_error::Result<()> {
        match P::GENERIC_WHICH {
            GenericWhichParty::Party0(ev) => AuthBitGenerator::open_with_delta(
                &shares
                    .iter()
                    .map(|share| share.party_b.into_inner(ev))
                    .collect::<Vec<_>>(),
                PartyPrivateCopy::new(delta),
                PartyPrivate::new(outputs),
                channel,
            ),
            GenericWhichParty::Party1(ev) => AuthBitGenerator::open_with_delta(
                &shares
                    .iter()
                    .map(|share| share.party_a.into_inner(ev))
                    .collect::<Vec<_>>(),
                PartyPrivateCopy::new(delta),
                PartyPrivate::new(outputs),
                channel,
            ),
        }
    }

    /// The $`\Delta`$ value used to validate the other party's share.
    pub fn delta(&self) -> U8x16 {
        match P::GENERIC_WHICH {
            GenericWhichParty::Party0(ev) => self
                .party_b
                .as_ref()
                .into_inner(ev)
                .delta()
                .into_inner(Witness::EQUAL_TYPES),
            GenericWhichParty::Party1(ev) => self
                .party_a
                .as_ref()
                .into_inner(ev)
                .delta()
                .into_inner(Witness::EQUAL_TYPES),
        }
    }

    /// Compute $`\langle x \rangle \oplus c`$, where $`c`$ is a public
    /// constant.
    ///
    /// This works by computing $`[x_2]_B \oplus c`$, where $`[x_2]_B`$ is the
    /// authenticated bit held by Party B.
    pub fn xor_with_const(&self, authshare: AuthShare<P>, bit: F2) -> AuthShare<P> {
        Self::xor_with_const_with_delta(authshare, bit, self.delta())
    }

    /// Compute $`\langle x \rangle \oplus c`$, where $`c`$ is a public
    /// constant, using a supplied $`\Delta`$ value.
    ///
    /// See [`AuthShareGenerator::xor_with_const`] for details.
    pub fn xor_with_const_with_delta(
        authshare: AuthShare<P>,
        bit: F2,
        delta: U8x16,
    ) -> AuthShare<P> {
        match P::GENERIC_WHICH {
            GenericWhichParty::Party0(ev) => AuthShare {
                party_a: authshare.party_a,
                party_b: PartyEitherCopy::new(
                    ev,
                    AuthBitGenerator::xor_with_const_with_delta(
                        authshare.party_b.into_inner(ev),
                        bit,
                        PartyPrivateCopy::new(delta),
                    ),
                ),
            },
            GenericWhichParty::Party1(ev) => AuthShare {
                party_a: authshare.party_a,
                party_b: PartyEitherCopy::new(
                    ev,
                    AuthBitGenerator::xor_with_const_with_delta(
                        authshare.party_b.into_inner(ev),
                        bit,
                        PartyPrivateCopy::new(delta),
                    ),
                ),
            },
        }
    }

    /// Compute $`\langle c \rangle`$, where $`c`$ is a public constant.
    ///
    /// This sets one party's share to $`c`$, and the other party's share to 0.
    pub fn constant(&self, constant: F2) -> AuthShare<P> {
        AuthShareGenerator::constant_with_delta(constant, self.delta())
    }

    /// Compute $`\langle c \rangle`$, where $`c`$ is a public constant, using
    /// the supplied $`\Delta`$ value.
    ///
    /// See [`AuthShareGenerator::constant`] for details.
    pub fn constant_with_delta(constant: F2, delta: U8x16) -> AuthShare<P> {
        match P::GENERIC_WHICH {
            GenericWhichParty::Party0(ev) => AuthShare {
                party_a: PartyEitherCopy::new(
                    ev,
                    AuthBitGenerator::constant_with_delta(
                        constant,
                        PartyPrivateCopy::empty(Witness::EQUAL_TYPES),
                    ),
                ),
                party_b: PartyEitherCopy::new(
                    ev,
                    AuthBitGenerator::constant_with_delta(F2::ZERO, PartyPrivateCopy::new(delta)),
                ),
            },
            GenericWhichParty::Party1(ev) => AuthShare {
                party_a: PartyEitherCopy::new(
                    ev,
                    AuthBitGenerator::constant_with_delta(constant, PartyPrivateCopy::new(delta)),
                ),
                party_b: PartyEitherCopy::new(
                    ev,
                    AuthBitGenerator::constant_with_delta(
                        F2::ZERO,
                        PartyPrivateCopy::empty(Witness::EQUAL_TYPES),
                    ),
                ),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
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

    fn generators(
        mut rng_a: &mut SwankyRng,
        mut rng_b: &mut SwankyRng,
    ) -> (AuthShareGenerator<PartyA>, AuthShareGenerator<PartyB>) {
        swanky_channel::local::local_channel_pair(
            |c| AuthShareGenerator::<PartyA>::new(c, &mut rng_a),
            |c| AuthShareGenerator::<PartyB>::new(c, &mut rng_b),
        )
        .unwrap()
    }

    /// Generates `AuthShare`s.
    fn generate(
        nshares: usize,
        generator_a: &mut AuthShareGenerator<PartyA>,
        generator_b: &mut AuthShareGenerator<PartyB>,
        mut rng_a: &mut SwankyRng,
        mut rng_b: &mut SwankyRng,
    ) -> (Vec<AuthShare<PartyA>>, Vec<AuthShare<PartyB>>) {
        let mut output_a: Vec<AuthShare<PartyA>> = vec![];
        let mut output_b: Vec<AuthShare<PartyB>> = vec![];
        swanky_channel::local::local_channel_pair(
            |c| generator_a.generate(nshares, &mut output_a, c, &mut rng_a),
            |c| generator_b.generate(nshares, &mut output_b, c, &mut rng_b),
        )
        .unwrap();
        (output_a, output_b)
    }

    /// Open vectors of `AuthShare`s using their associated generators.
    fn open(
        generator_a: &AuthShareGenerator<PartyA>,
        generator_b: &AuthShareGenerator<PartyB>,
        output_a: Vec<AuthShare<PartyA>>,
        output_b: Vec<AuthShare<PartyB>>,
    ) -> ((bool, Vec<F2>), (bool, Vec<F2>)) {
        swanky_channel::local::local_channel_pair(
            |c| {
                let mut outputs = vec![];
                let result = generator_a.open(&output_a, &mut outputs, c);
                Ok((result.is_ok(), outputs))
            },
            |c| {
                let mut outputs = vec![];
                let result = generator_b.open(&output_b, &mut outputs, c);
                Ok((result.is_ok(), outputs))
            },
        )
        .unwrap()
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn honest_generation_works(nshares in 1..1000usize,
                                   seed_party_a in any::<u128>(), seed_party_b in any::<u128>()) {
            let mut rng_a = SwankyRng::from_seed(seed_party_a.into());
            let mut rng_b = SwankyRng::from_seed(seed_party_b.into());
            let (mut generator_a, mut generator_b) = generators(&mut rng_a, &mut rng_b);
            let (output_a, output_b) = generate(nshares, &mut generator_a, &mut generator_b, &mut rng_a, &mut rng_b);
            let ((validation_a, _), (validation_b, _)) = open(&generator_a, &generator_b, output_a, output_b);
            prop_assert!(validation_a);
            prop_assert!(validation_b);
        }
    }

    #[test]
    fn honest_generation_opening_each_share_works() {
        let nshares = 1000usize;
        let mut rng_a = SwankyRng::new();
        let mut rng_b = SwankyRng::new();
        let (mut generator_a, mut generator_b) = generators(&mut rng_a, &mut rng_b);
        let (shares_a, shares_b) = generate(
            nshares,
            &mut generator_a,
            &mut generator_b,
            &mut rng_a,
            &mut rng_b,
        );
        let (output_bits_a, output_bits_b) = swanky_channel::local::local_channel_pair(
            |channel| {
                AuthShareGenerator::open_my_shares(&shares_a, channel).unwrap();

                let mut outputs = vec![];
                generator_a
                    .open_their_shares(&shares_a, &mut outputs, channel)
                    .unwrap();
                Ok(outputs)
            },
            |channel| {
                let mut outputs = vec![];
                generator_b
                    .open_their_shares(&shares_b, &mut outputs, channel)
                    .unwrap();

                AuthShareGenerator::open_my_shares(&shares_b, channel).unwrap();
                Ok(outputs)
            },
        )
        .unwrap();

        let ((result_a, outputs_a), (result_b, outputs_b)) =
            open(&generator_a, &generator_b, shares_a, shares_b);
        assert!(result_a);
        assert!(result_b);
        for ((c, c_), (a, b)) in outputs_a
            .into_iter()
            .zip(outputs_b)
            .zip(output_bits_a.into_iter().zip(output_bits_b))
        {
            // The outputs for each party from `AuthShareGenerator::open` should
            // be the same.
            assert_eq!(c, c_);
            // The outputs from `AuthShareGenerator::open` should be equal to
            // each party's opened share XORed together.
            assert_eq!(c, a + b);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn wrong_output_fails(nshares in 1..1000usize,
                              seed_party_a in any::<u128>(), seed_party_b in any::<u128>()) {
            let mut rng_a = SwankyRng::from_seed(U8x16::from(seed_party_a));
            let mut rng_b = SwankyRng::from_seed(U8x16::from(seed_party_b));
            let (mut generator_a, mut generator_b) = generators(&mut rng_a, &mut rng_b);
            let (output_a, _) = generate(nshares, &mut generator_a, &mut generator_b, &mut rng_a, &mut rng_b);
            let (_, output_d) = generate(nshares, &mut generator_a, &mut generator_b, &mut rng_a, &mut rng_b);
            let ((validation_a, _), (validation_b, _)) = open(&generator_a, &generator_b, output_a, output_d);
            prop_assert!(!validation_a);
            prop_assert!(!validation_b);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn tampered_party_b_share_fails(nshares in 1..1000usize, index in any::<proptest::sample::Index>(),
                                        seed_party_a in any::<u128>(), seed_party_b in any::<u128>()) {
            let mut rng_a = SwankyRng::from_seed(U8x16::from(seed_party_a));
            let mut rng_b = SwankyRng::from_seed(U8x16::from(seed_party_b));
            let index = index.index(nshares);
            let (mut generator_a, mut generator_b) = generators(&mut rng_a, &mut rng_b);
            let (output_a, mut output_b) = generate(nshares, &mut generator_a, &mut generator_b, &mut rng_a, &mut rng_b);
            let (_, output_d) = generate(nshares, &mut generator_a, &mut generator_b, &mut rng_a, &mut rng_b);
            output_b[index] = output_d[index];
            let ((validation_a, _), (validation_b, _)) = open(&generator_a, &generator_b, output_a, output_b);
            prop_assert!(!validation_a);
            prop_assert!(!validation_b);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn tampered_party_a_share_fails(nshares in 1..1000usize, index in any::<proptest::sample::Index>(),
                                        seed_party_a in any::<u128>(), seed_party_b in any::<u128>()) {
            let mut rng_a = SwankyRng::from_seed(U8x16::from(seed_party_a));
            let mut rng_b = SwankyRng::from_seed(U8x16::from(seed_party_b));
            let index = index.index(nshares);
            let (mut generator_a, mut generator_b) = generators(&mut rng_a, &mut rng_b);
            let (mut output_a, output_b) = generate(nshares, &mut generator_a, &mut generator_b, &mut rng_a, &mut rng_b);
            let (output_c, _) = generate(nshares, &mut generator_a, &mut generator_b, &mut rng_a, &mut rng_b);
            output_a[index] = output_c[index];
            let ((validation_a, _), (validation_b, _)) = open(&generator_a, &generator_b, output_a, output_b);
            prop_assert!(!validation_a);
            prop_assert!(!validation_b);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn xor_with_const_works(constants in proptest::collection::vec(any::<bool>(), 1..1000),
                                seed_party_a in any::<u128>(), seed_party_b in any::<u128>()) {
            let mut rng_a = SwankyRng::from_seed(U8x16::from(seed_party_a));
            let mut rng_b = SwankyRng::from_seed(U8x16::from(seed_party_b));
            let constants: Vec<F2> = constants.into_iter().map(F2::from).collect();
            let count = constants.len();
            let (mut generator_a, mut generator_b) = generators(&mut rng_a, &mut rng_b);
            let (output_a, output_b) = generate(count, &mut generator_a, &mut generator_b, &mut rng_a, &mut rng_b);
            for ((a, b), bit) in output_a
                .into_iter()
                .zip(output_b.into_iter())
                .zip(constants)
            {
                let new_a = generator_a.xor_with_const(a, bit);
                let new_b = generator_b.xor_with_const(b, bit);
                // The new authenticated share should still validate.
                let ((validation_a, _), (validation_b, _)) = open(&generator_a, &generator_b, vec![new_a], vec![new_b]);
                prop_assert!(validation_a);
                prop_assert!(validation_b);
                // The new authenticated share should equal `⟨x⟩ ⊕ c`.
                prop_assert_eq!(a.bit() + b.bit() + bit, new_a.bit() + new_b.bit());
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn mul_with_const_works(constants in proptest::collection::vec(any::<bool>(), 1..1000),
                                seed_party_a in any::<u128>(), seed_party_b in any::<u128>()) {
            let mut rng_a = SwankyRng::from_seed(U8x16::from(seed_party_a));
            let mut rng_b = SwankyRng::from_seed(U8x16::from(seed_party_b));
            let constants: Vec<F2> = constants.into_iter().map(F2::from).collect();
            let count = constants.len();
            let (mut generator_a, mut generator_b) = generators(&mut rng_a, &mut rng_b);
            let (output_a, output_b) = generate(count, &mut generator_a, &mut generator_b, &mut rng_a, &mut rng_b);
            for ((a, b), bit) in output_a
                .into_iter()
                .zip(output_b.into_iter())
                .zip(constants)
            {
                let new_a = a.mul_with_const(bit);
                let new_b = b.mul_with_const(bit);
                // The new authenticated share should still validate.
                let ((validation_a, _), (validation_b, _)) = open(&generator_a, &generator_b, vec![new_a], vec![new_b]);
                prop_assert!(validation_a);
                prop_assert!(validation_b);
                // The new authenticated share should equal `c · ⟨x⟩`.
                prop_assert_eq!((a.bit() + b.bit()) * bit, new_a.bit() + new_b.bit());
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn constant_works(constants in proptest::collection::vec(any::<bool>(), 1..1000),
                          seed_party_a in any::<u128>(), seed_party_b in any::<u128>()) {
            let mut rng_a = SwankyRng::from_seed(U8x16::from(seed_party_a));
            let mut rng_b = SwankyRng::from_seed(U8x16::from(seed_party_b));
            let constants: Vec<F2> = constants.into_iter().map(F2::from).collect();
            let (generator_a, generator_b) = generators(&mut rng_a, &mut rng_b);
            for bit in constants {
                let bit_a = generator_a.constant(bit);
                let bit_b = generator_b.constant(bit);
                // The new authenticated share should still validate.
                let ((validation_a, _), (validation_b, _)) = open(&generator_a, &generator_b, vec![bit_a], vec![bit_b]);
                prop_assert!(validation_a);
                prop_assert!(validation_b);
                // The new authenticated share should equal `bit`.
                prop_assert_eq!(bit, bit_a.bit() + bit_b.bit());
            }
        }
    }
}
