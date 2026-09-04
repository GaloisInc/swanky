//! Authenticated bits.
//!
//! See [`crate`] for a high-level description of authenticated bits. This
//! module provides the [`AuthBit`] type, which represents an authenticated bit,
//! alongside the [`AuthBitGenerator`] type, which provides a means for
//! generating a vector of [`AuthBit`]s.
//!
//! # Details
//!
//! The protocol is briefly described by Nielsen et al. [^1] in Section 3.1, but
//! essentially, authenticated bits are _just_ the outputs of correlated
//! oblivious transfer (called Δ-ROT in the paper).
//!
//! In more detail, to generate [`AuthBit`]s, the prover holds a vector of bits
//! $`b_i`$ of length $`n`$, and the verifier holds a long term key $`\Delta`$.
//!
//! The prover and verifier perform a Δ-ROT per bit so that the prover receives
//! $`M_i := K_i \oplus b_i \Delta`$ and the verifier receives $`K_i`$. In other
//! words:
//!
//! - If $`b_i = 1`$, the prover receives $`M_{i,1} := K_i \oplus \Delta`$.
//! - If $`b_i = 0`$, the prover receives $`M_{i,0} := K_i`$.
//!
//! The verifier receives both $`M_{i,0}`$ and $`M_{i,1}`$.
//!
//! To open an authenticated bit, the prover sends $`(b_i, M_i)`$ to
//! the verifier and the verifier checks that $`M_i = K_i \oplus b \Delta`$.
//!
//! # Example
//!
//! Below is an example that shows the generation and opening of 10
//! [`AuthBit`]s.
//!
//! ```
//! # use rand::RngExt;
//! # use swanky_authenticated_bits::authbits::{AuthBit, AuthBitGenerator};
//! # use swanky_field_binary::F2;
//! # use swanky_party::{party_system, either::PartyEither, private::PartyPrivate, ty_eq::Witness};
//! # use std::iter::Copied;
//! # use std::slice::Iter;
//! # party_system! {
//! #     mod ps {
//! #         Prover,
//! #         Verifier,
//! #     }
//! # }
//! # use ps::{Prover, Verifier};
//! # fn main() -> swanky_error::Result<()> {
//! let (bits_prover, bits_verifier) = swanky_channel::local::local_channel_pair(
//!     |c| {
//!         // The prover.
//!         let mut rng = swanky_rng::SwankyRng::new();
//!         let bits = rng.random::<[F2; 10]>();
//!         let mut authbits: Vec<AuthBit<Prover>> = vec![];
//!         let mut generator: AuthBitGenerator<_> = AuthBitGenerator::new(c, &mut rng)?;
//!         generator.generate(PartyEither::new(Witness::EQUAL_TYPES, bits.iter().copied()), &mut authbits, c, &mut rng)?;
//!         generator.open(&authbits, PartyPrivate::empty(Witness::EQUAL_TYPES), c)?;
//!         Ok(bits.to_vec())
//!     },
//!     |c| {
//!         // The verifier.
//!         let mut rng = swanky_rng::SwankyRng::new();
//!         let count = 10;
//!         let mut bits = vec![];
//!         let mut authbits: Vec<AuthBit<Verifier>> = vec![];
//!         let mut generator: AuthBitGenerator<_> = AuthBitGenerator::new(c, &mut rng)?;
//!         let input: PartyEither<_, Copied<Iter<'_, F2>>, _> = PartyEither::new(Witness::EQUAL_TYPES, count);
//!         generator.generate(input, &mut authbits, c, &mut rng)?;
//!         generator.open(&authbits, PartyPrivate::new(&mut bits), c)?;
//!         Ok(bits)
//!     }
//! )?;
//! assert_eq!(bits_prover, bits_verifier);
//! # Ok(())
//! # }
//! ```
//!
//! [^1]: J.B. Nielsen, T. Schneider, R. Trifiletti. "Constant Round Maliciously
//!     Secure 2PC with Function-independent Preprocessing using LEGO".
//!     <https://eprint.iacr.org/2016/1069.pdf>

use rand::{CryptoRng, RngExt};
use swanky_channel::Channel;
use swanky_error::{ErrorKind, WrapErr};
use swanky_field::FiniteRing;
use swanky_field_binary::{F2, F2BitDeserializer, F2BitSerializer, F128b};
use swanky_ot_alsz_kos::kos;
use swanky_ot_traits::{CorrelatedReceiver, CorrelatedSender, Receiver, Sender};
use swanky_party::{
    GenericParty, GenericWhichParty, Party0, Party1,
    either::{PartyEither, PartyEitherCopy},
    private::{PartyPrivate, PartyPrivateCopy},
};
use swanky_serialization::{SequenceDeserializer, SequenceSerializer};
use vectoreyes::{SimdBase, U8x16};

/// The prover's part of the authentication bit.
///
/// The prover holds a bit that they wish to authenticate and receive a MAC
/// which corresponds to that authentication.
#[derive(Clone, Copy, Default)]
struct ProverAuthBit {
    /// MAC authenticating the bit.
    mac: U8x16,
    /// The authenticated bit.
    bit: F2,
}
/// The verifier's part of the authentication bit.
///
/// The verifier holds a local `key` that verifies the integrity of the prover's
/// MAC.
#[derive(Clone, Copy, Default)]
struct VerifierAuthBit {
    /// Key authenticating the prover's MAC.
    key: U8x16,
}
/// An authenticated bit.
///
/// See [`crate::authbits`] for details. [`AuthBit`]s can be generated using
/// [`AuthBitGenerator`].
#[derive(Clone, Copy, Default)]
pub struct AuthBit<P: GenericParty>(PartyEitherCopy<P, ProverAuthBit, VerifierAuthBit>);

impl<P: GenericParty> AuthBit<P> {
    /// The [`ProverAuthBit`] component.
    fn prover(self) -> PartyPrivateCopy<Party0<P>, P, ProverAuthBit> {
        self.0.into()
    }
    /// The [`ProverAuthBit`] component as a mutable reference.
    fn prover_mut(&mut self) -> PartyPrivate<Party0<P>, P, &mut ProverAuthBit> {
        self.0.as_mut().into()
    }
    /// The [`VerifierAuthBit`] component.
    fn verifier(self) -> PartyPrivateCopy<Party1<P>, P, VerifierAuthBit> {
        self.0.into()
    }
    /// The [`VerifierAuthBit`] component as a mutable reference.
    fn verifier_mut(&mut self) -> PartyPrivate<Party1<P>, P, &mut VerifierAuthBit> {
        self.0.as_mut().into()
    }
    /// Output the verifier's key associated with this [`AuthBit`].
    pub fn key(&self) -> PartyPrivateCopy<Party1<P>, P, U8x16> {
        self.verifier().map(|vab| vab.key)
    }
    /// Output the prover's MAC associated with this [`AuthBit`].
    pub fn mac(&self) -> PartyPrivateCopy<Party0<P>, P, U8x16> {
        self.prover().map(|vab| vab.mac)
    }
    /// Output the prover's bit associated with this [`AuthBit`].
    pub fn bit(&self) -> PartyPrivateCopy<Party0<P>, P, F2> {
        self.prover().map(|vab| vab.bit)
    }

    /// Compute $`c \cdot [b]`$, where $`c`$ is a public constant.
    ///
    /// This maps the prover's values $`(b, M)`$ to $`(c \cdot b, c \cdot M)`$,
    /// and maps the verifier's value $`K`$ to $`c \cdot K`$.
    pub fn mul_with_const(&self, constant: F2) -> Self {
        match P::GENERIC_WHICH {
            GenericWhichParty::Party0(ev) => {
                let prover = self.prover().into_inner(ev);
                Self(PartyEitherCopy::new(
                    ev,
                    ProverAuthBit {
                        mac: (constant * F128b::from(prover.mac)).into(),
                        bit: constant * prover.bit,
                    },
                ))
            }
            GenericWhichParty::Party1(ev) => {
                let verifier = self.verifier().into_inner(ev);
                Self(PartyEitherCopy::new(
                    ev,
                    VerifierAuthBit {
                        key: (constant * F128b::from(verifier.key)).into(),
                    },
                ))
            }
        }
    }
}

/// XOR two authenticated bits. Linear operations on authenticated bits are "free"
/// (i.e. can be done locally).
impl<P: GenericParty> core::ops::BitXor for AuthBit<P> {
    type Output = Self;
    fn bitxor(self, rhs: Self) -> Self::Output {
        let pairs = self.0.zip(rhs.0);
        AuthBit(pairs.map(
            |(lhs, rhs)| ProverAuthBit {
                mac: lhs.mac ^ rhs.mac,
                bit: lhs.bit + rhs.bit,
            },
            |(lhs, rhs)| VerifierAuthBit {
                key: lhs.key ^ rhs.key,
            },
        ))
    }
}

impl<P: GenericParty> core::ops::BitXorAssign for AuthBit<P> {
    fn bitxor_assign(&mut self, rhs: Self) {
        match P::GENERIC_WHICH {
            GenericWhichParty::Party0(ev) => {
                self.prover_mut().into_inner(ev).mac ^= rhs.prover().into_inner(ev).mac;
                self.prover_mut().into_inner(ev).bit += rhs.prover().into_inner(ev).bit;
            }
            GenericWhichParty::Party1(ev) => {
                self.verifier_mut().into_inner(ev).key ^= rhs.verifier().into_inner(ev).key;
            }
        }
        self.0.zip(rhs.0).map(
            |(mut lhs, rhs)| {
                lhs.mac ^= rhs.mac;
                lhs.bit += rhs.bit
            },
            |(mut lhs, rhs)| lhs.key ^= rhs.key,
        );
    }
}

/// A type for generating [`AuthBit`]s.
///
/// For authenticated bit _verifiers_, the generator contains the particular
/// $`\Delta`$ value to verify against. This means that generated [`AuthBit`]s
/// _must_ be opened using the same generator that generated them! Odd behavior
/// may result if a different generator is used: when verifying one bits,
/// verification will fail (with overwhelming probability), but when verifying
/// zero bits, verification will not (because the $`\Delta`$ value is never used
/// in the verification of a zero bit)!
///
/// # Implementation Note
/// Internally, [`AuthBitGenerator`] uses oblivious transfer (OT). In this
/// implementation, the KOS OT protocol is currently hardcoded. There may come a
/// point in the future where we'll want to make the OT protocol adjustable, in
/// which case the the type definition may have to change (in order to include
/// any necessarily OT trait).
pub struct AuthBitGenerator<P: GenericParty> {
    /// The verifier's global $`\Delta`$.
    delta: PartyPrivateCopy<Party1<P>, P, U8x16>,
    /// The party-specific correlated OT instantiation.
    ot: PartyEither<P, kos::Receiver, kos::Sender>,
}

impl<P: GenericParty> AuthBitGenerator<P> {
    /// Create a new [`AuthBitGenerator`].
    ///
    /// The verifier's $`\Delta`$ value is randomly generated using `rng`.
    pub fn new<RNG>(channel: &mut Channel, mut rng: RNG) -> swanky_error::Result<Self>
    where
        RNG: CryptoRng,
    {
        match P::GENERIC_WHICH {
            GenericWhichParty::Party0(e) => {
                Self::new_with_delta(PartyPrivateCopy::empty(e), channel, rng)
            }
            GenericWhichParty::Party1(_e) => {
                let delta = rng.random::<U8x16>();
                Self::new_with_delta(PartyPrivateCopy::new(delta), channel, rng)
            }
        }
    }

    /// Create a new [`AuthBitGenerator`] with a supplied $`\Delta`$ value.
    pub fn new_with_delta<RNG>(
        delta: PartyPrivateCopy<Party1<P>, P, U8x16>,
        channel: &mut Channel,
        mut rng: RNG,
    ) -> swanky_error::Result<Self>
    where
        RNG: CryptoRng,
    {
        let result = match P::GENERIC_WHICH {
            GenericWhichParty::Party0(e) => AuthBitGenerator {
                delta: PartyPrivateCopy::empty(e),
                ot: PartyEither::new(
                    e,
                    kos::Receiver::init(channel, &mut rng).wrap_err(
                        ErrorKind::InitializationError,
                        "Failed to initialize KOS receiver.",
                    )?,
                ),
            },
            GenericWhichParty::Party1(e) => AuthBitGenerator {
                delta: PartyPrivateCopy::new(delta.into_inner(e)),
                ot: PartyEither::new(
                    e,
                    kos::Sender::init(channel, &mut rng).wrap_err(
                        ErrorKind::InitializationError,
                        "Failed to initialize KOS sender.",
                    )?,
                ),
            },
        };
        Ok(result)
    }

    /// Generate a vector of authenticated bits.
    ///
    /// `Party0` supplies the bits to authenticate, and `Party1` specifies
    /// the number of bits. The resulting authenticated bits are
    /// [`Vec::extend`]ed into `out`.
    pub fn generate<RNG: CryptoRng, I: Iterator<Item = F2>>(
        &mut self,
        bits_in: PartyEither<P, I, usize>,
        out: &mut Vec<AuthBit<P>>,
        mut channel: &mut Channel,
        rng: &mut RNG,
    ) -> swanky_error::Result<()> {
        match P::GENERIC_WHICH {
            GenericWhichParty::Party0(e) => {
                let bits = bits_in.into_inner(e);
                // TODO: Once OT uses F2 instead of bool this line won't be necessary.
                let bits = bits.map(bool::from).collect::<Vec<bool>>();
                let macs = self
                    .ot
                    .as_mut()
                    .into_inner(e)
                    .receive_correlated(&mut channel, &bits, rng)
                    .wrap_err(
                        ErrorKind::NetworkError,
                        "Failed to receive correlated data.",
                    )?;

                out.extend(bits.into_iter().zip(macs).map(|(bit, mac)| {
                    AuthBit(PartyEitherCopy::new(
                        e,
                        ProverAuthBit {
                            bit: bit.into(),
                            mac,
                        },
                    ))
                }));
                Ok(())
            }
            GenericWhichParty::Party1(e) => {
                let delta = self.delta().into_inner(e);
                let keys = self
                    .ot
                    .as_mut()
                    .into_inner(e)
                    .send_correlated(&mut channel, bits_in.into_inner(e), delta, rng)
                    .wrap_err(ErrorKind::NetworkError, "Failed to send correlated data.")?;
                out.extend(
                    keys.into_iter()
                        .map(|key| AuthBit(PartyEitherCopy::new(e, VerifierAuthBit { key }))),
                );

                Ok(())
            }
        }
    }

    /// Open the authenticated bits in `authbits`.
    ///
    /// This corresponds to the prover sending $`(b, M)`$ to the verifier, who
    /// checks that $`K = M \oplus b \Delta`$. The resulting opened bits are
    /// [`Vec::push`]ed to `outputs`.
    ///
    /// # Errors
    ///
    /// This method returns an error if any [`AuthBit`] fails validation.
    /// In this case, no opened bits are added to `outputs`.
    pub fn open(
        &self,
        authbits: &[AuthBit<P>],
        outputs: PartyPrivate<Party1<P>, P, &mut Vec<F2>>,
        channel: &mut Channel,
    ) -> swanky_error::Result<()> {
        AuthBitGenerator::open_with_delta(authbits, self.delta(), outputs, channel)
    }

    /// Open the authenticated bits in `authbits` using a supplied $`\Delta`$ value.
    ///
    /// See [`AuthBitGenerator::open`] for details.
    ///
    /// # Errors
    ///
    /// This method returns an error if any [`AuthBit`] fails validation.
    /// In this case, no opened bits are added to `outputs`.
    pub fn open_with_delta(
        authbits: &[AuthBit<P>],
        delta: PartyPrivateCopy<Party1<P>, P, U8x16>,
        outputs: PartyPrivate<Party1<P>, P, &mut Vec<F2>>,
        channel: &mut Channel,
    ) -> swanky_error::Result<()> {
        match P::GENERIC_WHICH {
            GenericWhichParty::Party0(e) => {
                let mut bit_ser: F2BitSerializer =
                    SequenceSerializer::new(&mut channel.as_std_io()).wrap_err(
                        ErrorKind::InitializationError,
                        "Failed to initialize sequence serializer.",
                    )?;
                for b in authbits.iter() {
                    bit_ser
                        .write(channel.as_std_io(), b.bit().into_inner(e))
                        .wrap_err(
                            ErrorKind::SerializationError,
                            "Failed to write serialized bits.",
                        )?;
                }
                bit_ser.finish(channel.as_std_io()).wrap_err(
                    ErrorKind::SerializationError,
                    "Failed to finish bit serialization.",
                )?;

                for ab in authbits.iter() {
                    channel.write_bytes(ab.mac().into_inner(e).as_ref())?;
                }
            }
            GenericWhichParty::Party1(e) => {
                let mut bit_ser: F2BitDeserializer = SequenceDeserializer::new(channel.as_std_io())
                    .wrap_err(
                        ErrorKind::InitializationError,
                        "Failed to create sequence deserializer.",
                    )?;
                let bits_ = outputs.into_inner(e);
                // We only want to validate the bits we added to the `outputs`
                // vector, so we save the existing length so we can only
                // validate the [`Vec::push`]ed bits.
                let outputs_initial_len = bits_.len();
                for _ in 0..authbits.len() {
                    // Optimistically add the opened bits to the output vector.
                    // We remove these added values below if validation fails.
                    bits_.push(bit_ser.read(channel.as_std_io()).wrap_err(
                        ErrorKind::SerializationError,
                        "Failed to read serialized bits.",
                    )?);
                }
                let mut validation = true;
                for (ab, bit) in authbits.iter().zip(bits_[outputs_initial_len..].iter()) {
                    let mac = channel.read::<U8x16>()?;

                    validation &= mac
                        == if F2::ONE == *bit {
                            ab.key().into_inner(e) ^ delta.into_inner(e)
                        } else {
                            ab.key().into_inner(e)
                        };
                }
                if !validation {
                    // Validation failed, so the bits added to the output vector
                    // are not necessarily valid. So truncate the vector back to
                    // its original size.
                    bits_.truncate(outputs_initial_len);
                    swanky_error::bail!(ErrorKind::OtherError, "Validation check failed");
                }
            }
        }
        Ok(())
    }

    /// The verifier's $`\Delta`$ value.
    pub fn delta(&self) -> PartyPrivateCopy<Party1<P>, P, U8x16> {
        self.delta
    }

    /// Compute $`[b] \oplus c`$, where $`c`$ is a public constant.
    ///
    /// This maps the prover's values $`(b, M)`$ to $`(b \oplus c, M)`$,
    /// and maps the verifier's value $`K`$ to $`K \oplus c \Delta`$.
    pub fn xor_with_const(&self, authbit: AuthBit<P>, bit: F2) -> AuthBit<P> {
        Self::xor_with_const_with_delta(authbit, bit, self.delta())
    }

    /// Compute $`[b] \oplus c`$, where $`c`$ is a public constant, using a
    /// supplied $`\Delta`$ value.
    ///
    /// See [`AuthBitGenerator::xor_with_const`] for details.
    pub fn xor_with_const_with_delta(
        authbit: AuthBit<P>,
        bit: F2,
        delta: PartyPrivateCopy<Party1<P>, P, U8x16>,
    ) -> AuthBit<P> {
        match P::GENERIC_WHICH {
            GenericWhichParty::Party0(ev) => AuthBit(PartyEitherCopy::new(
                ev,
                ProverAuthBit {
                    mac: authbit.mac().into_inner(ev),
                    bit: authbit.bit().into_inner(ev) + bit,
                },
            )),
            GenericWhichParty::Party1(ev) => AuthBit(PartyEitherCopy::new(
                ev,
                VerifierAuthBit {
                    key: authbit.key().into_inner(ev)
                        ^ U8x16::from(bit * F128b::from(delta.into_inner(ev))),
                },
            )),
        }
    }

    /// Compute $`[c]`$, where $`c`$ is a public constant, using a supplied
    /// $`\Delta`$ value.
    ///
    /// This sets the prover's values to $`(c, 0)`$ and the verifier's value to
    /// $`c \cdot \Delta`$.
    pub fn constant(&self, constant: F2) -> AuthBit<P> {
        AuthBitGenerator::constant_with_delta(constant, self.delta)
    }

    /// Compute $`[c]`$, where $`c`$ is a public constant, using a supplied
    /// $`\Delta`$ value.
    ///
    /// See [`AuthBitGenerator::constant`] for details.
    pub fn constant_with_delta(
        constant: F2,
        delta: PartyPrivateCopy<Party1<P>, P, U8x16>,
    ) -> AuthBit<P> {
        match P::GENERIC_WHICH {
            GenericWhichParty::Party0(ev) => AuthBit(PartyEitherCopy::new(
                ev,
                ProverAuthBit {
                    mac: U8x16::ZERO,
                    bit: constant,
                },
            )),
            GenericWhichParty::Party1(ev) => AuthBit(PartyEitherCopy::new(
                ev,
                VerifierAuthBit {
                    key: U8x16::from(constant * F128b::from(delta.into_inner(ev))),
                },
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{iter::Copied, slice::Iter};

    use super::*;
    use proptest::prelude::*;
    use rand::SeedableRng;
    use swanky_field::FiniteRing;
    use swanky_party::{party_system, ty_eq::Witness};
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
    ) -> (AuthBitGenerator<PartyA>, AuthBitGenerator<PartyB>) {
        swanky_channel::local::local_channel_pair(
            |c| AuthBitGenerator::<PartyA>::new(c, &mut rng_a),
            |c| AuthBitGenerator::<PartyB>::new(c, &mut rng_b),
        )
        .unwrap()
    }

    /// Validates pairs of `PartyA` and `PartyB` `AuthBit`s.
    fn validate(pr: &[AuthBit<PartyA>], vr: &[AuthBit<PartyB>], delta: U8x16) -> bool {
        assert!(!pr.is_empty());
        assert!(!vr.is_empty());
        assert_eq!(pr.len(), vr.len());

        pr.iter()
            .zip(vr)
            .map(|(ab_pr, ab_vr)| {
                ab_pr.mac().into_inner(Witness::EQUAL_TYPES)
                    == (if ab_pr.bit().into_inner(Witness::EQUAL_TYPES) == F2::ONE {
                        ab_vr.key().into_inner(Witness::EQUAL_TYPES) ^ delta
                    } else {
                        ab_vr.key().into_inner(Witness::EQUAL_TYPES)
                    })
            })
            .reduce(|b1, b2| b1 && b2)
            .unwrap()
    }

    /// Generates `AuthBit`s, outputting the produced `AuthBit`s and their
    /// associated generators. If `tamper_mac` is true, tamper with `PartyA`'s
    /// MAC. If `tamper_key` is true, tamper with `PartyB`'s key.
    fn generate(
        bits_in: &[F2],
        generator_a: &mut AuthBitGenerator<PartyA>,
        generator_b: &mut AuthBitGenerator<PartyB>,
        mut rng_a: &mut SwankyRng,
        mut rng_b: &mut SwankyRng,
        tamper_mac: bool,
        tamper_key: bool,
    ) -> (Vec<AuthBit<PartyA>>, Vec<AuthBit<PartyB>>) {
        assert!(!bits_in.is_empty());
        swanky_channel::local::local_channel_pair(
            |channel_pr| {
                let mut outputs = vec![];
                let bits = PartyEither::new(Witness::EQUAL_TYPES, bits_in.iter().copied());
                generator_a.generate(bits, &mut outputs, channel_pr, &mut rng_a)?;
                if tamper_mac {
                    // Tamper the MAC of the first `AuthBit`.
                    outputs[0] = AuthBit(PartyEitherCopy::new(
                        Witness::EQUAL_TYPES,
                        ProverAuthBit {
                            bit: outputs[0].bit().into_inner(Witness::EQUAL_TYPES),
                            mac: rng_a.random(),
                        },
                    ));
                }
                generator_a.open(
                    &outputs,
                    PartyPrivate::empty(Witness::EQUAL_TYPES),
                    channel_pr,
                )?;
                Ok(outputs)
            },
            |channel_vr| {
                let mut outputs = vec![];
                let count: PartyEither<_, Copied<Iter<'_, F2>>, _> =
                    PartyEither::new(Witness::EQUAL_TYPES, bits_in.len());
                generator_b.generate(count, &mut outputs, channel_vr, &mut rng_b)?;
                if tamper_key {
                    // Tamper the key of the first `AuthBit`.
                    outputs[0] = AuthBit(PartyEitherCopy::new(
                        Witness::EQUAL_TYPES,
                        VerifierAuthBit {
                            key: rng_b.random(),
                        },
                    ));
                }
                let mut output = vec![];
                let validation =
                    generator_b.open(&outputs, PartyPrivate::new(&mut output), channel_vr);
                // The generated bits should always be valid when no tampering happens.
                if !tamper_mac && !tamper_key {
                    assert!(validation.is_ok());
                } else {
                    assert!(validation.is_err());
                }
                Ok(outputs)
            },
        )
        .unwrap()
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn xor_with_const_works(bits in proptest::collection::vec(any::<bool>(), 1..1000),
                                public_bits in proptest::collection::vec(any::<bool>(), 1..1000),
                                seed_party_a in any::<u128>(),
                                seed_party_b in any::<u128>()) {
            let mut rng_a = SwankyRng::from_seed(seed_party_a.into());
            let mut rng_b = SwankyRng::from_seed(seed_party_b.into());
            let bits: Vec<F2> = bits.into_iter().map(F2::from).collect();
            let public_bits: Vec<F2> = public_bits.into_iter().map(F2::from).collect();
            let (mut generator_a, mut generator_b) = generators(&mut rng_a, &mut rng_b);
            let (output_a, output_b) = generate(&bits, &mut generator_a, &mut generator_b, &mut rng_a, &mut rng_b, false, false);
            for ((authbit_a, authbit_b), public_bit) in output_a
                .into_iter()
                .zip(output_b.into_iter())
                .zip(public_bits.into_iter())
            {
                let new_authbit_a = generator_a.xor_with_const(authbit_a, public_bit);
                let new_authbit_b = generator_b.xor_with_const(authbit_b, public_bit);
                // The new authenticated bits should still validate.
                let validation = validate(
                    &[new_authbit_a],
                    &[new_authbit_b],
                    generator_b.delta().into_inner(Witness::EQUAL_TYPES),
                );
                prop_assert!(validation);
                // The new authenticated bits should equal `bit ^ public_bit`.
                prop_assert_eq!(
                    new_authbit_a.bit().into_inner(Witness::EQUAL_TYPES),
                    authbit_a.bit().into_inner(Witness::EQUAL_TYPES) + public_bit
                );
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn mul_with_const_works(bits in proptest::collection::vec(any::<bool>(), 1..1000),
                                public_bits in proptest::collection::vec(any::<bool>(), 1..1000),
                                seed_party_a in any::<u128>(),
                                seed_party_b in any::<u128>()) {
            let mut rng_a = SwankyRng::from_seed(seed_party_a.into());
            let mut rng_b = SwankyRng::from_seed(seed_party_b.into());
            let bits: Vec<F2> = bits.into_iter().map(F2::from).collect();
            let public_bits: Vec<F2> = public_bits.into_iter().map(F2::from).collect();
            let (mut generator_a, mut generator_b) = generators(&mut rng_a, &mut rng_b);
            let (output_a, output_b) = generate(&bits, &mut generator_a, &mut generator_b, &mut rng_a, &mut rng_b, false, false);
            for ((authbit_a, authbit_b), public_bit) in output_a
                .into_iter()
                .zip(output_b.into_iter())
                .zip(public_bits.into_iter())
            {
                let new_authbit_a = authbit_a.mul_with_const(public_bit);
                let new_authbit_b = authbit_b.mul_with_const(public_bit);
                // The new authenticated bits should still validate.
                let validation = validate(
                    &[new_authbit_a],
                    &[new_authbit_b],
                    generator_b.delta().into_inner(Witness::EQUAL_TYPES),
                );
                prop_assert!(validation);
                // The new authenticated bits should equal `bit * public_bit`.
                prop_assert_eq!(
                    new_authbit_a.bit().into_inner(Witness::EQUAL_TYPES),
                    authbit_a.bit().into_inner(Witness::EQUAL_TYPES) * public_bit
                );

            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn constant_works(public_bits in proptest::collection::vec(any::<bool>(), 1..1000),
                          seed_party_a in any::<u128>(),
                          seed_party_b in any::<u128>()) {
            let mut rng_a = SwankyRng::from_seed(seed_party_a.into());
            let mut rng_b = SwankyRng::from_seed(seed_party_b.into());
            let public_bits: Vec<F2> = public_bits.into_iter().map(F2::from).collect();
            let (generator_a, generator_b) = generators(&mut rng_a, &mut rng_b);
            for bit in public_bits {
                let bit_a = generator_a.constant(bit);
                let bit_b = generator_b.constant(bit);
                let validation = validate(
                    &[bit_a],
                    &[bit_b],
                    generator_b.delta().into_inner(Witness::EQUAL_TYPES),
                );
                prop_assert!(validation);
                // The new authenticated bits should equal `bit`.
                prop_assert_eq!(
                    bit_a.bit().into_inner(Witness::EQUAL_TYPES),
                    bit
                );
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn honest_generation_works(bits in proptest::collection::vec(any::<bool>(), 1..1000),
                                   seed_party_a in any::<u128>(),
                                   seed_party_b in any::<u128>()) {
            let mut rng_a = SwankyRng::from_seed(seed_party_a.into());
            let mut rng_b = SwankyRng::from_seed(seed_party_b.into());
            let bits: Vec<F2> = bits.into_iter().map(F2::from).collect();
            let (mut generator_a, mut generator_b) = generators(&mut rng_a, &mut rng_b);
            let (output_a, output_b) = generate(&bits, &mut generator_a, &mut generator_b, &mut rng_a, &mut rng_b, false, false);
            let validation = validate(
                &output_a,
                &output_b,
                generator_b.delta().into_inner(Witness::EQUAL_TYPES),
            );
            prop_assert!(validation);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn tampered_mac_fails(bits in proptest::collection::vec(any::<bool>(), 1..1000),
                              seed_party_a in any::<u128>(),
                              seed_party_b in any::<u128>()) {
            let mut rng_a = SwankyRng::from_seed(seed_party_a.into());
            let mut rng_b = SwankyRng::from_seed(seed_party_b.into());
            let bits: Vec<F2> = bits.into_iter().map(F2::from).collect();
            let (mut generator_a, mut generator_b) = generators(&mut rng_a, &mut rng_b);
            let (output_a, output_b) = generate(&bits, &mut generator_a, &mut generator_b, &mut rng_a, &mut rng_b, true, false);
            let validation = validate(
                &output_a,
                &output_b,
                generator_b.delta().into_inner(Witness::EQUAL_TYPES),
            );
            prop_assert!(!validation);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn tampered_key_fails(bits in proptest::collection::vec(any::<bool>(), 1..1000),
                              seed_party_a in any::<u128>(),
                              seed_party_b in any::<u128>()) {
            let mut rng_a = SwankyRng::from_seed(seed_party_a.into());
            let mut rng_b = SwankyRng::from_seed(seed_party_b.into());
            let bits: Vec<F2> = bits.into_iter().map(F2::from).collect();
            let (mut generator_a, mut generator_b) = generators(&mut rng_a, &mut rng_b);
            let (output_a, output_b) = generate(&bits, &mut generator_a, &mut generator_b, &mut rng_a, &mut rng_b, false, true);
            let validation = validate(
                &output_a,
                &output_b,
                generator_b.delta().into_inner(Witness::EQUAL_TYPES),
            );
            prop_assert!(!validation);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn tampered_delta_fails(bits in proptest::collection::vec(any::<bool>(), 1..1000),
                                delta in any::<u128>(),
                                seed_party_a in any::<u128>(),
                                seed_party_b in any::<u128>()) {
            let mut rng_a = SwankyRng::from_seed(seed_party_a.into());
            let mut rng_b = SwankyRng::from_seed(seed_party_b.into());
            let bits: Vec<F2> = bits.into_iter().map(F2::from).collect();
            let (mut generator_a, mut generator_b) = generators(&mut rng_a, &mut rng_b);
            let (output_a, output_b) = generate(&bits, &mut generator_a, &mut generator_b, &mut rng_a, &mut rng_b, false, true);
            let validation = validate(&output_a, &output_b, U8x16::from(delta));
            // If all bits are 0, then `delta` never comes into play, so
            // validation "succeeds". Hence, only assert if this is not the case.
            if !bits.into_iter().all(|bit| bit == F2::ZERO) {
                prop_assert!(!validation);
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn bitxor_works(nbits in 320..1000,
                        seed_party_a in any::<u128>(),
                        seed_party_b in any::<u128>()) {
            let mut rng_a = SwankyRng::from_seed(seed_party_a.into());
            let mut rng_b = SwankyRng::from_seed(seed_party_b.into());
            let bits1: Vec<_> = (0..nbits).map(|_| rng_a.random::<F2>()).collect();
            let bits2: Vec<_> = (0..nbits).map(|_| rng_a.random::<F2>()).collect();
            let (mut generator_a, mut generator_b) = generators(&mut rng_a, &mut rng_b);
            let (mut output_a, mut output_b) = generate(
                &bits1,
                &mut generator_a,
                &mut generator_b,
                &mut rng_a,
                &mut rng_b,
                false,
                false,
            );
            let (output_c, output_d) = generate(
                &bits2,
                &mut generator_a,
                &mut generator_b,
                &mut rng_a,
                &mut rng_b,
                false,
                false,
            );
            // `results = (a ^ c, b ^ d)`
            let results: Vec<_> = output_a
                .iter()
                .zip(output_b.iter())
                .zip(output_c.iter().zip(output_d.iter()))
                .map(|((a, b), (c, d))| (*a ^ *c, *b ^ *d))
                .collect();
            // Test that `bitxor` works as intended.
            for (result, ((a, b), (c, d))) in results.iter().zip(
                output_a
                    .iter()
                    .zip(output_b.iter())
                    .zip(output_c.iter().zip(output_d.iter())),
            ) {
                assert_eq!(
                    result.0.bit().into_inner(Witness::EQUAL_TYPES),
                    a.bit().into_inner(Witness::EQUAL_TYPES) + c.bit().into_inner(Witness::EQUAL_TYPES)
                );
                assert_eq!(
                    result.0.mac().into_inner(Witness::EQUAL_TYPES),
                    a.mac().into_inner(Witness::EQUAL_TYPES) ^ c.mac().into_inner(Witness::EQUAL_TYPES)
                );
                assert_eq!(
                    result.1.key().into_inner(Witness::EQUAL_TYPES),
                    b.key().into_inner(Witness::EQUAL_TYPES) ^ d.key().into_inner(Witness::EQUAL_TYPES)
                );
            }
            // Test that `bitxor_assign` works as intended.
            for ((a, b), (c, d)) in output_a
                .iter_mut()
                .zip(output_b.iter_mut())
                .zip(output_c.iter().zip(output_d.iter()))
            {
                *a ^= *c;
                *b ^= *d;
            }
            for (result, (a, b)) in results.iter().zip(output_a.iter().zip(output_b.iter())) {
                assert_eq!(
                    result.0.bit().into_inner(Witness::EQUAL_TYPES),
                    a.bit().into_inner(Witness::EQUAL_TYPES)
                );
                assert_eq!(
                    result.0.mac().into_inner(Witness::EQUAL_TYPES),
                    a.mac().into_inner(Witness::EQUAL_TYPES)
                );
                assert_eq!(
                    result.1.key().into_inner(Witness::EQUAL_TYPES),
                    b.key().into_inner(Witness::EQUAL_TYPES)
                );
            }
        }
    }
}
