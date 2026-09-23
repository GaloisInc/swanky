//! Authenticated AND triples.
//!
//! An authenticated AND triple is a random authenticated triple $`(\langle x
//! \rangle, \langle y \rangle, \langle z \rangle)`$ [^1] such that $`x \cdot y
//! = z`$.
//!
//! # Details
//!
//! To generate [`AndTriple`]s, the parties first compute _leaky_ AND triples,
//! which are equivalent to [`AndTriple`]s with the exception that an
//! adversarial Party A can attempt to guess the value of $`x`$: if correct this
//! remains undetected, if incorrect the adversary is caught.
//!
//! We turn leaky AND triples into _authenticated_ AND triples using a bucketing
//! technique: the parties generate a bunch of leaky AND triples, randomly
//! shuffle these, and the "bucket" them into buckets of size $`B`$, where $`B`$
//! depends on the total number of authenticated AND triples desired. Each
//! bucket is them combined into a single (authenticated) AND triple. See Katz
//! et al. [^2] for details.
//!
//! # Security
//!
//! The generation protocol for leaky AND triples requires that the
//! least-significant bit of the $`\Delta`$ value be fixed, and hence the
//! protocol achieves at most 127-bits of security.
//!
//! In addition, the parameters for combining leaky AND triples into
//! authenticated AND triples assumes 40-bits of statistical security.
//!
//! [^1]: See [`crate::authshares`] for the definition of the $`\langle x
//! \rangle`$ notation.
//!
//! [^2]: J. Katz, S. Ranellucci, M. Rosulek, X. Wang. "Optimizing Authenticated
//! Garbling for Faster Secure Two-Party Computation".
//! <https://eprint.iacr.org/2018/578.pdf>

use crate::{
    authshares::{AuthShare, AuthShareGenerator},
    leaky_and_triples::{LeakyAndTriple, LeakyAndTripleGenerator},
};
use bytemuck::TransparentWrapper;
use rand::{CryptoRng, SeedableRng, seq::SliceRandom};
use std::io::{Cursor, Seek};
use swanky_channel::Channel;
use swanky_error::{ErrorKind, WrapErr};
use swanky_field::FiniteRing;
use swanky_field_binary::{F2, F2BitDeserializer, F2BitSerializer};
use swanky_party::{
    GenericParty, GenericWhichParty, Party1, either::PartyEither, private::PartyPrivate,
};
use swanky_rng::SwankyRng;
use swanky_serialization::{SequenceDeserializer, SequenceSerializer};
use vectoreyes::U8x16;

/// An AND triple.
///
/// See [`crate::and_triples`] for details. [`AndTriple`]s can be generated using
/// [`AndTripleGenerator`].
#[derive(Clone, Copy, TransparentWrapper)]
#[repr(transparent)]
pub struct AndTriple<P: GenericParty>(
    // A `LeakyAndTriple` is still an AND triple.
    LeakyAndTriple<P>,
);

impl<P: GenericParty> From<LeakyAndTriple<P>> for AndTriple<P> {
    fn from(value: LeakyAndTriple<P>) -> Self {
        Self(value)
    }
}

impl<P: GenericParty> AndTriple<P> {
    /// The authenticated share $`\langle x \rangle`$.
    pub fn x(&self) -> AuthShare<P> {
        self.0.x()
    }

    /// The authenticated share $`\langle y \rangle`$.
    pub fn y(&self) -> AuthShare<P> {
        self.0.y()
    }

    /// The authenticated share $`\langle z \rangle`$ such that $`z = x \cdot
    /// y`$.
    pub fn z(&self) -> AuthShare<P> {
        self.0.z()
    }
}

/// A type for generating [`AndTriple`]s.
pub struct AndTripleGenerator<P: GenericParty> {
    leaky_generator: LeakyAndTripleGenerator<P>,
}

impl<P: GenericParty> AndTripleGenerator<P> {
    /// Create a new [`AndTripleGenerator`].
    pub fn new<RNG: CryptoRng>(channel: &mut Channel, rng: &mut RNG) -> swanky_error::Result<Self> {
        let leaky_generator = LeakyAndTripleGenerator::new(channel, rng)?;
        Ok(Self { leaky_generator })
    }

    /// Generate a valid Δ that can be used by the [`AndTripleGenerator`].
    /// The AND and Leaky AND triple generation protocols require that parties
    /// have Δ with different least significant bits (lsb). Towards that we
    /// require that Party0's Δ has lsb == 1 and Party1's Δ has lsb == 0.
    pub fn generate_valid_delta<RNG: CryptoRng>(rng: &mut RNG) -> U8x16 {
        LeakyAndTripleGenerator::<P>::generate_valid_delta(rng)
    }

    /// Create a new [`AndTripleGenerator`] with a supplied $`\Delta`$ value.
    ///
    /// # Panics
    /// This panics if $`\mathsf{lsb}(\Delta_\mathsf{A}) \neq 1`$ or if
    /// $`\mathsf{lsb}(\Delta_\mathsf{B}) \neq 0`$.
    pub fn new_with_delta<RNG: CryptoRng>(
        delta: U8x16,
        channel: &mut Channel,
        rng: &mut RNG,
    ) -> swanky_error::Result<Self> {
        let leaky_generator = LeakyAndTripleGenerator::new_with_delta(delta, channel, rng)?;
        Ok(Self { leaky_generator })
    }

    /// Generate a vector of AND triples.
    ///
    /// # Security
    /// This method utilizes parameters fixed for a statistical security
    /// parameter of 40-bits.
    ///
    /// # Panics
    /// This panics if `ntriples < 320`, as 320 is the minimum number of triples
    /// that can be generated.
    pub fn generate<RNG: CryptoRng>(
        &mut self,
        ntriples: usize,
        out: &mut Vec<AndTriple<P>>,
        channel: &mut Channel,
        rng: &mut RNG,
    ) -> swanky_error::Result<()> {
        // See Table 4 from https://eprint.iacr.org/2017/030.pdf.
        //
        // These numbers are for a statistical security of 40 bits.
        let bucket_size = if ntriples >= 280_000 {
            3
        } else if ntriples >= 3_100 {
            4
        } else if ntriples >= 320 {
            5
        } else {
            panic!("Too few triples: Must be >= 320");
        };
        let nleaky = ntriples * bucket_size;
        let mut leaky_ands = Vec::with_capacity(nleaky);
        self.leaky_generator
            .generate(nleaky, &mut leaky_ands, channel, rng)?;
        // Run a coin-tossing protocol to determine a seed for permuting the
        // generated leaky AND triples.
        let random = swanky_f_rand::random_seed::<P, _>(channel, rng)?;
        // Do the permutation.
        let mut shuffle_rng = SwankyRng::from_seed(random);
        leaky_ands.shuffle(&mut shuffle_rng);
        // Bucket the leaky AND triples and combine them into (non-leaky) AND triples.
        self.leaky_generator
            .combine(&leaky_ands, out, bucket_size, channel)?;
        Ok(())
    }

    /// Open the AND triples in `triples`.
    ///
    /// This corresponds to opening each of the underlying authenticated shares.
    pub fn open(
        &self,
        triples: &[AndTriple<P>],
        channel: &mut Channel,
    ) -> swanky_error::Result<()> {
        // An AND triple is _also_ a leaky-AND triple (with no leak), so use
        // that `open` method here.
        AndTripleGenerator::open_with_delta(triples, self.delta(), channel)
    }

    /// Open the AND triples in `triples` using a supplied $`\Delta`$ value.
    ///
    /// This corresponds to opening each of the underlying authenticated shares.
    pub fn open_with_delta(
        triples: &[AndTriple<P>],
        delta: U8x16,
        channel: &mut Channel,
    ) -> swanky_error::Result<()> {
        // An AND triple is _also_ a leaky-AND triple (with no leak), so use
        // that `open` method here.
        LeakyAndTripleGenerator::open_with_delta(AndTriple::peel_slice(triples), delta, channel)
    }

    /// Turn random AND triples into a "known" AND triples.
    ///
    /// Given random AND triple $`(\langle x \rangle, \langle y \rangle, \langle
    /// z \rangle)`$ such that $`x \cdot y = z`$ and authenticated shares
    /// $`\langle a \rangle`$ and $`\langle b \rangle`$, output authenticated
    /// share $`\langle c \rangle`$ such that $`a \cdot b = c`$.
    ///
    /// Resulting authenticated shares are [`Vec::push`]ed to the `outputs`
    /// vector.
    ///
    /// # Panics
    ///
    /// Panics if the lengths of `randoms`, `inputs_a`, and `inputs_b` are not
    /// equal.
    pub fn to_known_triple(
        &self,
        randoms: &[AndTriple<P>],
        inputs_a: &[AuthShare<P>],
        inputs_b: &[AuthShare<P>],
        outputs: &mut Vec<AuthShare<P>>,
        channel: &mut Channel,
    ) -> swanky_error::Result<()> {
        assert_eq!(randoms.len(), inputs_a.len());
        assert_eq!(randoms.len(), inputs_b.len());
        // We convert from a random triple to a known triple using a trick from
        // [1] (although at this point it's largely considered a "standard
        // technique"). The protocol works as follows. The random AND triple
        // `⟨x⟩, ⟨y⟩, ⟨z⟩` is used to "mask" the `⟨a⟩` and `⟨b⟩` shares so they
        // can be opened. These are then used to compute `⟨c⟩ := ⟨a b⟩`.
        //
        // In particular, the parties compute:
        // ```
        //     ⟨c⟩ := ⟨z⟩ ⊕ f ⟨y⟩ ⊕ g ⟨x⟩ ⊕ f g
        // ```
        // where `f := ⟨a⟩ ⊕ ⟨x⟩` and `g := ⟨b⟩ ⊕ ⟨y⟩` are opened between each
        // party. Note that the above formula can be expanded into:
        // ```
        //     ⟨z⟩ ⊕ (⟨a⟩ ⊕ ⟨x⟩) ⟨y⟩ ⊕ (⟨b⟩ ⊕ ⟨y⟩) ⟨x⟩ ⊕ (⟨a⟩ ⊕ ⟨x⟩) (⟨b⟩ ⊕ ⟨y⟩)
        // =>  ⟨z⟩ ⊕ ⟨a⟩⟨y⟩ ⊕ ⟨x⟩⟨y⟩ ⊕ ⟨b⟩⟨x⟩ ⊕ ⟨y⟩⟨x⟩ ⊕ ⟨a⟩⟨b⟩ ⊕ ⟨a⟩⟨y⟩ ⊕ ⟨x⟩⟨b⟩ ⊕ ⟨x⟩⟨y⟩
        // =>  ⟨a⟩⟨b⟩
        // ```
        // which is what we want.
        //
        // [1]: "Efficient multiparty protocols using circuit randomization." D.
        //     Beaver. CRYPTO 1991.

        // In order to reduce the round complexity, Party A sends its values of
        // `f := ⟨a⟩ ⊕ ⟨x⟩` and `g := ⟨b⟩ ⊕ ⟨y⟩` for all inputs first, followed
        // by Party B sending its values. This results in a single round of
        // communication between the parties.
        //
        // However, this does complicate the code, as now Party B needs to store
        // the `f` and `g` bits sent by Party A as intermediate values. We do
        // this in a compact way by using [`F2BitSerializer`].

        let mut channel = channel.as_std_io();
        // Contains the intermediate bits `f` and `g` send by Party A.
        let mut intermediates = Cursor::new(vec![]);
        // Only Party B needs to serialize the intermediate values.
        let mut vec_ser: PartyPrivate<Party1<P>, _, _> =
            PartyPrivate::new(F2BitSerializer::new(&mut intermediates).wrap_err(
                ErrorKind::InitializationError,
                "Failed to initialize F2 bit serializer.",
            )?);
        let mut serde: PartyEither<P, _, _> = match P::GENERIC_WHICH {
            GenericWhichParty::Party0(ev) => PartyEither::new(
                ev,
                F2BitSerializer::new(&mut channel).wrap_err(
                    ErrorKind::InitializationError,
                    "Failed to initialize F2 bit serializer.",
                )?,
            ),
            GenericWhichParty::Party1(ev) => PartyEither::new(
                ev,
                F2BitDeserializer::new(&mut channel).wrap_err(
                    ErrorKind::InitializationError,
                    "Failed to initialize F2 bit deserializer.",
                )?,
            ),
        };
        // Round 1a: Party A --> Party B.
        for (random, (a, b)) in randoms.iter().zip(inputs_a.iter().zip(inputs_b.iter())) {
            // Compute Party A's openings of `f := ⟨a⟩ ⊕ ⟨x⟩` and `g := ⟨b⟩ ⊕ ⟨y⟩`.
            let f = *a ^ random.x();
            let g = *b ^ random.y();
            match P::GENERIC_WHICH {
                GenericWhichParty::Party0(ev) => {
                    let ser = serde.as_mut().into_inner(ev);
                    ser.write(&mut channel, f.bit()).wrap_err(
                        ErrorKind::NetworkError,
                        "Failed to write opened bit f := ⟨a⟩ ⊕ ⟨x⟩.",
                    )?;
                    ser.write(&mut channel, g.bit()).wrap_err(
                        ErrorKind::NetworkError,
                        "Failed to write opened bit g := ⟨b⟩ ⊕ ⟨y⟩.",
                    )?;
                }
                GenericWhichParty::Party1(ev) => {
                    let de = serde.as_mut().into_inner(ev);
                    let f1: F2 = de
                        .read(&mut channel)
                        .wrap_err(ErrorKind::NetworkError, "Failed to read bit.")?;
                    let g1: F2 = de
                        .read(&mut channel)
                        .wrap_err(ErrorKind::NetworkError, "Failed to read bit.")?;
                    // Store `f1` and `g1` to be used in Round 1b.
                    vec_ser
                        .as_mut()
                        .into_inner(ev)
                        .write(&mut intermediates, f1)
                        .wrap_err(ErrorKind::NetworkError, "Failed to write bit.")?;
                    vec_ser
                        .as_mut()
                        .into_inner(ev)
                        .write(&mut intermediates, g1)
                        .wrap_err(ErrorKind::NetworkError, "Failed to write bit.")?;
                }
            };
        }
        // Finalize Round 1a.
        match P::GENERIC_WHICH {
            GenericWhichParty::Party0(ev) => serde.into_inner(ev).finish(&mut channel).wrap_err(
                ErrorKind::SerializationError,
                "Failed to finalize bit serialization.",
            )?,
            GenericWhichParty::Party1(ev) => {
                vec_ser.into_inner(ev).finish(&mut intermediates).wrap_err(
                    ErrorKind::SerializationError,
                    "Failed to finalize bit serialization.",
                )?;
                intermediates
                    .rewind()
                    .wrap_err(ErrorKind::OtherError, "Failed to rewind cursor.")?;
            }
        }
        // Only Party B needs to deserialize the intermediate values.
        let mut vec_de: PartyPrivate<Party1<P>, _, _> =
            PartyPrivate::new(F2BitDeserializer::new(&mut intermediates).wrap_err(
                ErrorKind::InitializationError,
                "Failed to initialize bit deserializer.",
            )?);
        let mut serde: PartyEither<P, _, _> = match P::GENERIC_WHICH {
            GenericWhichParty::Party0(ev) => PartyEither::new(
                ev,
                F2BitDeserializer::new(&mut channel).wrap_err(
                    ErrorKind::InitializationError,
                    "Failed to initialize bit deserializer.",
                )?,
            ),
            GenericWhichParty::Party1(ev) => PartyEither::new(
                ev,
                F2BitSerializer::new(&mut channel).wrap_err(
                    ErrorKind::InitializationError,
                    "Failed to initialize bit serializer.",
                )?,
            ),
        };

        // Round 1b: Party B --> Party A.
        for (random, (a, b)) in randoms.iter().zip(inputs_a.iter().zip(inputs_b.iter())) {
            // Compute openings of `f := ⟨a⟩ ⊕ ⟨x⟩` and `g := ⟨b⟩ ⊕ ⟨y⟩`.
            let f = *a ^ random.x();
            let g = *b ^ random.y();
            let (f, g) = match P::GENERIC_WHICH {
                GenericWhichParty::Party0(ev) => {
                    let de = serde.as_mut().into_inner(ev);
                    let f2: F2 = de
                        .read(&mut channel)
                        .wrap_err(ErrorKind::NetworkError, "Failed to read bit.")?;
                    let g2: F2 = de
                        .read(&mut channel)
                        .wrap_err(ErrorKind::NetworkError, "Failed to read bit.")?;
                    let f = f.bit() + f2;
                    let g = g.bit() + g2;
                    (f, g)
                }
                GenericWhichParty::Party1(ev) => {
                    let ser = serde.as_mut().into_inner(ev);
                    ser.write(&mut channel, f.bit())
                        .wrap_err(ErrorKind::NetworkError, "Failed to write bit.")?;
                    ser.write(&mut channel, g.bit())
                        .wrap_err(ErrorKind::NetworkError, "Failed to write bit.")?;
                    let f = f.bit()
                        + vec_de
                            .as_mut()
                            .into_inner(ev)
                            .read(&mut intermediates)
                            .wrap_err(ErrorKind::NetworkError, "Failed to read bit.")?;
                    let g = g.bit()
                        + vec_de
                            .as_mut()
                            .into_inner(ev)
                            .read(&mut intermediates)
                            .wrap_err(ErrorKind::NetworkError, "Failed to read bit.")?;
                    (f, g)
                }
            };
            // Compute `⟨c⟩ := ⟨z⟩ ⊕ f ⟨y⟩ ⊕ g ⟨x⟩ ⊕ f g`.
            let mut c = random.z();
            if f == F2::ONE {
                c = c ^ random.y();
            }
            if g == F2::ONE {
                c = c ^ random.x();
            }
            let c = self
                .leaky_generator
                .auth_share_generator
                .xor_with_const(c, f * g);
            outputs.push(c);
        }
        // Finalize Round 1b.
        match P::GENERIC_WHICH {
            GenericWhichParty::Party0(_) => (),
            GenericWhichParty::Party1(ev) => serde.into_inner(ev).finish(&mut channel).wrap_err(
                ErrorKind::SerializationError,
                "Failed to finalize bit serialization.",
            )?,
        }
        Ok(())
    }

    /// The $`\Delta`$ value used to validate the other party's shares.
    pub fn delta(&self) -> U8x16 {
        self.leaky_generator.delta()
    }

    /// Return the [`AuthShareGenerator`] associated with this generator.
    pub fn auth_share_generator(&self) -> &AuthShareGenerator<P> {
        &self.leaky_generator.auth_share_generator
    }

    /// Return the _mutable_ [`AuthShareGenerator`] associated with this generator.
    pub fn auth_share_generator_mut(&mut self) -> &mut AuthShareGenerator<P> {
        &mut self.leaky_generator.auth_share_generator
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
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
    ) -> (AndTripleGenerator<PartyA>, AndTripleGenerator<PartyB>) {
        swanky_channel::local::local_channel_pair(
            |c| AndTripleGenerator::<PartyA>::new(c, &mut rng_a),
            |c| AndTripleGenerator::<PartyB>::new(c, &mut rng_b),
        )
        .unwrap()
    }

    fn generate_triples(
        ntriples: usize,
        generator_a: &mut AndTripleGenerator<PartyA>,
        generator_b: &mut AndTripleGenerator<PartyB>,
        mut rng_a: &mut SwankyRng,
        mut rng_b: &mut SwankyRng,
    ) -> (Vec<AndTriple<PartyA>>, Vec<AndTriple<PartyB>>) {
        swanky_channel::local::local_channel_pair(
            |c| {
                let mut triples: Vec<AndTriple<PartyA>> = vec![];
                generator_a.generate(ntriples, &mut triples, c, &mut rng_a)?;
                Ok(triples)
            },
            |c| {
                let mut triples: Vec<AndTriple<PartyB>> = vec![];
                generator_b.generate(ntriples, &mut triples, c, &mut rng_b)?;
                Ok(triples)
            },
        )
        .unwrap()
    }

    fn generate_shares(
        nshares: usize,
        generator_a: &mut AndTripleGenerator<PartyA>,
        generator_b: &mut AndTripleGenerator<PartyB>,
        mut rng_a: &mut SwankyRng,
        mut rng_b: &mut SwankyRng,
    ) -> (Vec<AuthShare<PartyA>>, Vec<AuthShare<PartyB>>) {
        swanky_channel::local::local_channel_pair(
            |c| {
                let mut shares: Vec<AuthShare<PartyA>> = vec![];
                generator_a.auth_share_generator_mut().generate(
                    nshares,
                    &mut shares,
                    c,
                    &mut rng_a,
                )?;
                Ok(shares)
            },
            |c| {
                let mut shares: Vec<AuthShare<PartyB>> = vec![];
                generator_b.auth_share_generator_mut().generate(
                    nshares,
                    &mut shares,
                    c,
                    &mut rng_b,
                )?;
                Ok(shares)
            },
        )
        .unwrap()
    }

    fn validate_triples(
        generator_a: &AndTripleGenerator<PartyA>,
        generator_b: &AndTripleGenerator<PartyB>,
        triples_a: Vec<AndTriple<PartyA>>,
        triples_b: Vec<AndTriple<PartyB>>,
    ) -> (bool, bool) {
        swanky_channel::local::local_channel_pair(
            |c| {
                let result = generator_a.open(&triples_a, c);
                Ok(result.is_ok())
            },
            |c| {
                let result = generator_b.open(&triples_b, c);
                Ok(result.is_ok())
            },
        )
        .unwrap()
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn honest_generation_works(ntriples in 320..1000usize,
                                   seed_a in any::<u128>(),
                                   seed_b in any::<u128>()) {
            let mut rng_a = SwankyRng::from_seed(seed_a.into());
            let mut rng_b = SwankyRng::from_seed(seed_b.into());
            let (mut generator_a, mut generator_b) = generators(&mut rng_a, &mut rng_b);
            let (triples_a, triples_b) = generate_triples(ntriples, &mut generator_a, &mut generator_b, &mut rng_a, &mut rng_b);
            let (validation_a, validation_b) =
                validate_triples(&generator_a, &generator_b, triples_a, triples_b);
            prop_assert!(validation_a);
            prop_assert!(validation_b);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn fixing_and_triples_works(ntriples in 320..1000usize,
                                    seed_a in any::<u128>(),
                                    seed_b in any::<u128>()) {
            let mut rng_a = SwankyRng::from_seed(seed_a.into());
            let mut rng_b = SwankyRng::from_seed(seed_b.into());
            let (mut generator_a, mut generator_b) = generators(&mut rng_a, &mut rng_b);
            let (triples_a, triples_b) = generate_triples(
                ntriples,
                &mut generator_a,
                &mut generator_b,
                &mut rng_a,
                &mut rng_b,
            );
            let (shares_a, shares_b) = generate_shares(
                2 * ntriples,
                &mut generator_a,
                &mut generator_b,
                &mut rng_a,
                &mut rng_b,
            );
            // Convert the random triples to known triples.
            let mut cs_a = vec![];
            let mut cs_b = vec![];
            swanky_channel::local::local_channel_pair(
                |channel| {
                    generator_a.to_known_triple(
                        &triples_a,
                        &shares_a[..ntriples],
                        &shares_a[ntriples..],
                        &mut cs_a,
                        channel,
                    )?;
                    Ok(())
                },
                |channel| {
                    generator_b.to_known_triple(
                        &triples_b,
                        &shares_b[..ntriples],
                        &shares_b[ntriples..],
                        &mut cs_b,
                        channel,
                    )?;
                    Ok(())
                },
            )
            .unwrap();
            // Open the shares and triples to check validity.
            let ((shares_a, cs_a), (shares_b, cs_b)) = swanky_channel::local::local_channel_pair(
                |channel| {
                    let mut shares: Vec<F2> = vec![];
                    let mut cs: Vec<F2> = vec![];
                    generator_a.auth_share_generator().open(&shares_a, &mut shares, channel)?;
                    generator_a.auth_share_generator().open(&cs_a, &mut cs, channel)?;
                    Ok((shares, cs))
                },
                |channel| {
                    let mut shares: Vec<F2> = vec![];
                    let mut cs: Vec<F2> = vec![];
                    generator_b.auth_share_generator().open(&shares_b, &mut shares, channel)?;
                    generator_b.auth_share_generator().open(&cs_b, &mut cs, channel)?;
                    Ok((shares, cs))
                },
            )
            .unwrap();
            // Check validity of all the triples.
            for i in 0..ntriples {
                // `auth_share_generator().open()` should ensure that the opened
                // shares are the same.
                prop_assert_eq!(shares_a[2 * i], shares_b[2 * i]);
                prop_assert_eq!(shares_a[2 * i + 1], shares_b[2 * i + 1]);
                prop_assert_eq!(cs_a[i], cs_b[i]);
                // Check that the AND relation holds.
                let a = shares_a[i];
                let b = shares_a[ntriples + i];
                let c = cs_a[i];
                prop_assert_eq!(a * b, c);
            }
        }
    }
}
