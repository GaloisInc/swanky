//! Leaky AND triples.
//!
//! An authenticated AND triple is a random authenticated triple $`(\langle x
//! \rangle, \langle y \rangle, \langle z \rangle)`$ [^1] such that $`x \cdot y
//! = z`$. A _leaky_ AND triple is an authenticated AND triple where the
//! adversary can guess the value of $`x`$: if correct this remains undetected,
//! if incorrect the adversary is caught.
//!
//! The leaky AND triple generation protocol implemented here is from Figure 5
//! of Katz et al. [^2].
//!
//! [^1]: See [`crate::authshares`] for the definition of the $`\langle x
//! \rangle`$ notation.
//!
//! [^2]: J. Katz, S. Ranellucci, M. Rosulek, X. Wang. "Optimizing Authenticated
//! Garbling for Faster Secure Two-Party Computation".
//! <https://eprint.iacr.org/2018/578.pdf>

use crate::{
    and_triples::AndTriple,
    authshares::{AuthShare, AuthShareGenerator},
};
use itertools::Itertools;
use rand::{CryptoRng, Rng, RngExt};
use swanky_channel::Channel;
use swanky_error::{ErrorKind, WrapErr};
use swanky_f_eq::EqualityFunctionality;
use swanky_field::FiniteRing;
use swanky_field_binary::{F2, F2BitDeserializer, F2BitSerializer, F128b};
use swanky_party::{GenericParty, GenericWhichParty};
use swanky_serialization::{CanonicalSerialize, SequenceDeserializer, SequenceSerializer};
use vectoreyes::U8x16;

/// A leaky AND triple.
///
/// See [`crate::leaky_and_triples`] for details.
#[derive(Clone, Copy)]
pub(crate) struct LeakyAndTriple<P: GenericParty> {
    /// The authenticated share $`\langle x \rangle`$.
    x: AuthShare<P>,
    /// The authenticated share $`\langle y \rangle`$.
    y: AuthShare<P>,
    /// The authenticated share $`\langle z \rangle`$ such that $`z = x \cdot
    /// y`$.
    z: AuthShare<P>,
}

impl<P: GenericParty> LeakyAndTriple<P> {
    /// The authenticated share $`\langle x \rangle`$.
    pub(crate) fn x(&self) -> AuthShare<P> {
        self.x
    }

    /// The authenticated share $`\langle y \rangle`$.
    pub(crate) fn y(&self) -> AuthShare<P> {
        self.y
    }

    /// The authenticated share $`\langle z \rangle`$ such that $`z = x \cdot
    /// y`$.
    pub(crate) fn z(&self) -> AuthShare<P> {
        self.z
    }
}

/// A type for generating [`LeakyAndTriple`]s.
pub(crate) struct LeakyAndTripleGenerator<P: GenericParty> {
    pub(crate) auth_share_generator: AuthShareGenerator<P>,
}

impl<P: GenericParty> LeakyAndTripleGenerator<P> {
    /// Generate a valid Δ that can be used by the [`LeakyAndTripleGenerator`]
    ///
    /// The AND and Leaky AND triple generation protocols require that parties
    /// have Δ with different least significant bits (lsb). Towards that we
    /// require that Party0's Δ has lsb == 1 and Party1's Δ has lsb == 0.
    pub(crate) fn generate_valid_delta<RNG: CryptoRng + Rng>(rng: &mut RNG) -> U8x16 {
        let delta = rng.random::<F128b>();
        // We require that for Party A `lsb(Δ) = 1`, and for Party
        // B `lsb(Δ) = 0`. So adjust `delta` as needed.
        let delta = match P::GENERIC_WHICH {
            GenericWhichParty::Party0(_) => {
                if delta.lsb() == F2::ZERO {
                    delta + F128b::ONE
                } else {
                    delta
                }
            }
            GenericWhichParty::Party1(_) => {
                if delta.lsb() == F2::ONE {
                    delta + F128b::ONE
                } else {
                    delta
                }
            }
        };
        U8x16::from(delta)
    }

    /// Create a new [`LeakyAndTripleGenerator`].
    pub(crate) fn new<RNG: CryptoRng + Rng>(
        channel: &mut Channel,
        rng: &mut RNG,
    ) -> swanky_error::Result<Self> {
        let delta = Self::generate_valid_delta(rng);
        Self::new_with_delta(delta, channel, rng)
    }

    /// Create a new [`LeakyAndTripleGenerator`] with a supplied $`\Delta`$
    /// value.
    ///
    /// # Panics
    /// This panics if $`\mathsf{lsb}(\Delta_\mathsf{A}) \neq 1`$ or if
    /// $`\mathsf{lsb}(\Delta_\mathsf{B}) \neq 0`$.
    pub(crate) fn new_with_delta<RNG: CryptoRng + Rng>(
        delta: U8x16,
        channel: &mut Channel,
        rng: &mut RNG,
    ) -> swanky_error::Result<Self> {
        match P::GENERIC_WHICH {
            GenericWhichParty::Party0(_) => {
                assert_eq!(F128b::from(delta).lsb(), F2::ONE)
            }
            GenericWhichParty::Party1(_) => {
                assert_eq!(F128b::from(delta).lsb(), F2::ZERO)
            }
        }
        let auth_share_generator = AuthShareGenerator::new_with_delta(delta, channel, rng)?;
        Ok(Self {
            auth_share_generator,
        })
    }

    /// Generate a vector of leaky AND triples.
    ///
    /// This implements the $`\Pi_{\mathsf{Land}}`$ protocol (Figure 5) from
    /// Katz et al. [^1].
    ///
    /// [^1]: J. Katz, S. Ranellucci, M. Rosulek, X. Wang. "Optimizing
    /// Authenticated Garbling for Faster Secure Two-Party Computation".
    /// <https://eprint.iacr.org/2018/578.pdf>
    pub(crate) fn generate<RNG: CryptoRng + Rng>(
        &mut self,
        ntriples: usize,
        out: &mut Vec<LeakyAndTriple<P>>,
        channel: &mut Channel,
        rng: &mut RNG,
    ) -> swanky_error::Result<()> {
        // The protocol works as follows.
        //
        // The parties begin by generating random shares, and viewing them as an
        // "uncorrelated" AND triple `(⟨x₁|x₂⟩, ⟨y₁|y₂⟩, ⟨z₁|r⟩)`. The goal then
        // is to turn the share `⟨r⟩` into a "correlated" share `⟨z₂⟩`.
        //
        // To do this, we want to find the (public) `d` such that
        // ```
        // ([x₁] ⊕ [x₂])([y₁] ⊕ [y₂]) ⊕ [z₁] ⊕ [r] ⊕ d = 0
        // ```
        // Then, we can compute `[z₂] = [r] ⊕ d`, and we're done.
        //
        // Now, consider computing the following:
        // ```
        // S = ((x₁ ⊕ x₂)(y₁ ⊕ y₂) ⊕ z₁ ⊕ r)(Δ₁ ⊕ Δ₂)
        // ```
        // And recall that we enforce at initialization time that
        // ```
        // lsb(Δ₁ ⊕ Δ₂) = 1
        // ```
        // Thus, if `((x₁ ⊕ x₂)(y₁ ⊕ y₂) ⊕ z₁ ⊕ r) = 0` (⇒ `d = 0`) then `S =
        // 0`, and if `((x₁ ⊕ x₂)(y₁ ⊕ y₂) ⊕ z₁ ⊕ r) = 1` (⇒ `d = 1`) then `S =
        // Δ₁ ⊕ Δ₂`, and hence `lsb(S) = d`. So the goal then is to compute `S`.
        //
        // Consider the `x₂(y₁ ⊕ y₂)(Δ₁ ⊕ Δ₂)` portion of `S`. The `(y₁ ⊕ y₂)(Δ₁
        // ⊕ Δ₂)` portion can be computed as `C₁ ⊕ C₂` where
        // ```
        // C₁ = y₁ Δ₁ ⊕ K[y₂] ⊕ M[y₁]
        // C₂ = y₂ Δ₂ ⊕ K[y₁] ⊕ M[y₂]
        // ```
        // These computations are entirely local to each party.
        //
        // Now, we can compute `S` as:
        // ```
        // S = x₁(C₁ ⊕ C₂) ⊕ x₂(C₁ ⊕ C₂) ⊕ (z₁ ⊕ r)(Δ₁ ⊕ Δ₂)
        // ```
        // Each `xₚ(C₁ ⊕ C₂)` can be computed using Half-Gates, since the `xₚ`
        // is known to one of the parties. (The details of Half-Gates won't be
        // described here, but that is where the `G` and `E` variables come from
        // in the implementation.)
        //
        // Likewise, `(z₁ ⊕ r)(Δ₁ ⊕ Δ₂)` can be computed as `Z = Z₁ ⊕ Z₂` where:
        // ```
        // Z₁ = z₁ Δ₁ ⊕ K[r] ⊕ M[z₁]
        // Z₂ = r  Δ₂ ⊕ K[z₁] ⊕ M[r]
        // ```
        // Again, this is entirely local to each party.
        //
        // Thus, we can compute `S = S₁ ⊕ S₂` and thus compute (public) bit `d`
        // as `lsb(S₁) ⊕ lsb(S₂)`.
        //
        // Lastly, to enforce no party cheated in revealing their share of `d`,
        // we check equality, since it should be the case that `S₁ ⊕ dΔ₁ = S₂ ⊕
        // dΔ₂` (since by construction, `S₁ ⊕ S₂ =  = d(Δ₁ ⊕ Δ₂)`).

        let nshares = 3 * ntriples;
        let delta = F128b::from(self.auth_share_generator.delta());
        let mut shares = Vec::with_capacity(nshares);

        // A and B obtain random authenticated shares `(⟨x₁|x₂⟩, ⟨y₁|y₂⟩,
        // ⟨z₁|r⟩)`.
        self.auth_share_generator
            .generate(nshares, &mut shares, channel, rng)?;

        // We need to compute `H(K[x])` twice below, so we cache the result to
        // save on hashing the same value twice.
        let hashed_x_keys: Vec<_> = shares
            .iter()
            .tuples()
            .map(|(x, _, _)| hash(F128b::from(x.key())))
            .collect();

        // A and B locally compute `Cₚ = y Δ + K[y] + M[y]` for all `y`.
        // These values correspond to shares of some `C = C₁ ⊕ C₂` such that
        // ```
        // C = (y₁ ⊕ y₂)(Δ₁ ⊕ Δ₂)
        // ```
        let cs: Vec<F128b> = shares
            .iter()
            .tuples()
            .map(|(_, y, _)| y.bit() * delta + F128b::from(y.key()) + F128b::from(y.mac()))
            .collect();

        let mut ss = Vec::with_capacity(ntriples);

        // A and B compute the Half-Gates computations of `x₁(C₁ ⊕ C₂)` and
        // `x₂(C₁ ⊕ C₂)`.

        // Function for sending `G := H(K[x] + Δ) + H(K[x]) + C`.
        let send_g = |x: &AuthShare<P>,
                      c: F128b,
                      hashed_x_key: F128b,
                      channel: &mut Channel|
         -> swanky_error::Result<()> {
            let g = hash(F128b::from(x.key()) + delta) + hashed_x_key + c;
            channel.write(&g)?;
            Ok(())
        };
        // Function for receiving `G` and computing `E := x G + H(M[x]) + x C`
        // and `S := H(K[x]) + E + (z Δ + K[z] + M[z])`.
        let mut receive_g_and_compute_s = |x: &AuthShare<P>,
                                           z: &AuthShare<P>,
                                           c: F128b,
                                           hashed_x_key: F128b,
                                           channel: &mut Channel|
         -> swanky_error::Result<()> {
            let g = channel.read::<F128b>()?;
            let e = x.bit() * g + hash(x.mac().into()) + x.bit() * c;
            let s =
                hashed_x_key + e + z.bit() * delta + F128b::from(z.key()) + F128b::from(z.mac());
            ss.push(s);
            Ok(())
        };

        // Compute shares of `S` using the above functions.
        for (((x, _, z), c), hashed_x_key) in shares
            .iter()
            .tuples()
            .zip(cs.iter())
            .zip(hashed_x_keys.iter())
        {
            match P::GENERIC_WHICH {
                GenericWhichParty::Party0(_) => {
                    send_g(x, *c, *hashed_x_key, channel)?;
                }
                GenericWhichParty::Party1(_) => {
                    receive_g_and_compute_s(x, z, *c, *hashed_x_key, channel)?;
                }
            }
        }
        for (((x, _, z), c), hashed_x_key) in shares
            .iter()
            .tuples()
            .zip(cs.iter())
            .zip(hashed_x_keys.iter())
        {
            match P::GENERIC_WHICH {
                GenericWhichParty::Party0(_) => {
                    receive_g_and_compute_s(x, z, *c, *hashed_x_key, channel)?;
                }
                GenericWhichParty::Party1(_) => {
                    send_g(x, *c, *hashed_x_key, channel)?;
                }
            }
        }

        let mut feq = EqualityFunctionality::<P>::new(rng);

        // Function for sending the LSB `d` of each party's share of `S`.
        let send_lsb = |channel: &mut Channel| -> swanky_error::Result<()> {
            let mut serializer: F2BitSerializer = SequenceSerializer::new(&mut channel.as_std_io())
                .wrap_err(
                    ErrorKind::InitializationError,
                    "Failed to initialize bit sequence serializer.",
                )?;
            for s in ss.iter() {
                let lsb_s_mine = s.lsb();
                serializer
                    .write(channel.as_std_io(), lsb_s_mine)
                    .wrap_err(ErrorKind::NetworkError, "Failed to write LSB.")?;
            }
            serializer.finish(channel.as_std_io()).wrap_err(
                ErrorKind::SerializationError,
                "Failed to finalize bit serialization.",
            )?;
            Ok(())
        };
        // Function for receiving the LSB of each party's share of `S`, sending
        // `L := S + dΔ` to `Feq`, and output the updated triple.
        let receive_lsb = |channel: &mut Channel| -> swanky_error::Result<()> {
            let mut deserializer: F2BitDeserializer =
                SequenceDeserializer::new(&mut channel.as_std_io()).wrap_err(
                    ErrorKind::InitializationError,
                    "Failed to initialize bit sequence deserializer.",
                )?;
            for ((x, y, z), s) in shares.into_iter().tuples().zip(ss.iter()) {
                let lsb_s_mine = s.lsb();
                let lsb_s_other = deserializer
                    .read(channel.as_std_io())
                    .wrap_err(ErrorKind::NetworkError, "Failed to read LSB.")?;
                let d = lsb_s_mine + lsb_s_other;
                // Send `L := S + dΔ` to `Feq`.
                feq.input(U8x16::from(s + d * delta));
                // Compute `⟨z'⟩ := ⟨z⟩ ⊕ d`.
                let z_new = self.auth_share_generator.xor_with_const(z, d);
                let triple = LeakyAndTriple { x, y, z: z_new };
                out.push(triple);
            }
            Ok(())
        };

        // Compute the correction bit `d` and output the updating triples using
        // the above functions.
        match P::GENERIC_WHICH {
            GenericWhichParty::Party0(_) => {
                send_lsb(channel)?;
                receive_lsb(channel)?;
            }
            GenericWhichParty::Party1(_) => {
                receive_lsb(channel)?;
                send_lsb(channel)?;
            }
        }
        // Check the equality on all the `L` values to enforce proper behavior.
        feq.finalize(channel)
    }

    /// Open the (leaky) AND triples in `triples` using a supplied $`\Delta`$ value.
    ///
    /// This corresponds to opening each of the underlying authenticated shares.
    pub(crate) fn open_with_delta(
        triples: &[LeakyAndTriple<P>],
        delta: U8x16,
        channel: &mut Channel,
    ) -> swanky_error::Result<()> {
        // Flatten triples into a vector of shares so we can call
        // `AuthShareGenerator::open` on the shares.
        let shares: Vec<AuthShare<_>> = triples
            .iter()
            .flat_map(|triple| [triple.x, triple.y, triple.z])
            .collect();
        let mut out = Vec::with_capacity(3 * triples.len());
        AuthShareGenerator::open_with_delta(&shares, delta, &mut out, channel)?;
        // Confirm when testing that all the triples are indeed valid.
        #[cfg(test)]
        {
            for (i, triple) in out.as_chunks::<3>().0.iter().enumerate() {
                assert_eq!(triple[0] * triple[1], triple[2], "Iteration {i} failed");
            }
        }
        Ok(())
    }

    /// Combines a vector of $`B \cdot N`$ randomly permuted [`LeakyAndTriple`]s
    /// into $`N`$ [`AndTriple`]s, where $`B`$ denotes the bucket size and $`N`$
    /// denotes the number of AND triples produced.
    ///
    /// This implements the $`\Pi_{\mathsf{aAND}}`$ protocol (Figure 9) from
    /// Wang et al. [^1].
    ///
    /// # Security
    /// This assumes that the bucket size $`B`$ is correct for the given number
    /// $`N`$ of (non-leaky) AND triples produced:
    ///
    /// | ≥ # Triples | Bucket Size |
    /// | :---------: | :---------: |
    /// |         320 |           5 |
    /// |       3,100 |           4 |
    /// |     280,000 |           3 |
    ///
    /// That is, if you want to create $`N`$ triples, you need to generate $`B
    /// \cdot N`$ leaky-AND triples, randomly permute the triples, and then call
    /// `combine` with bucket size $`B`$. See Table 4 from Wang et al. [^1] (the
    /// number of triples above is for a statistical security parameter of 40
    /// bits).
    ///
    /// This implies that _there is no security guarantee_ when generating fewer
    /// than 320 triples!
    ///
    /// # Panics
    /// This panics if `bucket_size ∉ {3, 4, 5}`, if `bucket_size` does not
    /// divide `leaky_ands.len()`, or if `leaky_ands` is empty.
    ///
    /// [^1]: X. Wang, S. Ranellucci, J. Katz. "Authenticated Garbling and
    /// Efficient Maliciously Secure Two-Party Computation".
    /// <https://eprint.iacr.org/2017/030.pdf>
    pub(crate) fn combine(
        &self,
        leaky_ands: &[LeakyAndTriple<P>],
        out: &mut Vec<AndTriple<P>>,
        bucket_size: usize,
        channel: &mut Channel,
    ) -> swanky_error::Result<()> {
        // This protocol works by combining `B` leaky AND triples into one
        // non-leaky AND triple in an iterative way. Two leaky AND triples
        // `(⟨x₁|x₂⟩, ⟨y₁|y₂⟩, ⟨z₁|z₂⟩)` and `(⟨x'₁|x'₂⟩, ⟨y'₁|y'₂⟩, ⟨z'₁|z'₂⟩)`
        // are combined as follows:
        //
        // 1. Each party computes `dᵢ = yᵢ ⊕ y'ᵢ` and reveals `dᵢ` to the other
        //    party, who checks its validity.
        // 2. Each party computes `d = d₁ ⊕ d₂`.
        // 3. The parties output a new AND triple as:
        //    `(⟨x₁ ⊕ x'₁         |         x₂ ⊕ x'₂⟩,
        //      ⟨y₁               |               y₂⟩,
        //      ⟨z₁ ⊕ z'₁ ⊕ d x'₁ | z₂ ⊕ z'₂ ⊕ d x'₂⟩)`
        //
        // The protocol then proceeds to combine the newly produced AND triple
        // with the next one in the bucket, resulting in one final (non-leaky)
        // AND triple that combines all `B` leaky AND triples.
        //
        // The implementation below optimizes the above protocol as follows.
        // Instead of revealing the `d`s one at a time, it instead computes all
        // the `d`s up front and opens them all in one fell swoop.
        assert!(bucket_size == 3 || bucket_size == 4 || bucket_size == 5);
        assert_eq!(leaky_ands.len() % bucket_size, 0);
        assert!(!leaky_ands.is_empty());

        let nbuckets = leaky_ands.len() / bucket_size;
        let mut ds = Vec::with_capacity((bucket_size - 1) * nbuckets);
        let mut ds_opened = Vec::with_capacity((bucket_size - 1) * nbuckets);

        for bucket in leaky_ands.chunks_exact(bucket_size) {
            bucket.iter().skip(1).map(|triple| triple.y()).fold(
                bucket.first().unwrap().y(),
                |y, y_| {
                    // Compute `⟨d⟩ := ⟨y⟩ ⊕ ⟨y'⟩` and save it for opening later.
                    ds.push(y ^ y_);
                    // The combined AND triple uses only `⟨y⟩` and not ⟨y'⟩, so
                    // return it as part of our fold. This means that the `i`th
                    // `⟨d⟩` value is an XOR of the `⟨y⟩` value from the first
                    // bucket entry with the `⟨y⟩` value from the `i+1`th bucket
                    // entry.
                    y
                },
            );
        }

        // Open the `⟨d⟩`s in one shot. This is much more efficient than opening
        // the `⟨d⟩`s on a per-bucket basis.
        AuthShareGenerator::open_with_delta(&ds, self.delta(), &mut ds_opened, channel)?;

        for (bucket, ds_opened) in leaky_ands
            .chunks_exact(bucket_size)
            .zip(ds_opened.chunks_exact(bucket_size - 1))
        {
            // Compute the resulting triple as:
            //   ⟨x''⟩ := ⟨x⟩ ⊕ ⟨x'⟩
            //   ⟨y''⟩ := ⟨y⟩
            //   ⟨z''⟩ := ⟨z⟩ ⊕ ⟨z'⟩ ⊕ d ⟨x'⟩
            let triple = bucket.iter().skip(1).zip(ds_opened).fold(
                *bucket.first().unwrap(),
                |acc, (triple, d)| LeakyAndTriple {
                    x: acc.x ^ triple.x,
                    y: acc.y,
                    z: if *d == F2::ONE {
                        acc.z ^ triple.z ^ triple.x
                    } else {
                        acc.z ^ triple.z
                    },
                },
            );
            out.push(triple.into());
        }
        Ok(())
    }

    /// The $`\Delta`$ value used to validate the other party's shares.
    pub(crate) fn delta(&self) -> U8x16 {
        self.auth_share_generator.delta()
    }
}

fn hash(input: F128b) -> F128b {
    // Implement the hash function using Blake3.
    //
    // TODO: It _might_ be safe to use a correlation-robust fixed-key hash
    // function here. However, the proof as-is is in the random oracle model,
    // and effort would need to be spent to validate that it is still secure in
    // the correlation-robust hash function model!
    let mut hasher = blake3::Hasher::new();
    hasher.update(&U8x16::from(input).to_bytes());
    let hash = *hasher.finalize().as_bytes();
    let result: [u8; 16] = hash[0..16].try_into().unwrap();
    F128b::from(U8x16::from(result))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytemuck::TransparentWrapper;
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
    ) -> (
        LeakyAndTripleGenerator<PartyA>,
        LeakyAndTripleGenerator<PartyB>,
    ) {
        swanky_channel::local::local_channel_pair(
            |c| LeakyAndTripleGenerator::<PartyA>::new(c, &mut rng_a),
            |c| LeakyAndTripleGenerator::<PartyB>::new(c, &mut rng_b),
        )
        .unwrap()
    }

    fn generate_triples(
        ntriples: usize,
        generator_a: &mut LeakyAndTripleGenerator<PartyA>,
        generator_b: &mut LeakyAndTripleGenerator<PartyB>,
        mut rng_a: &mut SwankyRng,
        mut rng_b: &mut SwankyRng,
    ) -> (Vec<LeakyAndTriple<PartyA>>, Vec<LeakyAndTriple<PartyB>>) {
        swanky_channel::local::local_channel_pair(
            |c| {
                let mut triples: Vec<LeakyAndTriple<PartyA>> = vec![];
                generator_a.generate(ntriples, &mut triples, c, &mut rng_a)?;
                Ok(triples)
            },
            |c| {
                let mut triples: Vec<LeakyAndTriple<PartyB>> = vec![];
                generator_b.generate(ntriples, &mut triples, c, &mut rng_b)?;
                Ok(triples)
            },
        )
        .unwrap()
    }

    fn validate(
        generator_a: &LeakyAndTripleGenerator<PartyA>,
        generator_b: &LeakyAndTripleGenerator<PartyB>,
        output_a: Vec<LeakyAndTriple<PartyA>>,
        output_b: Vec<LeakyAndTriple<PartyB>>,
    ) -> (bool, bool) {
        swanky_channel::local::local_channel_pair(
            |c| {
                let result =
                    LeakyAndTripleGenerator::open_with_delta(&output_a, generator_a.delta(), c);
                Ok(result.is_ok())
            },
            |c| {
                let result =
                    LeakyAndTripleGenerator::open_with_delta(&output_b, generator_b.delta(), c);
                Ok(result.is_ok())
            },
        )
        .unwrap()
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn honest_generation_works(ntriples in 1..10000usize,
                                   seed_a in any::<u128>(),
                                   seed_b in any::<u128>()) {
            let mut rng_a = SwankyRng::from_seed(seed_a.into());
            let mut rng_b = SwankyRng::from_seed(seed_b.into());
            let (mut generator_a, mut generator_b) = generators(&mut rng_a, &mut rng_b);
            let (triples_a, triples_b) = generate_triples(ntriples, &mut generator_a, &mut generator_b, &mut rng_a, &mut rng_b);
            let (validation_a, validation_b) =
                validate(&generator_a, &generator_b, triples_a, triples_b);
            prop_assert!(validation_a);
            prop_assert!(validation_b);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn combine_works(ntriples in 320..3100usize,
                         seed_a in any::<u128>(),
                         seed_b in any::<u128>()) {
            let bucket_size = 5;
            let nleaky = ntriples * bucket_size;
            let mut rng_a = SwankyRng::from_seed(seed_a.into());
            let mut rng_b = SwankyRng::from_seed(seed_b.into());
            let (mut generator_a, mut generator_b) = generators(&mut rng_a, &mut rng_b);
            let (triples_a, triples_b) = generate_triples(nleaky, &mut generator_a, &mut generator_b, &mut rng_a, &mut rng_b);
            swanky_channel::local::local_channel_pair(
                |channel| {
                    let mut out = vec![];
                    generator_a.combine(&triples_a, &mut out, bucket_size, channel).unwrap();
                    let result = LeakyAndTripleGenerator::open_with_delta(AndTriple::peel_slice(&out), generator_a.delta(), channel);
                    assert!(result.is_ok());
                    Ok(())
                },
                |channel| {
                    let mut out = vec![];
                    generator_b.combine(&triples_b, &mut out, bucket_size, channel).unwrap();
                    let result = LeakyAndTripleGenerator::open_with_delta(AndTriple::peel_slice(&out), generator_b.delta(), channel);
                    assert!(result.is_ok());
                    Ok(())
                },
            )
            .unwrap();
        }
    }
}
