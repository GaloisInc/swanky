#![deny(missing_docs)]
//! Implementation of the Ishai-Kilian-Nissim-Petrank (IKNP)
//! semi-honest oblivious transfer extension protocol (cf.
//! <https://link.springer.com/chapter/10.1007/978-3-540-45146-4_9>),
//! using optimizations by Asharov, Lindell, Schneider, Zohner (cf.
//! <https://eprint.iacr.org/2016/602>). In particular, this
//! implements Protocol 4 from the aforementioned paper.

use std::marker::PhantomData;

use rand::{CryptoRng, Rng, SeedableRng};
use subtle::{ConditionallySelectable, ConstantTimeEq};

use swanky_adversary::SemiHonest;
use swanky_channel::Channel;
use swanky_cr_hash::CorrelationRobustHash;
use swanky_error::{ErrorKind, Result, WrapErr};
use swanky_field::FiniteRing;
use swanky_field_binary::{F2, F2BitDeserializer, F2BitSerializer};
use swanky_ot_traits_new::{
    OTCorrelated, OTInit, OTRandom, ObliviousTransfer, Party, Receiver, Sender, WhichParty,
};
use swanky_party::{
    either::PartyEither,
    party_map::{PartyMap, map_evidence_party0, map_evidence_party1},
    private::{PartyPrivate, PartyPrivateCopy},
    ty_eq::{EqualityProposition, Witness},
};
use swanky_rng::SwankyRng;
use swanky_serialization::{SequenceDeserializer, SequenceSerializer};
use vectoreyes::U8x16;

/// The number of base OTs for IKNP.
const N_BASE_OTS: usize = 128;

/// The Ishai-Kilian-Nissim-Petrank (IKNP) semi-honest oblivious
/// transfer protocol, with optimizations by
/// Asharov-Lindell-Schneider-Zohner (ALSZ).
///
/// Original IKNP paper: <https://link.springer.com/chapter/10.1007/978-3-540-45146-4_9>
///
/// ALSZ paper: <https://eprint.iacr.org/2016/602>
pub struct IKNP<
    P: Party,
    OT: ObliviousTransfer<PartyMap<P, Receiver, Sender>> = swanky_ot_chou_orlandi_new::ChouOrlandi<
        PartyMap<P, Receiver, Sender>,
    >,
> {
    // Corresponds to $`s`$ in the paper.
    base_ot_selection_bits: PartyPrivateCopy<Sender, P, [F2; N_BASE_OTS]>,
    // Represents the same value as base_ot_selection_bits.
    base_ot_selection_block: PartyPrivateCopy<Sender, P, U8x16>,
    rngs: PartyEither<P, [SwankyRng; N_BASE_OTS], [(SwankyRng, SwankyRng); N_BASE_OTS]>,
    ot: PhantomData<OT>,
}

impl<P: Party, OT: ObliviousTransfer<PartyMap<P, Receiver, Sender>>> IKNP<P, OT> {
    /// Initialize the ALSZ protocol using a fixed key, `base_ot_selection_block`.
    pub fn init_fixed_key(
        base_ot_selection_block: PartyPrivate<Sender, P, U8x16>,
        channel: &mut Channel,
        rng: &mut impl CryptoRng,
    ) -> Result<Self> {
        let ot = OT::init(channel, rng)?;

        let s: PartyPrivateCopy<Sender, _, _> = base_ot_selection_block
            .as_ref()
            .map(|s_| {
                Ok(<[F2; N_BASE_OTS]>::try_from(
                    F2BitDeserializer::new(&mut std::io::empty())
                        .wrap_err(
                            ErrorKind::SerializationError,
                            "Could not initialize bit deserializer",
                        )?
                        .read_vec(&mut &s_.as_ref()[..], N_BASE_OTS)
                        .wrap_err(ErrorKind::SerializationError, "Failed to read bits")?,
                )
                .expect("There are exactly 128 bits"))
            })
            .lift_result()?
            .into();

        let inputs: PartyEither<PartyMap<P, Receiver, Sender>, usize, &[F2]> = match P::WHICH {
            WhichParty::Sender(ev) => PartyEither::new::<Receiver>(
                map_evidence_party0::<P, _, _>(ev),
                s.as_ref().into_inner(ev),
            ),
            WhichParty::Receiver(ev) => {
                PartyEither::new::<Sender>(map_evidence_party1::<P, _, _>(ev), N_BASE_OTS)
            }
        };

        let values: PartyPrivate<Sender, PartyMap<P, Receiver, Sender>, [[U8x16; 2]; N_BASE_OTS]> =
            PartyPrivate::new_with(|| {
                [0; N_BASE_OTS].map(|_| {
                    let mut k0 = U8x16::default();
                    let mut k1 = U8x16::default();
                    rng.fill_bytes(k0.as_mut());
                    rng.fill_bytes(k1.as_mut());
                    [k0, k1]
                })
            });

        let mut outputs: PartyPrivate<Receiver, PartyMap<P, Receiver, Sender>, Vec<U8x16>> =
            PartyPrivate::new_with(|| Vec::with_capacity(N_BASE_OTS));

        ot.ot(
            inputs,
            values.as_ref().map(|values| &values[..]),
            outputs.as_mut(),
            channel,
            rng,
        )?;

        let rngs = match P::WHICH {
            WhichParty::Sender(ev) => PartyEither::new(
                ev,
                <[U8x16; N_BASE_OTS]>::try_from(
                    outputs.into_inner(map_evidence_party0::<P, _, _>(ev).sym()),
                )
                .expect("The Vec has exactly 128 elements")
                .map(SwankyRng::from_seed),
            ),
            WhichParty::Receiver(ev) => PartyEither::new(
                ev,
                values
                    .into_inner(map_evidence_party1::<P, _, _>(ev).sym())
                    .map(|ks| (SwankyRng::from_seed(ks[0]), SwankyRng::from_seed(ks[1]))),
            ),
        };

        Ok(Self {
            base_ot_selection_bits: s,
            base_ot_selection_block: base_ot_selection_block.into(),
            rngs,
            ot: PhantomData,
        })
    }

    /// Perform initial setup communication.
    ///
    /// This corresponds to substeps (a) - (c) in the OT Extension
    /// Phase of Protocol 4 of the paper linked above
    /// (<https://eprint.iacr.org/2016/602>); the return value is the
    /// matrix $`Q`$ (for the `Sender`) or $`T`$ (for the `Receiver`).
    pub fn setup(
        &mut self,
        n_ots: usize,
        selection_bits: PartyPrivateCopy<Receiver, P, &[u8]>,
        channel: &mut Channel,
    ) -> Result<Vec<u8>> {
        const NROWS: usize = 128;
        let ncols = n_ots + (8 - n_ots % 8) % 8;

        let mut u = vec![0u8; ncols / 8];

        let res = match P::WHICH {
            WhichParty::Sender(ev) => {
                let mut qs = vec![0u8; NROWS * ncols / 8];
                let zero = vec![0u8; ncols / 8];

                for (j, (&b, rng)) in self
                    .base_ot_selection_bits
                    .as_ref()
                    .into_inner(ev)
                    .iter()
                    .zip(self.rngs.as_mut().into_inner(ev).iter_mut())
                    .enumerate()
                {
                    let range = j * ncols / 8..(j + 1) * ncols / 8;
                    let q = &mut qs[range];

                    channel
                        .read_bytes(&mut u)
                        .wrap_err(ErrorKind::NetworkError, "Unable to read bytes")?;

                    rng.fill_bytes(q);

                    q.iter_mut()
                        .zip(if b.into() { u.iter() } else { zero.iter() })
                        .for_each(|(a, &b)| *a ^= b);
                }

                qs
            }
            WhichParty::Receiver(ev) => {
                let mut ts = vec![0u8; NROWS * ncols / 8];

                for j in 0..self.rngs.as_ref().into_inner(ev).len() {
                    let range = j * ncols / 8..(j + 1) * ncols / 8;
                    let t = &mut ts[range];

                    self.rngs.as_mut().into_inner(ev)[j].0.fill_bytes(t);
                    self.rngs.as_mut().into_inner(ev)[j].1.fill_bytes(&mut u);

                    u.iter_mut()
                        .zip(t.iter().zip(selection_bits.into_inner(ev).iter()))
                        .for_each(|(a, (&b, &c))| {
                            *a ^= b;
                            *a ^= c;
                        });

                    channel
                        .write_bytes(&u)
                        .wrap_err(ErrorKind::NetworkError, "Unable to write bytes")?;
                }

                ts
            }
        };

        Ok(swanky_bit_matrix_transpose::transpose(&res, NROWS, ncols))
    }

    /// Get the key, `base_ot_selection_block`, as the Sender.
    pub fn base_ot_selection_block(
        &self,
        ev: Witness<impl EqualityProposition<Sender, P>>,
    ) -> U8x16 {
        self.base_ot_selection_block.into_inner(ev)
    }
}

// Shared functionality between random / correlated OT.
//
// Returns the Q/T matrix.
fn compute_mat<P: Party, OT: ObliviousTransfer<PartyMap<P, Receiver, Sender>>>(
    alsz: &mut IKNP<P, OT>,
    n_ots: usize,
    inputs: PartyEither<P, usize, &[F2]>,
    channel: &mut Channel,
) -> Result<Vec<u8>> {
    let inputs: PartyPrivate<Receiver, P, _> = inputs.into();

    let r: PartyPrivate<Receiver, P, _> = PartyPrivate::new_with(|| {
        Vec::with_capacity((n_ots / 8) + if n_ots.is_multiple_of(8) { 0 } else { 1 })
    })
    .zip(inputs.as_ref())
    .map(|(mut r, bits)| {
        F2BitSerializer::new(&mut std::io::empty())
            .wrap_err(
                ErrorKind::SerializationError,
                "Could not initialize bit serializer",
            )?
            .write_vec(&mut r, bits.iter().copied())
            .wrap_err(ErrorKind::SerializationError, "Failed to write bits")?;
        Ok(r)
    })
    .lift_result()?;

    // This is the T matrix for the Receiver, and the Q matrix for
    // the Sender.
    alsz.setup(n_ots, r.as_ref().map(|r| &r[..]).into(), channel)
}

impl<P: Party, OT: ObliviousTransfer<PartyMap<P, Receiver, Sender>>> OTInit<P> for IKNP<P, OT> {
    fn init(channel: &mut Channel, rng: &mut impl CryptoRng) -> Result<Self> {
        let mut s_: PartyPrivate<Sender, P, _> = PartyPrivate::new(U8x16::default());
        s_.as_mut().map(|s_| rng.fill_bytes(s_.as_mut()));
        IKNP::init_fixed_key(s_, channel, rng)
    }
}

impl<P: Party, OT: ObliviousTransfer<PartyMap<P, Receiver, Sender>>> OTRandom<P> for IKNP<P, OT> {
    fn ot_random<O: Extend<PartyEither<P, [U8x16; 2], U8x16>>>(
        mut self,
        inputs: PartyEither<P, usize, &[F2]>,
        outputs: &mut O,
        channel: &mut Channel,
        _rng: &mut impl CryptoRng,
    ) -> Result<Self> {
        let m = inputs
            .as_ref()
            .map(|&sz| sz, |inputs| inputs.len())
            .into_inner_same();
        let mat = compute_mat(&mut self, m, inputs, channel)?;

        for j in 0..m {
            let q = U8x16::from_array(
                <[u8; 16]>::try_from(&mat[j * 16..(j + 1) * 16])
                    .expect("The slice is exactly 16 bytes"),
            );

            match P::WHICH {
                WhichParty::Sender(ev) => {
                    let k0 = CorrelationRobustHash::fixed_key().hash(q);
                    let k1 = CorrelationRobustHash::fixed_key()
                        .hash(q ^ self.base_ot_selection_block.into_inner(ev));

                    outputs.extend(std::iter::once(PartyEither::new(ev, [k0, k1])));
                }
                WhichParty::Receiver(ev) => outputs.extend(std::iter::once(PartyEither::new(
                    ev,
                    CorrelationRobustHash::fixed_key().hash(q),
                ))),
            }
        }

        Ok(self)
    }
}

impl<P: Party, OT: ObliviousTransfer<PartyMap<P, Receiver, Sender>>> OTCorrelated<P>
    for IKNP<P, OT>
{
    fn ot_correlated<O: Extend<PartyEither<P, U8x16, U8x16>>>(
        mut self,
        inputs: PartyEither<P, usize, &[F2]>,
        delta: PartyPrivate<Sender, P, U8x16>,
        outputs: &mut O,
        channel: &mut Channel,
        _rng: &mut impl CryptoRng,
    ) -> Result<Self> {
        let m = inputs
            .as_ref()
            .map(|&sz| sz, |inputs| inputs.len())
            .into_inner_same();
        let mat = compute_mat(&mut self, m, inputs.clone(), channel)?;

        for j in 0..m {
            let q = U8x16::from_array(
                <[u8; 16]>::try_from(&mat[j * 16..(j + 1) * 16])
                    .expect("The slice is exactly 16 bytes"),
            );

            match P::WHICH {
                WhichParty::Sender(ev) => {
                    let x0 = CorrelationRobustHash::fixed_key().hash(q);
                    let x1 = x0 ^ *delta.as_ref().into_inner(ev);
                    let y = CorrelationRobustHash::fixed_key()
                        .hash(q ^ self.base_ot_selection_block.into_inner(ev))
                        ^ x1;

                    channel.write(&y)?;

                    outputs.extend(std::iter::once(PartyEither::new(ev, x0)));
                }
                WhichParty::Receiver(ev) => {
                    let h = CorrelationRobustHash::fixed_key().hash(q);

                    let y = channel.read::<U8x16>()?;
                    let y = ConditionallySelectable::conditional_select(
                        &y,
                        &U8x16::default(),
                        inputs.as_ref().into_inner(ev)[j].ct_eq(&F2::ZERO),
                    );

                    outputs.extend(std::iter::once(PartyEither::new(ev, y ^ h)))
                }
            }
        }

        Ok(self)
    }
}

impl<P: Party, OT: ObliviousTransfer<PartyMap<P, Receiver, Sender>> + SemiHonest> SemiHonest
    for IKNP<P, OT>
{
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_functionality_pow2() {
        swanky_ot_test_new::test_rotext::<IKNP<Sender>, IKNP<Receiver>>(1 << 10);
    }

    #[test]
    fn test_random_functionality_non_pow2() {
        swanky_ot_test_new::test_rotext::<IKNP<Sender>, IKNP<Receiver>>((1 << 10) + 1);
    }

    #[test]
    fn test_correlated_functionality_pow2() {
        swanky_ot_test_new::test_cotext::<IKNP<Sender>, IKNP<Receiver>>(1 << 10);
    }

    #[test]
    fn test_correlated_functionality_non_pow2() {
        swanky_ot_test_new::test_cotext::<IKNP<Sender>, IKNP<Receiver>>((1 << 10) + 1);
    }

    #[test]
    fn test_standard_functionality_pow2() {
        swanky_ot_test_new::test_otext::<IKNP<Sender>, IKNP<Receiver>>(1 << 10);
    }

    #[test]
    fn test_standard_functionality_non_pow2() {
        swanky_ot_test_new::test_otext::<IKNP<Sender>, IKNP<Receiver>>((1 << 10) + 1);
    }
}
