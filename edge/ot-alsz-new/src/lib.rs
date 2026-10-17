#![deny(missing_docs)]
//! Implementation of the Asharov-Lindell-Schneider-Zohner oblivious
//! transfer extension protocol (cf.
//! <https://eprint.iacr.org/2016/602>, Protocol 4).

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
};
use swanky_rng::SwankyRng;
use swanky_serialization::{SequenceDeserializer, SequenceSerializer};
use vectoreyes::U8x16;

/// The Asharov-Lindell-Schneider-Zohner (random) OT protocol.
///
/// Original paper: <https://eprint.iacr.org/2016/602>
pub struct ALSZ<
    P: Party,
    OT: ObliviousTransfer<PartyMap<P, Receiver, Sender>> = swanky_ot_chou_orlandi_new::ChouOrlandi<
        PartyMap<P, Receiver, Sender>,
    >,
> {
    s: PartyPrivateCopy<Sender, P, [F2; 128]>,
    s_: PartyPrivateCopy<Sender, P, U8x16>,
    rngs: PartyEither<P, [SwankyRng; 128], [(SwankyRng, SwankyRng); 128]>,
    ot: PhantomData<OT>,
}

impl<P: Party, OT: ObliviousTransfer<PartyMap<P, Receiver, Sender>>> ALSZ<P, OT> {
    /// Initialize the ALSZ protocol using a fixed key, `s_`.
    pub fn init_fixed_key(
        s_: PartyPrivate<Sender, P, [u8; 16]>,
        channel: &mut Channel,
        rng: &mut impl CryptoRng,
    ) -> Result<Self> {
        let ot = OT::init(channel, rng)?;

        let s: PartyPrivateCopy<Sender, _, _> = s_
            .as_ref()
            .map(|s_| {
                Ok(<[F2; 128]>::try_from(
                    F2BitDeserializer::new(&mut std::io::empty())
                        .wrap_err(
                            ErrorKind::SerializationError,
                            "Could not initialize bit deserializer",
                        )?
                        .read_vec(&mut &s_[..], 8 * 16)
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
                PartyEither::new::<Sender>(map_evidence_party1::<P, _, _>(ev), 128)
            }
        };

        let values: PartyPrivate<Sender, PartyMap<P, Receiver, Sender>, [[U8x16; 2]; 128]> =
            PartyPrivate::new_with(|| {
                [0; 128].map(|_| {
                    let mut k0 = U8x16::default();
                    let mut k1 = U8x16::default();
                    rng.fill_bytes(k0.as_mut());
                    rng.fill_bytes(k1.as_mut());
                    [k0, k1]
                })
            });

        let mut outputs: PartyPrivate<Receiver, PartyMap<P, Receiver, Sender>, Vec<U8x16>> =
            PartyPrivate::new_with(|| Vec::with_capacity(128));

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
                <[U8x16; 128]>::try_from(
                    outputs.into_inner(map_evidence_party0::<P, _, _>(ev).sym()),
                )
                .expect("The Vec has exactly 128 elements")
                .map(|output| SwankyRng::from_seed(output)),
            ),
            WhichParty::Receiver(ev) => PartyEither::new(
                ev,
                values
                    .into_inner(map_evidence_party1::<P, _, _>(ev).sym())
                    .map(|ks| (SwankyRng::from_seed(ks[0]), SwankyRng::from_seed(ks[1]))),
            ),
        };

        Ok(Self {
            s,
            s_: s_.map(|s_| U8x16::from_array(s_)).into(),
            rngs,
            ot: PhantomData,
        })
    }

    /// Perform initial setup communication.
    ///
    /// This corresponds to substeps (a) - (c) in Protocol 4 of the
    /// paper linked above (<https://eprint.iacr.org/2016/602>); the
    /// return value is the matrix $`Q`$.
    pub fn setup(
        &mut self,
        m: usize,
        r: PartyPrivateCopy<Receiver, P, &[u8]>,
        channel: &mut Channel,
    ) -> Result<Vec<u8>> {
        const NROWS: usize = 128;
        let ncols = m + (8 - m % 8) % 8;

        let mut u = vec![0u8; ncols / 8];

        let res = match P::WHICH {
            WhichParty::Sender(ev) => {
                let mut qs = vec![0u8; NROWS * ncols / 8];
                let zero = vec![0u8; ncols / 8];

                for (j, (&b, rng)) in self
                    .s
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
                        .zip(t.iter().zip(r.into_inner(ev).iter()))
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
}

// Shared functionality between random / correlated OT.
//
// Returns the Q/T matrix.
fn compute_mat<P: Party, OT: ObliviousTransfer<PartyMap<P, Receiver, Sender>>>(
    alsz: &mut ALSZ<P, OT>,
    m: usize,
    inputs: PartyEither<P, usize, &[F2]>,
    channel: &mut Channel,
) -> Result<Vec<u8>> {
    let inputs: PartyPrivate<Receiver, P, _> = inputs.into();

    let r: PartyPrivate<Receiver, P, _> = PartyPrivate::new_with(|| {
        Vec::with_capacity((m / 8) + if m.is_multiple_of(8) { 0 } else { 1 })
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
    alsz.setup(m, r.as_ref().map(|r| &r[..]).into(), channel)
}

impl<P: Party, OT: ObliviousTransfer<PartyMap<P, Receiver, Sender>>> OTInit<P> for ALSZ<P, OT> {
    fn init(channel: &mut Channel, rng: &mut impl CryptoRng) -> Result<Self> {
        let mut s_: PartyPrivate<Sender, P, _> = PartyPrivate::new([0u8; 16]);
        s_.as_mut().map(|s_| rng.fill_bytes(s_));
        ALSZ::init_fixed_key(s_, channel, rng)
    }
}

impl<P: Party, OT: ObliviousTransfer<PartyMap<P, Receiver, Sender>>> OTRandom<P> for ALSZ<P, OT> {
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
                    let k1 = CorrelationRobustHash::fixed_key().hash(q ^ self.s_.into_inner(ev));

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
    for ALSZ<P, OT>
{
    fn ot_correlated<O: Extend<PartyEither<P, U8x16, U8x16>>>(
        mut self,
        inputs: PartyEither<P, usize, &[F2]>,
        delta: PartyPrivate<P, Sender, U8x16>,
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
                    let y =
                        CorrelationRobustHash::fixed_key().hash(q ^ self.s_.into_inner(ev)) ^ x1;

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
    for ALSZ<P, OT>
{
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_functionality() {
        swanky_ot_test_new::test_rotext::<ALSZ<Sender>, ALSZ<Receiver>>(1 << 10);
    }

    #[test]
    fn test_correlated_functionality() {
        swanky_ot_test_new::test_cotext::<ALSZ<Sender>, ALSZ<Receiver>>(1 << 10);
    }

    #[test]
    fn test_standard_functionality() {
        swanky_ot_test_new::test_otext::<ALSZ<Sender>, ALSZ<Receiver>>(1 << 10);
    }
}
