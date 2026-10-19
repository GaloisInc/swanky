#![deny(missing_docs)]
//! Implementation of the Keller-Orsini-Scholl oblivious transfer
//! extension protocol (cf. <https://eprint.iacr.org/2015/546>).

use rand::{CryptoRng, Rng, SeedableRng};

use subtle::{ConditionallySelectable, ConstantTimeEq};
use swanky_adversary::{Malicious, SemiHonest};
use swanky_channel::Channel;
use swanky_cr_hash::TweakableCircularCorrelationRobustHash;
use swanky_error::{ErrorKind, Result, WrapErr, ensure};
use swanky_field::FiniteRing;
use swanky_field_binary::{F2, F2BitDeserializer, F2BitSerializer};
use swanky_ot_iknp::IKNP;
use swanky_ot_traits_new::{
    OTCorrelated, OTInit, OTRandom, ObliviousTransfer, Party, Receiver, Sender, WhichParty,
};
use swanky_party::{
    either::PartyEither,
    party_map::PartyMap,
    private::{PartyPrivate, PartyPrivateCopy},
};
use swanky_rng::SwankyRng;
use swanky_serialization::{SequenceDeserializer, SequenceSerializer};
use vectoreyes::U8x16;

/// The statistical security parameter.
const SSP: usize = 40;

/// The Keller-Orsini-Scholl (random) OT protocol.
///
/// Original paper: <https://eprint.iacr.org/2015/546>
pub struct KOS<
    P: Party,
    OT: ObliviousTransfer<PartyMap<P, Receiver, Sender>> + Malicious = swanky_ot_chou_orlandi_new::ChouOrlandi<
        PartyMap<P, Receiver, Sender>,
    >,
>(IKNP<P, OT>);

impl<P: Party, OT: ObliviousTransfer<PartyMap<P, Receiver, Sender>> + Malicious> KOS<P, OT> {
    /// Initialize the KOS protocol using a fixed key, `base_ot_selection_block`.
    pub fn init_fixed_key(
        base_ot_selection_block: PartyPrivate<Sender, P, U8x16>,
        channel: &mut Channel,
        rng: &mut impl CryptoRng,
    ) -> Result<Self> {
        Ok(Self(IKNP::init_with_fixed_base_ots(
            base_ot_selection_block,
            channel,
            rng,
        )?))
    }

    /// Perform initial setup communication.
    ///
    /// Runs a correlation check (Figure 7 in the linked paper).
    pub fn setup(
        &mut self,
        n_ots: usize,
        inputs: PartyPrivateCopy<Receiver, P, &[F2]>,
        channel: &mut Channel,
        rng: &mut impl CryptoRng,
    ) -> Result<Vec<u8>> {
        let n_ots = n_ots + (8 - n_ots % 8) % 8;

        let ncols = n_ots + 128 + SSP;

        let mut r: PartyPrivate<Receiver, P, _> =
            PartyPrivate::new_with(|| Vec::with_capacity((ncols / 8) + (8 - (ncols / 8) % 8) % 8))
                .zip(inputs.as_ref().into())
                .map(|(mut r, bits)| {
                    F2BitSerializer::new(&mut std::io::empty())
                        .wrap_err(
                            ErrorKind::SerializationError,
                            "Could not initialize bit serializer",
                        )?
                        .write_vec(
                            &mut r,
                            bits.iter()
                                .copied()
                                .chain((0..(ncols - n_ots)).map(|_| rand::random::<F2>())),
                        )
                        .wrap_err(ErrorKind::SerializationError, "Failed to write bits")?;
                    Ok(r)
                })
                .lift_result()?;

        let mat = self
            .0
            .setup(ncols, r.as_ref().map(|r| &r[..]).into(), channel)?;

        let mut seed = U8x16::default();
        rng.fill_bytes(seed.as_mut());

        match P::WHICH {
            WhichParty::Sender(ev) => {
                let seed = swanky_cointoss::send(channel, &[seed])?;
                let mut rng = SwankyRng::from_seed(seed[0]);

                let mut check = (U8x16::default(), U8x16::default());
                let mut chi = U8x16::default();

                for j in 0..ncols {
                    let q = U8x16::from_array(
                        <[u8; 16]>::try_from(&mat[j * 16..(j + 1) * 16])
                            .expect("The slice is exactly 16 bytes"),
                    );

                    rng.fill_bytes(chi.as_mut());

                    let [lo, hi] = q.carryless_mul_wide(chi);
                    check = (check.0 ^ lo, check.1 ^ hi);
                }

                let x = channel.read::<U8x16>()?;
                let t0 = channel.read::<U8x16>()?;
                let t1 = channel.read::<U8x16>()?;

                let [lo, hi] = x.carryless_mul_wide(self.0.base_ot_selection_block(ev));
                let check = (check.0 ^ lo, check.1 ^ hi);

                ensure!(
                    check == (t0, t1),
                    ErrorKind::OtherError,
                    "Consistency check failed"
                );
            }
            WhichParty::Receiver(ev) => {
                let seed = swanky_cointoss::receive(channel, &[seed])?;
                let mut rng = SwankyRng::from_seed(seed[0]);

                let mut x = U8x16::default();
                let mut t = (U8x16::default(), U8x16::default());

                let r_ = F2BitDeserializer::new(&mut std::io::empty())
                    .wrap_err(
                        ErrorKind::SerializationError,
                        "Could not initialize bit deserializer",
                    )?
                    .read_vec(&mut &r.as_mut().into_inner(ev)[..], ncols)
                    .wrap_err(ErrorKind::SerializationError, "Failed to read bits")?;

                let mut chi = U8x16::default();

                for (j, xj) in r_.into_iter().enumerate() {
                    let tj = U8x16::from_array(
                        <[u8; 16]>::try_from(&mat[j * 16..(j + 1) * 16])
                            .expect("The slice is exactly 16 bytes"),
                    );

                    rng.fill_bytes(chi.as_mut());
                    x ^= ConditionallySelectable::conditional_select(
                        &chi,
                        &U8x16::default(),
                        xj.ct_eq(&F2::ZERO),
                    );

                    let [lo, hi] = tj.carryless_mul_wide(chi);
                    t = (t.0 ^ lo, t.1 ^ hi);
                }

                channel.write(&x)?;
                channel.write(&t.0)?;
                channel.write(&t.1)?;
            }
        };

        Ok(mat)
    }
}

impl<P: Party, OT: ObliviousTransfer<PartyMap<P, Receiver, Sender>> + Malicious> OTInit<P>
    for KOS<P, OT>
{
    fn init(channel: &mut Channel, rng: &mut impl CryptoRng) -> Result<Self> {
        Ok(Self(IKNP::init(channel, rng)?))
    }
}

impl<P: Party, OT: ObliviousTransfer<PartyMap<P, Receiver, Sender>> + Malicious> OTRandom<P>
    for KOS<P, OT>
{
    fn ot_random<O: Extend<PartyEither<P, [U8x16; 2], U8x16>>>(
        mut self,
        inputs: PartyEither<P, usize, &[F2]>,
        outputs: &mut O,
        channel: &mut Channel,
        rng: &mut impl CryptoRng,
    ) -> Result<Self> {
        let m = inputs
            .as_ref()
            .map(|&sz| sz, |inputs| inputs.len())
            .into_inner_same();
        let inputs: PartyPrivate<Receiver, P, _> = inputs.into();
        let inputs: PartyPrivateCopy<Receiver, P, _> = inputs.into();

        let mat = self.setup(m, inputs, channel, rng)?;

        for j in 0..m {
            let q = U8x16::from_array(
                <[u8; 16]>::try_from(&mat[j * 16..(j + 1) * 16])
                    .expect("The slice is exactly 16 bytes"),
            );

            match P::WHICH {
                WhichParty::Sender(ev) => {
                    let k0 = TweakableCircularCorrelationRobustHash::fixed_key().hash(q, j as u128);
                    let k1 = TweakableCircularCorrelationRobustHash::fixed_key()
                        .hash(q ^ self.0.base_ot_selection_block(ev), j as u128);

                    outputs.extend(std::iter::once(PartyEither::new(ev, [k0, k1])));
                }
                WhichParty::Receiver(ev) => outputs.extend(std::iter::once(PartyEither::new(
                    ev,
                    TweakableCircularCorrelationRobustHash::fixed_key().hash(q, j as u128),
                ))),
            }
        }

        Ok(self)
    }
}

impl<P: Party, OT: ObliviousTransfer<PartyMap<P, Receiver, Sender>> + Malicious> OTCorrelated<P>
    for KOS<P, OT>
{
    fn ot_correlated<O: Extend<PartyEither<P, U8x16, U8x16>>>(
        mut self,
        inputs: PartyEither<P, usize, &[F2]>,
        delta: PartyPrivate<Sender, P, U8x16>,
        outputs: &mut O,
        channel: &mut Channel,
        rng: &mut impl CryptoRng,
    ) -> Result<Self> {
        let m = inputs
            .as_ref()
            .map(|&sz| sz, |inputs| inputs.len())
            .into_inner_same();
        let inputs: PartyPrivate<Receiver, P, _> = inputs.into();
        let inputs: PartyPrivateCopy<Receiver, P, _> = inputs.into();

        let mat = self.setup(m, inputs, channel, rng)?;

        for j in 0..m {
            let q = U8x16::from_array(
                <[u8; 16]>::try_from(&mat[j * 16..(j + 1) * 16])
                    .expect("The slice is exactly 16 bytes"),
            );

            match P::WHICH {
                WhichParty::Sender(ev) => {
                    let x0 = TweakableCircularCorrelationRobustHash::fixed_key().hash(q, j as u128);
                    let x1 = x0 ^ *delta.as_ref().into_inner(ev);
                    let y = TweakableCircularCorrelationRobustHash::fixed_key()
                        .hash(q ^ self.0.base_ot_selection_block(ev), j as u128)
                        ^ x1;

                    channel.write(&y)?;

                    outputs.extend(std::iter::once(PartyEither::new(ev, x0)));
                }
                WhichParty::Receiver(ev) => {
                    let h = TweakableCircularCorrelationRobustHash::fixed_key().hash(q, j as u128);

                    let y = channel.read::<U8x16>()?;
                    let y = ConditionallySelectable::conditional_select(
                        &y,
                        &U8x16::default(),
                        inputs.into_inner(ev)[j].ct_eq(&F2::ZERO),
                    );

                    outputs.extend(std::iter::once(PartyEither::new(ev, y ^ h)));
                }
            }
        }

        Ok(self)
    }
}

impl<P: Party, OT: ObliviousTransfer<PartyMap<P, Receiver, Sender>> + Malicious> SemiHonest
    for KOS<P, OT>
{
}

impl<P: Party, OT: ObliviousTransfer<PartyMap<P, Receiver, Sender>> + Malicious> Malicious
    for KOS<P, OT>
{
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_functionality() {
        swanky_ot_test_new::test_rotext::<KOS<Sender>, KOS<Receiver>>(1 << 10);
    }

    #[test]
    fn test_correlated_functionality() {
        swanky_ot_test_new::test_cotext::<KOS<Sender>, KOS<Receiver>>(1 << 10);
    }

    #[test]
    fn test_standard_functionality() {
        swanky_ot_test_new::test_otext::<KOS<Sender>, KOS<Receiver>>(1 << 10);
    }
}
