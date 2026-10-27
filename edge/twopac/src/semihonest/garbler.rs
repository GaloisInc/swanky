use fancy_garbling::{Garbler as Gb, WireLabel, WireMod2};
use fancy_traits::{Fancy, FancyBinary, FancyConstant, FancyEncode, FancyOutput};
use rand::{CryptoRng, RngExt, SeedableRng};
use swanky_adversary::SemiHonest;
use swanky_channel::Channel;
use swanky_error::{ErrorKind, WrapErr};
use swanky_field::FiniteRing;
use swanky_field_binary::F2;
use swanky_ot_traits_new::{ObliviousTransfer, Sender};
use swanky_party::{either::PartyEither, private::PartyPrivate, ty_eq::Witness};
use vectoreyes::U8x16;

/// Semi-honest garbler.
pub struct Garbler<RNG, OT, Wire> {
    garbler: Gb<RNG, Wire>,
    ot: OT,
    rng: RNG,
}

impl<OT, RNG, Wire> std::ops::Deref for Garbler<RNG, OT, Wire> {
    type Target = Gb<RNG, Wire>;
    fn deref(&self) -> &Self::Target {
        &self.garbler
    }
}

impl<OT, RNG, Wire> std::ops::DerefMut for Garbler<RNG, OT, Wire> {
    fn deref_mut(&mut self) -> &mut Gb<RNG, Wire> {
        &mut self.garbler
    }
}

impl<
    RNG: CryptoRng + SeedableRng<Seed = U8x16>,
    OT: ObliviousTransfer<Sender> + SemiHonest,
    Wire: WireLabel<F2>,
> Garbler<RNG, OT, Wire>
{
    /// Make a new `Garbler`.
    pub fn new(channel: &mut Channel, mut rng: RNG) -> swanky_error::Result<Self> {
        let ot = OT::init(channel, &mut rng)
            .wrap_err(ErrorKind::InitializationError, "Failed to initialize OT.")?;

        let garbler = Gb::new(RNG::from_seed(rng.random()));
        Ok(Garbler { garbler, ot, rng })
    }
}

impl<RNG: CryptoRng + SeedableRng<Seed = U8x16>, OT: ObliviousTransfer<Sender> + SemiHonest>
    FancyBinary for Garbler<RNG, OT, WireMod2>
{
    fn negate(&mut self, x: &Self::Item) -> Self::Item {
        self.garbler.negate(x)
    }

    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item {
        self.garbler.xor(x, y)
    }

    fn and(
        &mut self,
        x: &Self::Item,
        y: &Self::Item,
        channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        self.garbler.and(x, y, channel)
    }
}

impl<
    RNG: CryptoRng + SeedableRng<Seed = U8x16>,
    OT: ObliviousTransfer<Sender> + SemiHonest,
    Wire: WireLabel<F2>,
> Fancy for Garbler<RNG, OT, Wire>
{
    type Item = Wire;
}

impl<
    RNG: CryptoRng + SeedableRng<Seed = U8x16>,
    OT: ObliviousTransfer<Sender> + SemiHonest,
    Wire: WireLabel<F2>,
> FancyConstant<F2> for Garbler<RNG, OT, Wire>
{
    fn constant(&mut self, x: F2) -> Self::Item {
        self.garbler.constant(x)
    }
}

impl<
    RNG: CryptoRng + SeedableRng<Seed = U8x16>,
    OT: ObliviousTransfer<Sender> + SemiHonest,
    Wire: WireLabel<F2>,
> FancyEncode<F2> for Garbler<RNG, OT, Wire>
{
    fn encode_many(
        &mut self,
        vals: &[F2],
        channel: &mut Channel,
    ) -> swanky_error::Result<Vec<Wire>> {
        self.garbler.encode_many(vals, channel)
    }

    fn receive_many(&mut self, n: usize, channel: &mut Channel) -> swanky_error::Result<Vec<Wire>> {
        let mut wires = Vec::with_capacity(n);
        let mut inputs = Vec::with_capacity(n);

        for _ in 0..n {
            let delta = self.garbler.delta();
            let (zero, one) = Wire::constant(F2::ONE, &delta, &mut self.rng);
            wires.push(zero);
            inputs.push([zero.to_repr(), one.to_repr()]);
        }

        self.ot.ot::<Vec<_>>(
            PartyEither::new(Witness::EQUAL_TYPES, inputs.len()),
            PartyPrivate::new(&inputs[..]),
            PartyPrivate::empty(Witness::EQUAL_TYPES),
            channel,
            &mut self.rng,
        )?;
        Ok(wires)
    }
}

impl<
    RNG: CryptoRng + SeedableRng<Seed = U8x16>,
    OT: ObliviousTransfer<Sender> + SemiHonest,
    Wire: WireLabel<F2>,
> FancyOutput<F2> for Garbler<RNG, OT, Wire>
{
    fn output(
        &mut self,
        x: &Self::Item,
        channel: &mut Channel,
    ) -> swanky_error::Result<Option<F2>> {
        self.garbler.output(x, channel)
    }
}

impl<RNG, OT, Wire> SemiHonest for Garbler<RNG, OT, Wire> {}
