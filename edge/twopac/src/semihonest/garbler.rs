use fancy_garbling::{AllWire, ArithmeticWireLabel, Garbler as Gb, WireLabel, WireMod2};
use fancy_traits::{
    Fancy, FancyArithmetic, FancyBinary, FancyBinaryConstant, FancyConstant, FancyEncode,
    FancyOutput, FancyProj,
};
use rand::{CryptoRng, RngExt, SeedableRng};
use swanky_adversary::SemiHonest;
use swanky_block::Block;
use swanky_channel::Channel;
use swanky_error::{ErrorKind, WrapErr};
use swanky_field_binary::F2;
use swanky_ot_traits::Sender as OtSender;

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
    RNG: CryptoRng + SeedableRng<Seed = Block>,
    OT: OtSender<Msg = Block> + SemiHonest,
    Wire: WireLabel,
> Garbler<RNG, OT, Wire>
{
    /// Make a new `Garbler`.
    pub fn new(channel: &mut Channel, mut rng: RNG) -> swanky_error::Result<Self> {
        let ot = OT::init(channel, &mut rng)
            .wrap_err(ErrorKind::InitializationError, "Failed to initialize OT.")?;

        let garbler = Gb::new(RNG::from_seed(rng.random()));
        Ok(Garbler { garbler, ot, rng })
    }

    fn _evaluator_input(&mut self, delta: &Wire, q: u16) -> (Wire, Vec<(Block, Block)>) {
        let len = f32::from(q).log(2.0).ceil() as u16;
        let mut inputs = Vec::with_capacity(len as usize);
        let (zero, one) = Wire::constant(1, q, delta, &mut self.rng);
        let mut wire = zero.clone();
        inputs.push((zero.to_repr(), one.to_repr()));
        for i in 1..len {
            let (zero, one) = Wire::constant(1, q, delta, &mut self.rng);
            wire += zero.clone() * (1 << i);
            inputs.push((zero.to_repr(), one.to_repr()))
        }
        (wire, inputs)
    }
}

impl<RNG: CryptoRng + SeedableRng<Seed = Block>, OT: OtSender<Msg = Block> + SemiHonest> FancyBinary
    for Garbler<RNG, OT, WireMod2>
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

impl<RNG: CryptoRng + SeedableRng<Seed = Block>, OT: OtSender<Msg = Block> + SemiHonest> FancyBinary
    for Garbler<RNG, OT, AllWire>
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
    RNG: CryptoRng + SeedableRng<Seed = Block>,
    OT: OtSender<Msg = Block> + SemiHonest,
    Wire: WireLabel + ArithmeticWireLabel,
> FancyArithmetic for Garbler<RNG, OT, Wire>
{
    fn add(&mut self, x: &Wire, y: &Wire) -> Self::Item {
        self.garbler.add(x, y)
    }

    fn sub(&mut self, x: &Wire, y: &Wire) -> Self::Item {
        self.garbler.sub(x, y)
    }

    fn cmul(&mut self, x: &Wire, c: u16) -> Self::Item {
        self.garbler.cmul(x, c)
    }

    fn mul(
        &mut self,
        x: &Wire,
        y: &Wire,
        channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        self.garbler.mul(x, y, channel)
    }
}

impl<
    RNG: CryptoRng + SeedableRng<Seed = Block>,
    OT: OtSender<Msg = Block> + SemiHonest,
    Wire: WireLabel + ArithmeticWireLabel,
> FancyProj for Garbler<RNG, OT, Wire>
{
    fn proj(
        &mut self,
        x: &Wire,
        q: u16,
        tt: Option<Vec<u16>>,
        channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        self.garbler.proj(x, q, tt, channel)
    }
}

impl<
    RNG: CryptoRng + SeedableRng<Seed = Block>,
    OT: OtSender<Msg = Block> + SemiHonest,
    Wire: WireLabel,
> Fancy for Garbler<RNG, OT, Wire>
{
    type Item = Wire;
}

impl<
    RNG: CryptoRng + SeedableRng<Seed = Block>,
    OT: OtSender<Msg = Block> + SemiHonest,
    Wire: WireLabel,
> FancyConstant for Garbler<RNG, OT, Wire>
{
    fn constant(
        &mut self,
        x: u16,
        q: u16,
        channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        FancyConstant::constant(&mut self.garbler, x, q, channel)
    }
}

impl<
    RNG: CryptoRng + SeedableRng<Seed = Block>,
    OT: OtSender<Msg = Block> + SemiHonest,
    Wire: WireLabel,
> FancyBinaryConstant for Garbler<RNG, OT, Wire>
{
    fn constant(&mut self, x: F2) -> Self::Item {
        FancyBinaryConstant::constant(&mut self.garbler, x)
    }
}

impl<
    RNG: CryptoRng + SeedableRng<Seed = Block>,
    OT: OtSender<Msg = Block> + SemiHonest,
    Wire: WireLabel,
> FancyEncode for Garbler<RNG, OT, Wire>
{
    fn encode_many(
        &mut self,
        vals: &[u16],
        moduli: &[u16],
        channel: &mut Channel,
    ) -> swanky_error::Result<Vec<Wire>> {
        self.garbler.encode_many(vals, moduli, channel)
    }

    fn receive_many(
        &mut self,
        qs: &[u16],
        channel: &mut Channel,
    ) -> swanky_error::Result<Vec<Wire>> {
        let n = qs.len();
        let lens = qs.iter().map(|q| f32::from(*q).log(2.0).ceil() as usize);
        let mut wires = Vec::with_capacity(n);
        let mut inputs = Vec::with_capacity(lens.sum());

        for q in qs.iter() {
            let delta = self.garbler.delta(*q);
            let (wire, input) = self._evaluator_input(&delta, *q);
            wires.push(wire);
            for i in input.into_iter() {
                inputs.push(i);
            }
        }
        self.ot
            .send(channel, &inputs, &mut self.rng)
            .wrap_err(ErrorKind::OtherError, "Failed to send obliviously.")?;
        Ok(wires)
    }
}

impl<
    RNG: CryptoRng + SeedableRng<Seed = Block>,
    OT: OtSender<Msg = Block> + SemiHonest,
    Wire: WireLabel,
> FancyOutput for Garbler<RNG, OT, Wire>
{
    fn output(
        &mut self,
        x: &Self::Item,
        channel: &mut Channel,
    ) -> swanky_error::Result<Option<u16>> {
        self.garbler.output(x, channel)
    }
}

impl<RNG, OT, Wire> SemiHonest for Garbler<RNG, OT, Wire> {}
