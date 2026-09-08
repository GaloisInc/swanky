use fancy_garbling::{AllWire, ArithmeticWireLabel, Evaluator as Ev, WireLabel, WireMod2};
use fancy_traits::{
    Fancy, FancyArithmetic, FancyBinary, FancyBinaryConstant, FancyConstant, FancyEncode,
    FancyOutput, FancyProj,
};
use rand::CryptoRng;
use swanky_adversary::SemiHonest;
use swanky_block::Block;
use swanky_channel::Channel;
use swanky_error::{ErrorKind, WrapErr};
use swanky_field_binary::F2;
use swanky_ot_traits::Receiver as OtReceiver;

/// Semi-honest evaluator.
pub struct Evaluator<RNG, OT, Wire> {
    evaluator: Ev<Wire>,
    ot: OT,
    rng: RNG,
}

impl<RNG, OT, Wire> Evaluator<RNG, OT, Wire> {}

impl<RNG: CryptoRng, OT: OtReceiver<Msg = Block> + SemiHonest, Wire: WireLabel>
    Evaluator<RNG, OT, Wire>
{
    /// Make a new `Evaluator`.
    pub fn new(channel: &mut Channel, mut rng: RNG) -> swanky_error::Result<Self> {
        let ot = OT::init(channel, &mut rng)
            .wrap_err(ErrorKind::InitializationError, "Failed to initialize OT.")?;
        let evaluator = Ev::new();
        Ok(Self { evaluator, ot, rng })
    }

    fn run_ot(
        &mut self,
        inputs: &[bool],
        channel: &mut Channel,
    ) -> swanky_error::Result<Vec<Block>> {
        self.ot
            .receive(channel, inputs, &mut self.rng)
            .wrap_err(ErrorKind::OtherError, "Failed to run OT.")
    }
}

fn combine<Wire: WireLabel>(wires: &[Block], q: u16) -> Wire {
    assert!(!wires.is_empty());
    let acc = Wire::from_repr(wires[0], q);
    wires[1..].iter().enumerate().fold(acc, |acc, (i, w)| {
        let w = Wire::from_repr(*w, q);
        acc + w * (1 << (i + 1))
    })
}

impl<RNG: CryptoRng, OT: OtReceiver<Msg = Block> + SemiHonest> FancyBinary
    for Evaluator<RNG, OT, WireMod2>
{
    fn and(
        &mut self,
        x: &Self::Item,
        y: &Self::Item,
        channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        self.evaluator.and(x, y, channel)
    }

    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item {
        self.evaluator.xor(x, y)
    }

    fn negate(&mut self, x: &Self::Item) -> Self::Item {
        self.evaluator.negate(x)
    }
}

impl<RNG: CryptoRng, OT: OtReceiver<Msg = Block> + SemiHonest> FancyBinary
    for Evaluator<RNG, OT, AllWire>
{
    fn and(
        &mut self,
        x: &Self::Item,
        y: &Self::Item,
        channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        self.evaluator.and(x, y, channel)
    }

    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item {
        self.evaluator.xor(x, y)
    }

    fn negate(&mut self, x: &Self::Item) -> Self::Item {
        self.evaluator.negate(x)
    }
}

impl<
    RNG: CryptoRng,
    OT: OtReceiver<Msg = Block> + SemiHonest,
    Wire: WireLabel + ArithmeticWireLabel,
> FancyArithmetic for Evaluator<RNG, OT, Wire>
{
    fn add(&mut self, x: &Wire, y: &Wire) -> Self::Item {
        self.evaluator.add(x, y)
    }

    fn sub(&mut self, x: &Wire, y: &Wire) -> Self::Item {
        self.evaluator.sub(x, y)
    }

    fn cmul(&mut self, x: &Wire, c: u16) -> Self::Item {
        self.evaluator.cmul(x, c)
    }

    fn mul(
        &mut self,
        x: &Wire,
        y: &Wire,
        channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        self.evaluator.mul(x, y, channel)
    }
}

impl<
    RNG: CryptoRng,
    OT: OtReceiver<Msg = Block> + SemiHonest,
    Wire: WireLabel + ArithmeticWireLabel,
> FancyProj for Evaluator<RNG, OT, Wire>
{
    fn proj(
        &mut self,
        x: &Wire,
        q: u16,
        tt: Option<Vec<u16>>,
        channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        self.evaluator.proj(x, q, tt, channel)
    }
}

impl<RNG: CryptoRng, OT: OtReceiver<Msg = Block> + SemiHonest, Wire: WireLabel> Fancy
    for Evaluator<RNG, OT, Wire>
{
    type Item = Wire;
}

impl<RNG: CryptoRng, OT: OtReceiver<Msg = Block> + SemiHonest, Wire: WireLabel> FancyConstant
    for Evaluator<RNG, OT, Wire>
{
    fn constant(
        &mut self,
        x: u16,
        q: u16,
        channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        FancyConstant::constant(&mut self.evaluator, x, q, channel)
    }
}

impl<RNG: CryptoRng, OT: OtReceiver<Msg = Block> + SemiHonest, Wire: WireLabel> FancyBinaryConstant
    for Evaluator<RNG, OT, Wire>
{
    fn constant(&mut self, x: F2) -> Self::Item {
        FancyBinaryConstant::constant(&mut self.evaluator, x)
    }
}

impl<RNG: CryptoRng, OT: OtReceiver<Msg = Block> + SemiHonest, Wire: WireLabel> FancyEncode
    for Evaluator<RNG, OT, Wire>
{
    /// Receive garbler input wires.
    fn receive_many(
        &mut self,
        moduli: &[u16],
        channel: &mut Channel,
    ) -> swanky_error::Result<Vec<Wire>> {
        self.evaluator.receive_many(moduli, channel)
    }

    /// Perform OT and obtain wires for the evaluator's inputs.
    fn encode_many(
        &mut self,
        inputs: &[u16],
        moduli: &[u16],
        channel: &mut Channel,
    ) -> swanky_error::Result<Vec<Wire>> {
        let mut lens = Vec::new();
        let mut bs = Vec::new();
        for (x, q) in inputs.iter().zip(moduli.iter()) {
            let len = f32::from(*q).log(2.0).ceil() as usize;
            for b in (0..len).map(|i| x & (1 << i) != 0) {
                bs.push(b);
            }
            lens.push(len);
        }
        let wires = self
            .run_ot(&bs, channel)
            .wrap_err(ErrorKind::OtherError, "Failed to run oblivious transfer.")?;
        let mut start = 0;
        Ok(lens
            .into_iter()
            .zip(moduli.iter())
            .map(|(len, q)| {
                let range = start..start + len;
                let chunk = &wires[range];
                start += len;
                combine(chunk, *q)
            })
            .collect::<Vec<Wire>>())
    }
}

impl<RNG: CryptoRng, OT: OtReceiver<Msg = Block> + SemiHonest, Wire: WireLabel> FancyOutput
    for Evaluator<RNG, OT, Wire>
{
    fn output(&mut self, x: &Wire, channel: &mut Channel) -> swanky_error::Result<Option<u16>> {
        self.evaluator.output(x, channel)
    }
}

impl<RNG, OT, Wire> SemiHonest for Evaluator<RNG, OT, Wire> {}
