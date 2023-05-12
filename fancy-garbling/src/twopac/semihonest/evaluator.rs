use crate::{
    errors::TwopacError, wire::WireLabel, AllWire, ArithmeticWire, Evaluator as Ev, Fancy,
    FancyArithmetic, FancyBinary, FancyInput, FancyReveal, WireMod2,
};
use ocelot::ot::Receiver as OtReceiver;
use rand::{CryptoRng, Rng};
use scuttlebutt::{AbstractChannel, Block, SemiHonest};

/// Semi-honest evaluator.
pub struct Evaluator<C, RNG, OT, Wire> {
    evaluator: Ev<C, Wire>,
    channel: C,
    ot: OT,
    rng: RNG,
}

impl<C, RNG, OT, Wire> Evaluator<C, RNG, OT, Wire> {}

impl<
        C: AbstractChannel,
        RNG: CryptoRng + Rng,
        OT: OtReceiver<Msg = Block> + SemiHonest,
        Wire: WireLabel,
    > Evaluator<C, RNG, OT, Wire>
{
    /// Make a new `Evaluator`.
    pub fn new(mut channel: C, mut rng: RNG) -> Result<Self, TwopacError> {
        let ot = OT::init(&mut channel, &mut rng)?;
        let evaluator = Ev::new(channel.clone());
        Ok(Self {
            evaluator,
            channel,
            ot,
            rng,
        })
    }

    /// Get a reference to the internal channel.
    pub fn get_channel(&mut self) -> &mut C {
        &mut self.channel
    }

    fn run_ot(&mut self, inputs: &[bool]) -> Result<Vec<Block>, TwopacError> {
        self.ot
            .receive(&mut self.channel, inputs, &mut self.rng)
            .map_err(TwopacError::from)
    }
}

impl<
        C: AbstractChannel,
        RNG: CryptoRng + Rng,
        OT: OtReceiver<Msg = Block> + SemiHonest,
        Wire: WireLabel,
    > FancyInput for Evaluator<C, RNG, OT, Wire>
{
    type Item = Wire;
    type Error = TwopacError;

    /// Receive a garbler input wire.
    fn receive(&mut self, modulus: u16) -> Result<Wire, TwopacError> {
        let w = self.evaluator.read_wire(modulus)?;
        Ok(w)
    }

    /// Receive garbler input wires.
    fn receive_many(&mut self, moduli: &[u16]) -> Result<Vec<Wire>, TwopacError> {
        moduli.iter().map(|q| self.receive(*q)).collect()
    }

    /// Perform OT and obtain wires for the evaluator's inputs.
    fn encode_many(&mut self, inputs: &[u16], moduli: &[u16]) -> Result<Vec<Wire>, TwopacError> {
        let mut lens = Vec::new();
        let mut bs = Vec::new();
        for (x, q) in inputs.iter().zip(moduli.iter()) {
            let len = f32::from(*q).log(2.0).ceil() as usize;
            for b in (0..len).map(|i| x & (1 << i) != 0) {
                bs.push(b);
            }
            lens.push(len);
        }
        let wires = self.run_ot(&bs)?;
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

fn combine<Wire: WireLabel>(wires: &[Block], q: u16) -> Wire {
    wires.iter().enumerate().fold(Wire::zero(q), |acc, (i, w)| {
        let w = Wire::from_block(*w, q);
        acc.plus(&w.cmul(1 << i))
    })
}

impl<C: AbstractChannel, RNG, OT> FancyBinary for Evaluator<C, RNG, OT, WireMod2> {
    fn and(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error> {
        self.evaluator.and(x, y).map_err(Self::Error::from)
    }

    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error> {
        self.evaluator.xor(x, y).map_err(Self::Error::from)
    }

    fn negate(&mut self, x: &Self::Item) -> Result<Self::Item, Self::Error> {
        self.evaluator.negate(x).map_err(Self::Error::from)
    }
}

impl<C: AbstractChannel, RNG, OT> FancyBinary for Evaluator<C, RNG, OT, AllWire> {
    fn and(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error> {
        self.evaluator.and(x, y).map_err(Self::Error::from)
    }

    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error> {
        self.evaluator.xor(x, y).map_err(Self::Error::from)
    }

    fn negate(&mut self, x: &Self::Item) -> Result<Self::Item, Self::Error> {
        self.evaluator.negate(x).map_err(Self::Error::from)
    }
}

impl<C: AbstractChannel, RNG, OT, Wire: WireLabel + ArithmeticWire> FancyArithmetic
    for Evaluator<C, RNG, OT, Wire>
{
    fn add(&mut self, x: &Wire, y: &Wire) -> Result<Self::Item, Self::Error> {
        self.evaluator.add(x, y).map_err(Self::Error::from)
    }

    fn sub(&mut self, x: &Wire, y: &Wire) -> Result<Self::Item, Self::Error> {
        self.evaluator.sub(x, y).map_err(Self::Error::from)
    }

    fn cmul(&mut self, x: &Wire, c: u16) -> Result<Self::Item, Self::Error> {
        self.evaluator.cmul(x, c).map_err(Self::Error::from)
    }

    fn mul(&mut self, x: &Wire, y: &Wire) -> Result<Self::Item, Self::Error> {
        self.evaluator.mul(x, y).map_err(Self::Error::from)
    }

    fn proj(&mut self, x: &Wire, q: u16, tt: Option<Vec<u16>>) -> Result<Self::Item, Self::Error> {
        self.evaluator.proj(x, q, tt).map_err(Self::Error::from)
    }
}

impl<C: AbstractChannel, RNG, OT, Wire: WireLabel> Fancy for Evaluator<C, RNG, OT, Wire> {
    type Item = Wire;
    type Error = TwopacError;

    fn constant(&mut self, x: u16, q: u16) -> Result<Self::Item, Self::Error> {
        self.evaluator.constant(x, q).map_err(Self::Error::from)
    }

    fn output(&mut self, x: &Wire) -> Result<Option<u16>, Self::Error> {
        self.evaluator.output(x).map_err(Self::Error::from)
    }
}

impl<C: AbstractChannel, RNG: CryptoRng + Rng, OT, Wire: WireLabel> FancyReveal
    for Evaluator<C, RNG, OT, Wire>
{
    fn reveal(&mut self, x: &Self::Item) -> Result<u16, Self::Error> {
        self.evaluator.reveal(x).map_err(Self::Error::from)
    }
}

impl<C: AbstractChannel, RNG, OT, Wire> SemiHonest for Evaluator<C, RNG, OT, Wire> {}
