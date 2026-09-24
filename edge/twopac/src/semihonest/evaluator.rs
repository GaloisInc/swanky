use fancy_garbling::{Evaluator as Ev, WireLabel, WireMod2};
use fancy_traits::{Fancy, FancyBinary, FancyConstant, FancyEncode, FancyOutput};
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

impl<RNG: CryptoRng, OT: OtReceiver<Msg = Block> + SemiHonest, Wire: WireLabel<F2>>
    Evaluator<RNG, OT, Wire>
{
    /// Make a new `Evaluator`.
    pub fn new(channel: &mut Channel, mut rng: RNG) -> swanky_error::Result<Self> {
        let ot = OT::init(channel, &mut rng)
            .wrap_err(ErrorKind::InitializationError, "Failed to initialize OT.")?;
        let evaluator = Ev::new();
        Ok(Self { evaluator, ot, rng })
    }

    fn run_ot(&mut self, inputs: &[F2], channel: &mut Channel) -> swanky_error::Result<Vec<Block>> {
        self.ot
            .receive(channel, inputs, &mut self.rng)
            .wrap_err(ErrorKind::OtherError, "Failed to run OT.")
    }
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

impl<RNG: CryptoRng, OT: OtReceiver<Msg = Block> + SemiHonest, Wire: WireLabel<F2>> Fancy
    for Evaluator<RNG, OT, Wire>
{
    type Item = Wire;
}

impl<RNG: CryptoRng, OT: OtReceiver<Msg = Block> + SemiHonest, Wire: WireLabel<F2>>
    FancyConstant<F2> for Evaluator<RNG, OT, Wire>
{
    fn constant(&mut self, x: F2) -> Self::Item {
        self.evaluator.constant(x)
    }
}

impl<RNG: CryptoRng, OT: OtReceiver<Msg = Block> + SemiHonest, Wire: WireLabel<F2>> FancyEncode<F2>
    for Evaluator<RNG, OT, Wire>
{
    /// Receive garbler input wires.
    fn receive_many(&mut self, n: usize, channel: &mut Channel) -> swanky_error::Result<Vec<Wire>> {
        self.evaluator.receive_many(n, channel)
    }

    /// Perform OT and obtain wires for the evaluator's inputs.
    fn encode_many(
        &mut self,
        inputs: &[F2],
        channel: &mut Channel,
    ) -> swanky_error::Result<Vec<Wire>> {
        let wires = self
            .run_ot(inputs, channel)
            .wrap_err(ErrorKind::OtherError, "Failed to run oblivious transfer.")?;
        Ok(wires
            .into_iter()
            .map(|wire| Wire::from_repr(wire, 2))
            .collect::<Vec<Wire>>())
    }
}

impl<RNG: CryptoRng, OT: OtReceiver<Msg = Block> + SemiHonest, Wire: WireLabel<F2>> FancyOutput
    for Evaluator<RNG, OT, Wire>
{
    fn output(&mut self, x: &Wire, channel: &mut Channel) -> swanky_error::Result<Option<u16>> {
        self.evaluator.output(x, channel)
    }
}

impl<RNG, OT, Wire> SemiHonest for Evaluator<RNG, OT, Wire> {}
