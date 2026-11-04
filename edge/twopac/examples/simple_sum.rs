//! An example that adds two secret numbers in a binary garbled circuit
//! using fancy-garbling.

use fancy_circuits::{
    BinaryBundle, BinaryEncode, BinaryOutput, BinaryReceive, binary::BinaryAdditionNoCarry,
};
use fancy_traits::Circuit;
use swanky_channel::Channel;
use swanky_error::Result;
use swanky_ot_iknp::IKNP;
use swanky_ot_traits_new::{Receiver, Sender};
use swanky_rng::SwankyRng;
use swanky_twopac::semihonest::{Evaluator, Garbler};

const N: usize = 128;

fn gb_sum(input: u128, channel: &mut Channel, rng: SwankyRng) -> Result<()> {
    let mut gb = Garbler::<SwankyRng, IKNP<Sender>, _>::new(channel, rng)?;
    let inputs = gb_set_inputs(&mut gb, input, channel)?;
    let sum = BinaryAdditionNoCarry::new().execute(&mut gb, (&inputs.0, &inputs.1), channel)?;
    gb.bin_output(&sum, channel)?;
    Ok(())
}

fn gb_set_inputs<F: BinaryEncode + BinaryReceive>(
    gb: &mut F,
    input: u128,
    channel: &mut Channel,
) -> Result<(BinaryBundle<F::Item, N>, BinaryBundle<F::Item, N>)> {
    let x = gb.bin_encode::<N>(input, channel)?;
    let y = gb.bin_receive::<N>(channel)?;
    Ok((x, y))
}

fn ev_sum(input: u128, channel: &mut Channel, rng: SwankyRng) -> Result<u128> {
    let mut ev = Evaluator::<SwankyRng, IKNP<Receiver>, _>::new(channel, rng)?;
    let inputs = ev_set_inputs(&mut ev, input, channel)?;
    let sum = BinaryAdditionNoCarry::new().execute(&mut ev, (&inputs.0, &inputs.1), channel)?;
    let output = ev
        .bin_output(&sum, channel)
        .unwrap()
        .expect("evaluator should produce outputs");
    Ok(output)
}

fn ev_set_inputs<F: BinaryEncode + BinaryReceive>(
    ev: &mut F,
    input: u128,
    channel: &mut Channel,
) -> Result<(BinaryBundle<F::Item, N>, BinaryBundle<F::Item, N>)> {
    let x = ev.bin_receive::<N>(channel)?;
    let y = ev.bin_encode::<N>(input, channel)?;
    Ok((x, y))
}

use clap::Parser;
#[derive(Parser)]
/// Example usage:
///
/// cargo run --example simple_sum 2 3
///
/// Computes the SUM(2,3)
/// Where 2 is the garbler's value and 3 is the evaluator's.
struct Cli {
    /// The garbler's value.
    gb_value: u128,
    /// The evaluator's value.
    ev_value: u128,
}

fn main() {
    let cli = Cli::parse();
    let x: u128 = cli.gb_value;
    let y: u128 = cli.ev_value;

    let (_, result) = swanky_channel::local::local_channel_pair(
        |channel| {
            let rng = SwankyRng::new();
            gb_sum(x, channel, rng)
        },
        |channel| {
            let rng = SwankyRng::new();
            ev_sum(y, channel, rng)
        },
    )
    .unwrap();

    println!("SUM({x}, {y}) = {result}");

    assert_eq!(result, x + y);
}
