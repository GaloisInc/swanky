//! An example that secretly retrieves an element from an ORAM in a binary garbled circuit
//! using fancy-garbling.

use fancy_analyzer::CircuitAnalyzer;
use fancy_circuits::{BinaryBundle, BinaryGadgets, LinearOram};
use fancy_garbling::AllWire;
use fancy_traits::{Circuit, FancyOutput};
use rand::{CryptoRng, SeedableRng};
use swanky_block::Block;
use swanky_channel::Channel;
use swanky_error::Result;
use swanky_ot_alsz_kos::alsz::{Receiver as OtReceiver, Sender as OtSender};
use swanky_rng::SwankyRng;
use swanky_twopac::semihonest::{Evaluator, Garbler};

/// Bit length of items in RAM.
const NBITS: usize = 128;

/// The expected RAM computation.
fn ram_in_clear(ram: &[u128], index: usize) -> u128 {
    if index >= ram.len() { 0 } else { ram[index] }
}

/// Set the inputs from the garbler's perspective.
fn gb_set_inputs<F: BinaryGadgets>(
    gb: &mut F,
    inputs: &[u128],
    channel: &mut Channel,
) -> Result<(Vec<BinaryBundle<F::Item>>, BinaryBundle<F::Item>)> {
    let ram = gb.bin_encode_many(inputs, NBITS, channel)?;
    let query = gb.bin_receive(NBITS, channel)?;
    Ok((ram, query))
}

/// Set the inputs from the evaluator's perspective.
fn ev_set_inputs<F: BinaryGadgets>(
    ev: &mut F,
    input: u128,
    ram_size: usize,
    channel: &mut Channel,
) -> Result<(Vec<BinaryBundle<F::Item>>, BinaryBundle<F::Item>)> {
    let ram = ev.bin_receive_many(ram_size, NBITS, channel)?;
    let query = ev.bin_encode(input, NBITS, channel)?;
    Ok((ram, query))
}

fn gb_linear_oram<RNG: CryptoRng + SeedableRng<Seed = Block>>(
    inputs: &[u128],
    channel: &mut Channel,
    rng: RNG,
) -> Result<()> {
    let mut gb = Garbler::<_, OtSender, AllWire>::new(channel, rng)?;
    // The size of the RAM is assumed to be public. The garbler sends the RAM
    // size to the evaluator.
    channel.write(&inputs.len())?;
    // The circuit to garble.
    let circuit = LinearOram::<NBITS>::new(inputs.len());

    let inputs = gb_set_inputs(&mut gb, inputs, channel)?;
    let query = circuit.execute(&mut gb, inputs, channel)?;
    gb.outputs(query.wires(), channel)?;
    Ok(())
}

fn ev_linear_oram<RNG: CryptoRng>(input: u128, channel: &mut Channel, rng: RNG) -> Result<u128> {
    let mut ev = Evaluator::<_, OtReceiver, AllWire>::new(channel, rng)?;
    // The size of the RAM is assumed to be public. The evaluator receives this
    // size from the garbler.
    let size = channel.read::<usize>()?;
    // The circuit to evaluate.
    let circuit = LinearOram::<NBITS>::new(size);

    let inputs = ev_set_inputs(&mut ev, input, size, channel)?;
    let output = circuit.execute(&mut ev, inputs, channel)?;
    let result = ev
        .bin_output(&output, channel)?
        .expect("evaluator should produce outputs");
    Ok(result)
}

use clap::Parser;
#[derive(Parser)]
/// Example usage:
///
/// cargo run --example linear_oram 5 1 2 3 7 7 25
///
/// Computes RAM([1,2,3,7,7,25], at index: 5)
struct Cli {
    /// The first integer specifies the query.
    query: u128,
    /// The rest of the integers contitute the RAM values.
    ram: Vec<u128>,
}

fn main() {
    let cli = Cli::parse();

    let index = cli.query;
    let ram = cli.ram;

    let mut analyzer = CircuitAnalyzer::new();
    analyzer.eval(&LinearOram::<NBITS>::new(ram.len())).unwrap();
    println!("{analyzer}");

    let (_, result) = swanky_channel::local::local_channel_pair(
        |channel| {
            let rng = SwankyRng::new();
            gb_linear_oram(&ram, channel, rng)?;
            Ok(())
        },
        |channel| {
            let rng = SwankyRng::new();
            let result = ev_linear_oram(index, channel, rng)?;
            Ok(result)
        },
    )
    .unwrap();

    let expected = ram_in_clear(&ram, index as usize);
    println!("Garbled Circuit result is : RAM([{ram:?}], at index:{index}) = {result}");
    assert_eq!(result, expected);
}
