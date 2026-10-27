//! An example that computes the GCD of two secret numbers in a binary circuit
//! using `fancy-garbling`.

use core::cmp::{Ordering, max};
use fancy_circuits::{BinaryBundle, BinaryGadgets, Gcd};
use fancy_traits::Circuit;
use swanky_channel::Channel;
use swanky_error::Result;
use swanky_ot_iknp::IKNP;
use swanky_ot_traits_new::{Receiver, Sender};
use swanky_rng::SwankyRng;
use swanky_twopac::semihonest::{Evaluator, Garbler};

const NBITS: usize = 128;

/// The garbler's main method:
/// Given an `input` and public `upper_bound` (which must be pre-shared with the evaluator)
/// securely compute and return the GCD of `input` and the evaluator's input
///
/// In more detail:
///
/// (1) The garbler is first created using the passed rng and value.
/// (2) The garbler then exchanges their wires obliviously with the evaluator.
/// (3) The garbler and the evaluator then run the garbled circuit.
/// (4) The garbler and the evaluator open the result of the computation.
fn gb_gcd(input: u128, upper_bound: usize, channel: &mut Channel, rng: SwankyRng) -> Result<()> {
    let mut gb = Garbler::<SwankyRng, IKNP<Sender>, _>::new(channel, rng)?;
    let inputs = gb_set_inputs(&mut gb, input, channel)?;
    let gcd = Gcd::new(upper_bound).execute(&mut gb, (&inputs.0, &inputs.1), channel)?;
    gb.bin_output(&gcd, channel)?;
    Ok(())
}

fn gb_set_inputs<F: BinaryGadgets>(
    gb: &mut F,
    input: u128,
    channel: &mut Channel,
) -> Result<(BinaryBundle<F::Item>, BinaryBundle<F::Item>)> {
    let x = gb.bin_encode(input, NBITS, channel)?;
    let y = gb.bin_receive(NBITS, channel)?;
    Ok((x, y))
}

/// The evaluator's main method:
/// Given an `input` and public `upper_bound` (which must be pre-shared with the garbler)
/// securely compute and return the GCD of `input` and the garbler's input
///
/// In more detail:
///
/// (1) The evaluator is first created using the passed rng and value.
/// (2) The evaluator then exchanges their wires obliviously with the garbler.
/// (3) The evaluator and the garbler then run the garbled circuit.
/// (4) The evaluator and the garbler open the result of the computation.
/// (5) The evaluator translates the binary output of the circuit into its decimal
///     representation.
fn ev_gcd(input: u128, upper_bound: usize, channel: &mut Channel, rng: SwankyRng) -> Result<u128> {
    let mut ev = Evaluator::<SwankyRng, IKNP<Receiver>, _>::new(channel, rng)?;
    let inputs = ev_set_inputs(&mut ev, input, channel)?;
    let gcd = Gcd::new(upper_bound).execute(&mut ev, (&inputs.0, &inputs.1), channel)?;
    let output = ev
        .bin_output(&gcd, channel)?
        .expect("evaluator should produce outputs");
    Ok(output)
}

fn ev_set_inputs<F: BinaryGadgets>(
    ev: &mut F,
    input: u128,
    channel: &mut Channel,
) -> Result<(BinaryBundle<F::Item>, BinaryBundle<F::Item>)> {
    let x = ev.bin_receive(NBITS, channel)?;
    let y = ev.bin_encode(input, NBITS, channel)?;
    Ok((x, y))
}

fn gcd_in_clear(a: u128, b: u128, upper_bound: u128) -> u128 {
    let mut r_1: u128 = a;
    let mut r_2 = b;
    for _ in 0..upper_bound {
        match r_1.cmp(&r_2) {
            Ordering::Greater => r_1 -= r_2,
            Ordering::Less => r_2 -= r_1,
            Ordering::Equal => return r_1,
        }
    }
    r_1
}

use clap::Parser;
#[derive(Parser)]
/// Example usage:
///
/// cargo run --example gcd 2 3
///
/// Computes the GCD(2,3)
/// Where 2 is the garbler's value and 3 is the evaluator's.
struct Cli {
    /// The garbler's value.
    gb_value: u128,
    /// The evaluator's value.
    ev_value: u128,
}

fn main() {
    let cli = Cli::parse();
    let gb_value: u128 = cli.gb_value;
    let ev_value: u128 = cli.ev_value;

    let upper_bound: u128 = max(gb_value, ev_value);

    let (_, result) = swanky_channel::local::local_channel_pair(
        |channel| {
            let rng = SwankyRng::new();
            gb_gcd(gb_value, upper_bound as usize, channel, rng)
        },
        |channel| {
            let rng = SwankyRng::new();
            ev_gcd(ev_value, upper_bound as usize, channel, rng)
        },
    )
    .unwrap();

    println!("Garbled Circuit result is : GCD({gb_value}, {ev_value}) = {result}");

    let expected = gcd_in_clear(gb_value, ev_value, upper_bound);
    assert_eq!(result, expected);
}
