//! An example that adds two secret numbers in a binary garbled circuit
//! using fancy-garbling.
use fancy_garbling::{
    twopac::semihonest::{Evaluator, Garbler},
    AllWire, BinaryBundle, BinaryGadgets, Fancy, FancyArithmetic, FancyBinary, FancyReveal,
};

use ocelot::{ot::AlszReceiver as OtReceiver, ot::AlszSender as OtSender};
use scuttlebutt::{AbstractChannel, AesRng};

use std::env;

/// A structure that contains both the garbler and the evaluators
/// wires. This structure simplifies the API of the garbled circuit.
struct SUMInputs<F> {
    pub garbler_wires: BinaryBundle<F>,
    pub evaluator_wires: BinaryBundle<F>,
}

/// The garbler's main method:
/// (1) The garbler is first created using the passed rng and value.

fn gb_sum<C>(rng: &mut AesRng, channel: &mut C, input: u128)
where
    C: AbstractChannel + std::clone::Clone,
{
    // (1)
    let mut gb =
        Garbler::<C, AesRng, OtSender, AllWire>::new(channel.clone(), rng.clone()).unwrap();
}

/// The evaluator's main method:
/// (1) The evaluator is first created using the passed rng and value.

fn ev_sum<C>(rng: &mut AesRng, channel: &mut C, input: u128) -> u128
where
    C: AbstractChannel + std::clone::Clone,
{
    // (1)
    let mut ev =
        Evaluator::<C, AesRng, OtReceiver, AllWire>::new(channel.clone(), rng.clone()).unwrap();
    todo!()
}

/// The main fancy function which describes the garbled circuit for summation.
fn fancy_sum<F>(
    f: &mut F,
    wire_inputs: SUMInputs<F::Item>,
) -> Result<BinaryBundle<F::Item>, F::Error>
where
    F: FancyReveal + Fancy + BinaryGadgets + FancyBinary + FancyArithmetic,
{
    // The garbler and the evaluator's values are added together.
    // For simplicity we assume that the addition will not result
    // in a carry.
    let sum = f.bin_addition_no_carry(&wire_inputs.garbler_wires, &wire_inputs.evaluator_wires)?;

    Ok(sum)
}

fn sum_in_clear(gb_value: u128, ev_value: u128) -> u128 {
    gb_value + ev_value
}
fn main() {
    let args: Vec<_> = env::args().collect();
    let gb_value: u128 = args[1].parse().unwrap();
    let ev_value: u128 = args[2].parse().unwrap();

    println!(
        "Sum({} + {}) = {}",
        gb_value,
        ev_value,
        sum_in_clear(gb_value, ev_value)
    );
}
