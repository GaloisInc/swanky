//! An example that adds two secret numbers in a binary garbled circuit
//! using fancy-garbling.
use fancy_garbling::{
    BinaryBundle, BinaryGadgets, Fancy, FancyArithmetic, FancyBinary, FancyReveal,
};
use std::env;

/// The main fancy function which describes the garbled circuit for summation.
fn fancy_sum<F>(
    f: &mut F,
    garbler_wires: BinaryBundle<F::Item>,
    evaluator_wires: BinaryBundle<F::Item>,
) -> Result<BinaryBundle<F::Item>, F::Error>
where
    F: FancyReveal + Fancy + BinaryGadgets + FancyBinary + FancyArithmetic,
{
    // The garbler and the evaluator's values are added together.
    // For simplicity we assume that the addition will not result
    // in a carry.
    let sum = f.bin_addition_no_carry(&garbler_wires, &evaluator_wires)?;

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
