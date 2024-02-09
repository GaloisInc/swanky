//! An example that secretly retrieves an element from an ORAM in a binary garbled circuit
//! using fancy-garbling.
use fancy_garbling::{
    twopac::semihonest::{Evaluator, Garbler},
    AllWire, BinaryBundle, BinaryGadgets, Fancy, FancyArithmetic, FancyBinary, FancyInput,
    FancyReveal,
};

use ocelot::{ot::AlszReceiver as OtReceiver, ot::AlszSender as OtSender};
use scuttlebutt::{AbstractChannel, AesRng};

use std::env;
use std::fmt::Debug;
/// A structure that contains both the garbler and the evaluators
/// wires. This structure simplifies the API of the garbled circuit.
struct ORAMInputs<F> {
    ram: Vec<BinaryBundle<F>>,
    query: BinaryBundle<F>,
}
/// The garbler's main method:
/// (1) The garbler is first created using the passed rng and value.
/// (2) The garbler then exchanges their wires obliviously with the evaluator.
fn gb_linear_oram<C>(rng: &mut AesRng, channel: &mut C, inputs: &[u128])
where
    C: AbstractChannel + std::clone::Clone,
{
    // (1)
    let mut gb =
        Garbler::<C, AesRng, OtSender, AllWire>::new(channel.clone(), rng.clone()).unwrap();
    // The size of the RAM is assumed to be public. The garbler sends their number of
    // of input wires. We note that every element of the RAM has a fixed size of 128 bits.
    let _ = channel.write_usize(inputs.len());
    // (2)
    let circuit_wires = gb_set_fancy_inputs(&mut gb, inputs);
}

/// The garbler's wire exchange method
fn gb_set_fancy_inputs<F, E>(gb: &mut F, inputs: &[u128]) -> ORAMInputs<F::Item>
where
    F: FancyInput<Item = AllWire, Error = E>,
    E: Debug,
{
    // The number of bits needed to represent a single input value
    let nbits = 128;
    // The garbler encodes their wires with the appropriate moduli per wire.
    let ram: Vec<BinaryBundle<F::Item>> = gb.bin_encode_many(inputs, nbits).unwrap();
    // The evaluator receives their input labels using Oblivious Transfer (OT)
    let query: BinaryBundle<F::Item> = gb.bin_receive(nbits).unwrap();

    ORAMInputs { ram, query }
}

/// The evaluator's main method:
/// (1) The evaluator is first created using the passed rng and value.
/// (2) The evaluator then exchanges their wires obliviously with the garbler.
fn ev_linear_oram<C>(rng: &mut AesRng, channel: &mut C, input: u128) -> u128
where
    C: AbstractChannel + std::clone::Clone,
{
    // (1)
    let mut ev =
        Evaluator::<C, AesRng, OtReceiver, AllWire>::new(channel.clone(), rng.clone()).unwrap();
    let ram_size = channel.read_usize().unwrap();
    // (2)
    let circuit_wires = ev_set_fancy_inputs(&mut ev, input, ram_size);

    todo!()
}
fn ev_set_fancy_inputs<F, E>(ev: &mut F, input: u128, ram_size: usize) -> ORAMInputs<F::Item>
where
    F: FancyInput<Item = AllWire, Error = E>,
    E: Debug,
{
    // The number of bits needed to represent a single input value
    let nbits = 128;
    // The evaluator receives the garblers input labels.
    let ram: Vec<BinaryBundle<F::Item>> = ev.bin_receive_many(ram_size, nbits).unwrap();
    // The evaluator encodes their input labels.
    let query: BinaryBundle<F::Item> = ev.bin_encode(input, nbits).unwrap();

    ORAMInputs { ram, query }
}

/// The main fancy function which describes the garbled circuit for linear ORAM.
fn fancy_linear_oram<F>(
    f: &mut F,
    wire_inputs: ORAMInputs<F::Item>,
) -> Result<BinaryBundle<F::Item>, F::Error>
where
    F: FancyReveal + Fancy + BinaryGadgets + FancyBinary + FancyArithmetic,
{
    let ram: Vec<BinaryBundle<_>> = wire_inputs.ram;
    let index: BinaryBundle<_> = wire_inputs.query;

    let mut result = f.bin_constant_bundle(0, 128)?;
    let zero = f.bin_constant_bundle(0, 128)?;

    // We traverse the garbler's RAM one element at a time, and multiplex
    // the result based on whether the evaluator's query matches the current
    // index.
    for (i, item) in ram.iter().enumerate() {
        // The current index is turned into a binary constant bundle.
        let current_index = f.bin_constant_bundle(i as u128, 128)?;
        // We check if the evaluator's query matches the current index obliviously.
        let mux_bit = f.bin_eq_bundles(&index, &current_index)?;
        // We use the result of the prior equality check to multiplex by either adding 0 to
        // the result of the computation and keeping it as is, or adding RAM[i] to it
        // and updating it. The evaluator's query can only correspond to a single index.
        let mux = f.bin_multiplex(&mux_bit, &zero, item)?;
        result = f.bin_addition_no_carry(&result, &mux)?;
    }

    Ok(result)
}

fn ram_in_clear(index: usize, ram: &[u128]) -> u128 {
    ram[index]
}

fn main() {
    let args: Vec<_> = env::args().collect();

    let ev_index: usize = args[1].parse().unwrap();
    let gb_ram_string: String = args[2].parse::<String>().unwrap();
    let gb_ram: Vec<u128> = gb_ram_string
        .split_terminator(['[', ',', ']', ' '])
        .filter(|&x| !x.is_empty())
        .map(|s| s.parse::<u128>().unwrap())
        .collect();

    println!(
        "ORAM(index:{ev_index}, ram:{:?}) = {}",
        gb_ram,
        ram_in_clear(ev_index, &gb_ram)
    );
}
