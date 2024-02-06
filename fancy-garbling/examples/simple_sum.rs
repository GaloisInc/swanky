//! An example that adds two secret numbers in a binary garbled circuit
//! using fancy-garbling.
use fancy_garbling::{
    twopac::semihonest::{Evaluator, Garbler},
    util, AllWire, BinaryBundle, BinaryGadgets, Fancy, FancyArithmetic, FancyBinary, FancyInput,
    FancyReveal,
};

use ocelot::{ot::AlszReceiver as OtReceiver, ot::AlszSender as OtSender};
use scuttlebutt::{AbstractChannel, AesRng, Channel};

use std::fmt::Debug;

use std::env;
use std::{
    io::{BufReader, BufWriter},
    os::unix::net::UnixStream,
};

/// A structure that contains both the garbler and the evaluators
/// wires. This structure simplifies the API of the garbled circuit.
struct SUMInputs<F> {
    pub garbler_wires: BinaryBundle<F>,
    pub evaluator_wires: BinaryBundle<F>,
}

/// The garbler's main method:
/// (1) The garbler is first created using the passed rng and value.
/// (2) The garbler then exchanges their wires obliviously with the evaluator.
/// (3) The garbler and the evaluator then run the garbled circuit.
/// (4) The garbler and the evaluator open the result of the computation.
fn gb_sum<C>(rng: &mut AesRng, channel: &mut C, input: u128)
where
    C: AbstractChannel + std::clone::Clone,
{
    // (1)
    let mut gb =
        Garbler::<C, AesRng, OtSender, AllWire>::new(channel.clone(), rng.clone()).unwrap();
    // (2)
    let circuit_wires = gb_set_fancy_inputs(&mut gb, input);
    // (3)
    let sum = fancy_sum::<Garbler<C, AesRng, OtSender, AllWire>>(&mut gb, circuit_wires).unwrap();
    // (4)
    gb.outputs(sum.wires()).unwrap();
}

/// The garbler's wire exchange method
fn gb_set_fancy_inputs<F, E>(gb: &mut F, input: u128) -> SUMInputs<F::Item>
where
    F: FancyInput<Item = AllWire, Error = E>,
    E: Debug,
{
    // The number of bits needed to represent a single input, in this case a u128
    let nbits = 128;
    // The garbler encodes their input into binary wires
    let garbler_wires: BinaryBundle<F::Item> = gb.bin_encode(input, nbits).unwrap();
    // The evaluator receives their input labels using Oblivious Transfer (OT)
    let evaluator_wires: BinaryBundle<F::Item> = gb.bin_receive(nbits).unwrap();

    SUMInputs {
        garbler_wires,
        evaluator_wires,
    }
}

/// The evaluator's main method:
/// (1) The evaluator is first created using the passed rng and value.
/// (2) The evaluator then exchanges their wires obliviously with the garbler.
/// (3) The evaluator and the garbler then run the garbled circuit.
/// (4) The evaluator and the garbler open the result of the computation.
/// (5) The evaluator translates the binary output of the circuit into its decimal
///     representation.
fn ev_sum<C>(rng: &mut AesRng, channel: &mut C, input: u128) -> u128
where
    C: AbstractChannel + std::clone::Clone,
{
    // (1)
    let mut ev =
        Evaluator::<C, AesRng, OtReceiver, AllWire>::new(channel.clone(), rng.clone()).unwrap();
    // (2)
    let circuit_wires = ev_set_fancy_inputs(&mut ev, input);
    // (3)
    let sum =
        fancy_sum::<Evaluator<C, AesRng, OtReceiver, AllWire>>(&mut ev, circuit_wires).unwrap();

    // (4)
    let sum_binary = ev
        .outputs(sum.wires())
        .unwrap()
        .expect("evaluator should produce outputs");
    // (5)
    util::u128_from_bits(&sum_binary)
}

/// The evaluator's wire exchange method
fn ev_set_fancy_inputs<F, E>(ev: &mut F, input: u128) -> SUMInputs<F::Item>
where
    F: FancyInput<Item = AllWire, Error = E>,
    E: Debug,
{
    // The number of bits needed to represent a single input, in this case a u128
    let nbits = 128;
    // The evaluator receives the garblers input labels.
    let garbler_wires: BinaryBundle<F::Item> = ev.bin_receive(nbits).unwrap();
    // The evaluator receives their input labels using Oblivious Transfer (OT).
    let evaluator_wires: BinaryBundle<F::Item> = ev.bin_encode(input, nbits).unwrap();

    SUMInputs {
        garbler_wires,
        evaluator_wires,
    }
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

    let (sender, receiver) = UnixStream::pair().unwrap();

    std::thread::spawn(move || {
        let rng_gb = AesRng::new();
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = Channel::new(reader, writer);
        gb_sum(&mut rng_gb.clone(), &mut channel, gb_value);
    });

    let rng_ev = AesRng::new();
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let mut channel = Channel::new(reader, writer);

    let sum = sum_in_clear(gb_value, ev_value);
    let result = ev_sum(&mut rng_ev.clone(), &mut channel, ev_value);
    println!(
        "Garbled Circuit result is : SUM({}, {}) = {}",
        gb_value, ev_value, result
    );
    assert!(
        result == sum,
        "The garbled circuit result is incorrect and sould be {sum}"
    );
}
