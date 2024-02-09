//! An example that computes the gcd of two secret numbers in a binary garbled circuit
//! using fancy-garbling.

use fancy_garbling::{
    twopac::semihonest::{Evaluator, Garbler},
    util, AllWire, BinaryBundle, BinaryGadgets, Fancy, FancyArithmetic, FancyBinary, FancyInput,
    FancyReveal,
};

use ocelot::{ot::AlszReceiver as OtReceiver, ot::AlszSender as OtSender};
use scuttlebutt::{AbstractChannel, AesRng, Channel};

use std::cmp::{max, Ordering};
use std::fmt::Debug;
use std::{
    io::{BufReader, BufWriter},
    os::unix::net::UnixStream,
};

/// A structure that contains both the garbler and the evaluators
/// wires. This structure simplifies the API of the garbled circuit.
struct GCDInputs<F> {
    pub garbler_wires: BinaryBundle<F>,
    pub evaluator_wires: BinaryBundle<F>,
}

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
fn gb_gcd<C>(rng: &mut AesRng, channel: &mut C, input: u128, upper_bound: u128)
where
    C: AbstractChannel + std::clone::Clone,
{
    // (1)
    let mut gb =
        Garbler::<C, AesRng, OtSender, AllWire>::new(channel.clone(), rng.clone()).unwrap();
    // (2)
    let circuit_wires = gb_set_fancy_inputs(&mut gb, input);
    // (3)
    let gcd =
        fancy_gcd::<Garbler<C, AesRng, OtSender, AllWire>>(&mut gb, circuit_wires, upper_bound)
            .unwrap();
    // (4)
    gb.outputs(gcd.wires()).unwrap();
}
/// The garbler's wire exchange method
fn gb_set_fancy_inputs<F, E>(gb: &mut F, input: u128) -> GCDInputs<F::Item>
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

    GCDInputs {
        garbler_wires,
        evaluator_wires,
    }
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
fn ev_gcd<C>(rng: &mut AesRng, channel: &mut C, input: u128, upper_bound: u128) -> u128
where
    C: AbstractChannel + std::clone::Clone,
{
    // (1)
    let mut ev =
        Evaluator::<C, AesRng, OtReceiver, AllWire>::new(channel.clone(), rng.clone()).unwrap();
    // (2)
    let circuit_wires = ev_set_fancy_inputs(&mut ev, input);
    // (3)
    let gcd =
        fancy_gcd::<Evaluator<C, AesRng, OtReceiver, AllWire>>(&mut ev, circuit_wires, upper_bound)
            .unwrap();
    // (4)
    let gcd_binary = ev
        .outputs(gcd.wires())
        .unwrap()
        .expect("evaluator should produce outputs");

    // (5)
    util::u128_from_bits(&gcd_binary)
}
fn ev_set_fancy_inputs<F, E>(ev: &mut F, input: u128) -> GCDInputs<F::Item>
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

    GCDInputs {
        garbler_wires,
        evaluator_wires,
    }
}

/// The main fancy function which describes the garbled circuit for gcd.
fn fancy_gcd<F>(
    f: &mut F,
    wire_inputs: GCDInputs<F::Item>,
    upper_bound: u128,
) -> Result<BinaryBundle<F::Item>, F::Error>
where
    F: FancyReveal + Fancy + BinaryGadgets + FancyBinary + FancyArithmetic,
{
    let mut a: BinaryBundle<_> = wire_inputs.garbler_wires;
    let mut b: BinaryBundle<_> = wire_inputs.evaluator_wires;

    // Since the garbled circuit is oblivious, we cannot terminate the gcd algorithm by conditioning on
    // the values of `a` or `b` as is the case in the insecure version of gcd.
    // Instead, we rely on an upper bound on the number of iterations we know the algorithm will
    // terminate by. The Euclidean algorithm based on subtractions will take no more than N steps where N
    // is the larger of the two numbers we are computing the gcd for (think of GCD(X,1) for any X).
    // This is a loose upper bound. To keep input values secret, we can choose the upper bound in the circuit
    // to be a known maximal value that both parties know that neither of their values will exceed,
    // for example 2^32 i.e. std::u32::MAX. This is a very loose upper bound, and is only chosen for
    // illustrative purposes.
    for _ in 0..upper_bound {
        // Since the garbled circuit is non-branching, we don't know whether a > b and cannot branch computation
        // based on that result of that conditional. Instead, we need to perform the computation that occurs
        // for all cases of the predict "is a > b ?", i.e.:
        // (1)  a > b, (2) b > a. We consider the case where a == b separately since that is the case where we stop
        // updating our variables and find the result of the computation gcd(a,b).
        //
        // We compute a := a - b and check for an underflow that will help determine if "a > b";
        let (r_1, mut underflow_r_1) = f.bin_subtraction(&a, &b)?;
        // And compute b := b - a and check for an underflow that will help determine if "b > a";
        let (r_2, mut underflow_r_2) = f.bin_subtraction(&b, &a)?;

        // We compute "a == b"
        let check_equality = f.bin_eq_bundles(&a, &b)?;
        let zero = f.constant(0, 2)?;

        // The `underflow` bits act as dual purpose multiplexing bits:
        // (1) If a > b then underflow_r_1 = 1 and underflow_r_2 = 0
        // (2) If b > a then underflow_r_1 = 0 and underflow_r_2 = 1
        // (3) If a == b then underflow_r_1 = underflow_r_2 = 0
        underflow_r_1 = f.mux(&check_equality, &underflow_r_1, &zero)?;
        underflow_r_2 = f.mux(&check_equality, &underflow_r_2, &zero)?;

        // Using the `underflow` bits we multiplex in the following way:
        // (1) If a > b, a := a - b and b := b
        // (2) If b > a, a := a  and b := b - a
        // (3) If a == b, a := a and b := b
        a = f.bin_multiplex(&underflow_r_1, &a, &r_1)?;
        b = f.bin_multiplex(&underflow_r_2, &b, &r_2)?;
    }

    Ok(a)
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
/// Where 2 is the garbler's value and 3 the evaluator's
struct Cli {
    /// The first integer the garbler's value
    gb_value: u128,
    /// The second integer the evaluator's value
    ev_value: u128,
}

fn main() {
    let cli = Cli::parse();
    let gb_value: u128 = cli.gb_value;
    let ev_value: u128 = cli.ev_value;

    let upper_bound: u128 = max(gb_value, ev_value);

    let (sender, receiver) = UnixStream::pair().unwrap();

    std::thread::spawn(move || {
        let rng_gb = AesRng::new();
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = Channel::new(reader, writer);
        gb_gcd(&mut rng_gb.clone(), &mut channel, gb_value, upper_bound);
    });

    let rng_ev = AesRng::new();
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let mut channel = Channel::new(reader, writer);

    let result = ev_gcd(&mut rng_ev.clone(), &mut channel, ev_value, upper_bound);
    let resut_in_clear = gcd_in_clear(gb_value, ev_value, upper_bound);
    println!(
        "Garbled Circuit result is : GCD({}, {}) = {}",
        gb_value, ev_value, result
    );
    assert!(
        result == resut_in_clear,
        "The result is incorrect and should be {} \n (Note: If this is not the value that you are expecting,\n consider changing the upper bound)",
        resut_in_clear
    );
}
