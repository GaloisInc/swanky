//! An example that computes the gcd of two secret numbers in a binary garbled circuit
//! using fancy-garbling.

use fancy_garbling::{
    twopac::semihonest::{Evaluator, Garbler},
    AllWire, BinaryBundle, BinaryGadgets, Fancy, FancyArithmetic, FancyBinary, FancyReveal,
};

use ocelot::{ot::AlszReceiver as OtReceiver, ot::AlszSender as OtSender};
use scuttlebutt::{AbstractChannel, AesRng};

use std::cmp::{max, Ordering};
use std::env;

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

fn gb_gcd<C>(rng: &mut AesRng, channel: &mut C, input: u128, upper_bound: u128)
where
    C: AbstractChannel + std::clone::Clone,
{
    // (1)
    let mut gb =
        Garbler::<C, AesRng, OtSender, AllWire>::new(channel.clone(), rng.clone()).unwrap();
}

/// The evaluator's main method:
/// Given an `input` and public `upper_bound` (which must be pre-shared with the garbler)
/// securely compute and return the GCD of `input` and the garbler's input
///
/// In more detail:
///
/// (1) The evaluator is first created using the passed rng and value.

fn ev_gcd<C>(rng: &mut AesRng, channel: &mut C, input: u128, upper_bound: u128) -> u128
where
    C: AbstractChannel + std::clone::Clone,
{
    // (1)
    let mut ev =
        Evaluator::<C, AesRng, OtReceiver, AllWire>::new(channel.clone(), rng.clone()).unwrap();
    todo!()
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
    // to be a known maximal value that both party know that neither of their values will exceed,
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

fn main() {
    let args: Vec<_> = env::args().collect();
    let gb_value: u128 = args[1].parse().unwrap();
    let ev_value: u128 = args[2].parse().unwrap();
    let upper_bound: u128 = max(gb_value, ev_value);

    println!(
        "GCD({}, {}) = {}",
        gb_value,
        ev_value,
        gcd_in_clear(gb_value, ev_value, upper_bound)
    );
}
