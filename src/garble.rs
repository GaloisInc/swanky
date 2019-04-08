//! Structs and functions for creating, streaming, and evaluating garbled circuits.

use crate::circuit::Circuit;
use crate::error::GarblerError;
use crate::fancy::HasModulus;
use crate::wire::Wire;
use scuttlebutt::{AesRng, Block};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

mod evaluator;
mod garbler;

pub use crate::garble::evaluator::{Decoder, Encoder, Evaluator, GarbledCircuit};
pub use crate::garble::garbler::Garbler;

/// The outputs that can be emitted by a Garbler and consumed by an Evaluator.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub enum Message {
    /// The zero wire and delta offset for one of the garbler's inputs.
    ///
    /// This is produced by the garbler, and should be transformed into
    /// `GarblerInput` before being sent to the evaluator.
    UnencodedGarblerInput {
        /// The zero wire-label.
        zero: Wire,
        /// The offset wire-label.
        delta: Wire,
    },

    /// The zero wire and delta offset for one of the evaluator's inputs.
    ///
    /// This is produced by the garbler, and should be transformed into
    /// `EvaluatorInput` before being sent to the evaluator.
    UnencodedEvaluatorInput {
        /// The zero wire-label.
        zero: Wire,
        /// The offset wire-label.
        delta: Wire,
    },

    /// Encoded input for one of the garbler's inputs.
    GarblerInput(Wire),

    /// Encoded input for one of the evaluator's inputs.
    EvaluatorInput(Wire),

    /// Constant wire.
    Constant {
        /// The constant value.
        value: u16,
        /// The constant's wire-label.
        wire: Wire,
    },

    /// Garbled gate emitted by a projection or multiplication.
    GarbledGate(Vec<Block>),

    /// Output decoding information.
    OutputCiphertext(Vec<Block>),
}

impl std::fmt::Display for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(match self {
            Message::UnencodedGarblerInput { .. } => "UnencodedGarblerInput",
            Message::UnencodedEvaluatorInput { .. } => "UnencodedEvaluatorInput",
            Message::GarblerInput(_) => "GarblerInput",
            Message::EvaluatorInput(_) => "EvaluatorInput",
            Message::Constant { .. } => "Constant",
            Message::GarbledGate(_) => "GarbledGate",
            Message::OutputCiphertext(_) => "OutputCiphertext",
        })
    }
}

////////////////////////////////////////////////////////////////////////////////
// general user-facing garbling functions

// XXX: remove?

/// Create an iterator over the messages produced by fancy garbling.
///
/// This creates a new thread for the garbler, which passes messages back through a
/// channel one by one. This function has a restrictive input type because
/// `fancy_computation` is sent to the new thread.
// pub fn garble_iter<F>(f: &'static mut F, rng: AesRng) -> impl Iterator<Item = Message>
// where
//     F: FnMut(&mut Garbler<AesRng>) + Send + 'static,
// {
//     let (sender, receiver) = std::sync::mpsc::sync_channel(20);

//     std::thread::spawn(move || {
//         let callback = move |m| {
//             sender
//                 .send(m)
//                 .expect("garble_iter thread could not send message to iterator")
//         };
//         let mut garbler = Garbler::new(callback, rng);
//         f(&mut garbler);
//     });

//     receiver.into_iter()
// }

/// Garble a circuit without streaming.
pub fn garble(c: &mut Circuit) -> Result<(Encoder, Decoder, GarbledCircuit), GarblerError> {
    let garbler_inputs = Arc::new(Mutex::new(Vec::new()));
    let evaluator_inputs = Arc::new(Mutex::new(Vec::new()));
    let garbled_gates = Arc::new(Mutex::new(Vec::new()));
    let constants = Arc::new(Mutex::new(HashMap::new()));
    let garbled_outputs = Arc::new(Mutex::new(Vec::new()));
    let rng = AesRng::new();

    let callback = {
        let garbler_inputs = garbler_inputs.clone();
        let evaluator_inputs = evaluator_inputs.clone();
        let garbled_gates = garbled_gates.clone();
        let constants = constants.clone();
        let garbled_outputs = garbled_outputs.clone();
        move |m| {
            match m {
                Message::UnencodedGarblerInput { zero, .. } => {
                    garbler_inputs.lock().unwrap().push(zero)
                }
                Message::UnencodedEvaluatorInput { zero, .. } => {
                    evaluator_inputs.lock().unwrap().push(zero)
                }
                Message::GarbledGate(w) => garbled_gates.lock().unwrap().push(w),
                Message::OutputCiphertext(c) => garbled_outputs.lock().unwrap().push(c),
                Message::Constant { value, wire } => {
                    let q = wire.modulus();
                    constants.lock().unwrap().insert((value, q), wire);
                }
                m => return Err(GarblerError::MessageError(format!("invalid message {}", m))),
            }
            Ok(())
        }
    };

    let mut garbler = Garbler::new(callback, rng);
    let outputs = c.eval(&mut garbler)?;
    c.process_outputs(&outputs, &mut garbler)?;
    let deltas = garbler.get_deltas();

    let en = Encoder::new(
        garbler_inputs.lock().unwrap().clone(),
        evaluator_inputs.lock().unwrap().clone(),
        deltas,
    );
    let ev = GarbledCircuit::new(
        garbled_gates.lock().unwrap().clone(),
        constants.lock().unwrap().clone(),
    );
    let de = Decoder::new(garbled_outputs.lock().unwrap().clone());

    Ok((en, de, ev))
}

////////////////////////////////////////////////////////////////////////////////
// tests

#[cfg(test)]
mod classic {
    use super::*;
    use crate::circuit::{Circuit, CircuitBuilder};
    use crate::dummy::Dummy;
    use crate::fancy::{BundleGadgets, Fancy};
    use crate::util::{self, RngExt};
    use rand::thread_rng;

    // helper {{{
    fn garble_test_helper<F>(f: F)
    where
        F: Fn(u16) -> Circuit,
    {
        let mut rng = thread_rng();
        for _ in 0..16 {
            let q = rng.gen_prime();
            let mut c = &mut f(q);
            let (en, de, ev) = garble(&mut c).unwrap();
            for _ in 0..16 {
                let inps = (0..c.num_evaluator_inputs())
                    .map(|i| rng.gen_u16() % c.evaluator_input_mod(i))
                    .collect::<Vec<u16>>();
                // Run the garbled circuit evaluator.
                let xs = &en.encode_evaluator_inputs(&inps);
                let ys = &ev.eval(&mut c, &[], xs).unwrap();
                let decoded = de.decode(ys)[0];
                // Run the dummy evaluator.
                let mut dummy = Dummy::new(&[], &inps);
                let outputs = c.eval(&mut dummy).unwrap();
                c.process_outputs(&outputs, &mut dummy).unwrap();
                let should_be = dummy.get_output()[0];
                assert_eq!(decoded, should_be);
            }
        }
    }
    //}}}
    #[test] // add {{{
    fn add() {
        garble_test_helper(|q| {
            let mut b = CircuitBuilder::new();
            let x = b.evaluator_input(q).unwrap();
            let y = b.evaluator_input(q).unwrap();
            let z = b.add(&x, &y).unwrap();
            b.output(&z).unwrap();
            b.finish()
        });
    }
    //}}}
    #[test] // add_many {{{
    fn add_many() {
        garble_test_helper(|q| {
            let mut b = CircuitBuilder::new();
            let xs = b.evaluator_inputs(&vec![q; 16]).unwrap();
            let z = b.add_many(&xs).unwrap();
            b.output(&z).unwrap();
            b.finish()
        });
    }
    //}}}
    #[test] // or_many {{{
    fn or_many() {
        garble_test_helper(|_| {
            let mut b = CircuitBuilder::new();
            let xs = b.evaluator_inputs(&vec![2; 16]).unwrap();
            let z = b.or_many(&xs).unwrap();
            b.output(&z).unwrap();
            b.finish()
        });
    }
    //}}}
    #[test] // sub {{{
    fn sub() {
        garble_test_helper(|q| {
            let mut b = CircuitBuilder::new();
            let x = b.evaluator_input(q).unwrap();
            let y = b.evaluator_input(q).unwrap();
            let z = b.sub(&x, &y).unwrap();
            b.output(&z).unwrap();
            b.finish()
        });
    }
    //}}}
    #[test] // cmul {{{
    fn cmul() {
        garble_test_helper(|q| {
            let mut b = CircuitBuilder::new();
            let x = b.evaluator_input(q).unwrap();
            let _ = b.evaluator_input(q).unwrap();
            let z;
            if q > 2 {
                z = b.cmul(&x, 2).unwrap();
            } else {
                z = b.cmul(&x, 1).unwrap();
            }
            b.output(&z).unwrap();
            b.finish()
        });
    }
    //}}}
    #[test] // proj_cycle {{{
    fn proj_cycle() {
        garble_test_helper(|q| {
            let mut tab = Vec::new();
            for i in 0..q {
                tab.push((i + 1) % q);
            }
            let mut b = CircuitBuilder::new();
            let x = b.evaluator_input(q).unwrap();
            let _ = b.evaluator_input(q).unwrap();
            let z = b.proj(&x, q, Some(tab)).unwrap();
            b.output(&z).unwrap();
            b.finish()
        });
    }
    //}}}
    #[test] // proj_rand {{{
    fn proj_rand() {
        garble_test_helper(|q| {
            let mut rng = thread_rng();
            let mut tab = Vec::new();
            for _ in 0..q {
                tab.push(rng.gen_u16() % q);
            }
            let mut b = CircuitBuilder::new();
            let x = b.evaluator_input(q).unwrap();
            let _ = b.evaluator_input(q).unwrap();
            let z = b.proj(&x, q, Some(tab)).unwrap();
            b.output(&z).unwrap();
            b.finish()
        });
    }
    //}}}
    #[test] // mod_change {{{
    fn mod_change() {
        garble_test_helper(|q| {
            let mut b = CircuitBuilder::new();
            let x = b.evaluator_input(q).unwrap();
            let z = b.mod_change(&x, q * 2).unwrap();
            b.output(&z).unwrap();
            b.finish()
        });
    }
    //}}}
    #[test] // half_gate {{{
    fn half_gate() {
        garble_test_helper(|q| {
            let mut b = CircuitBuilder::new();
            let x = b.evaluator_input(q).unwrap();
            let y = b.evaluator_input(q).unwrap();
            let z = b.mul(&x, &y).unwrap();
            b.output(&z).unwrap();
            b.finish()
        });
    }
    //}}}
    #[test] // half_gate_unequal_mods {{{
    fn half_gate_unequal_mods() {
        for q in 3..16 {
            let ymod = 2 + thread_rng().gen_u16() % 6; // lower mod is capped at 8 for now
            println!("\nTESTING MOD q={} ymod={}", q, ymod);

            let mut b = CircuitBuilder::new();
            let x = b.evaluator_input(q).unwrap();
            let y = b.evaluator_input(ymod).unwrap();
            let z = b.mul(&x, &y).unwrap();
            b.output(&z).unwrap();
            let mut c = b.finish();

            let (en, de, ev) = garble(&mut c).unwrap();

            let mut fail = false;
            for x in 0..q {
                for y in 0..ymod {
                    println!("TEST x={} y={}", x, y);
                    let xs = &en.encode_evaluator_inputs(&[x, y]);
                    let ys = &ev.eval(&mut c, &[], xs).unwrap();
                    let decoded = de.decode(ys)[0];
                    let mut dummy = Dummy::new(&[], &[x, y]);
                    let outputs = c.eval(&mut dummy).unwrap();
                    c.process_outputs(&outputs, &mut dummy).unwrap();
                    let should_be = dummy.get_output()[0];
                    if decoded != should_be {
                        println!(
                            "FAILED inp={:?} q={} got={} should_be={}",
                            [x, y],
                            q,
                            decoded,
                            should_be
                        );
                        fail = true;
                    } else {
                        // println!("SUCCEEDED inp={:?} q={} got={} should_be={}", [x,y], q, decoded, should_be);
                    }
                }
            }
            if fail {
                panic!("failed!")
            }
        }
    }
    //}}}
    #[test] // mixed_radix_addition {{{
    fn mixed_radix_addition() {
        let mut rng = thread_rng();

        let nargs = 2 + rng.gen_usize() % 100;
        // let mods = (0..7).map(|_| rng.gen_modulus()).collect_vec(); // slow
        let mods = [3, 7, 10, 2, 13]; // fast

        let mut b = CircuitBuilder::new();
        let xs = b.evaluator_input_bundles(&mods, nargs).unwrap();
        let z = b.mixed_radix_addition(&xs).unwrap();
        b.output_bundle(&z).unwrap();
        let mut circ = b.finish();

        let (en, de, ev) = garble(&mut circ).unwrap();
        println!("mods={:?} nargs={} size={}", mods, nargs, ev.size());

        let Q: u128 = mods.iter().map(|&q| q as u128).product();

        // test random values
        for _ in 0..16 {
            let mut should_be = 0;
            let mut ds = Vec::new();
            for _ in 0..nargs {
                let x = rng.gen_u128() % Q;
                should_be = (should_be + x) % Q;
                ds.extend(util::as_mixed_radix(x, &mods).iter());
            }
            let X = en.encode_evaluator_inputs(&ds);
            let Y = ev.eval(&mut circ, &[], &X).unwrap();
            let res = de.decode(&Y);
            assert_eq!(util::from_mixed_radix(&res, &mods), should_be);
        }
    }
    //}}}
    #[test] // basic constants {{{
    fn basic_constant() {
        let mut b = CircuitBuilder::new();
        let mut rng = thread_rng();

        let q = rng.gen_modulus();
        let c = rng.gen_u16() % q;

        let y = b.constant(c, q).unwrap();
        b.output(&y).unwrap();

        let mut circ = b.finish();
        let (_, de, ev) = garble(&mut circ).unwrap();

        for _ in 0..64 {
            let mut dummy = Dummy::new(&[], &[]);
            let outputs = circ.eval(&mut dummy).unwrap();
            circ.process_outputs(&outputs, &mut dummy).unwrap();
            assert_eq!(dummy.get_output()[0], c, "plaintext eval failed");
            let Y = ev.eval(&mut circ, &[], &[]).unwrap();
            assert_eq!(de.decode(&Y)[0], c, "garbled eval failed");
        }
    }
    //}}}
    #[test] // constants {{{
    fn constants() {
        let mut b = CircuitBuilder::new();
        let mut rng = thread_rng();

        let q = rng.gen_modulus();
        let c = rng.gen_u16() % q;

        let x = b.evaluator_input(q).unwrap();
        let y = b.constant(c, q).unwrap();
        let z = b.add(&x, &y).unwrap();
        b.output(&z).unwrap();

        let mut circ = b.finish();
        let (en, de, ev) = garble(&mut circ).unwrap();

        for _ in 0..64 {
            let x = rng.gen_u16() % q;
            let mut dummy = Dummy::new(&[], &[x]);
            let outputs = circ.eval(&mut dummy).unwrap();
            circ.process_outputs(&outputs, &mut dummy).unwrap();
            assert_eq!(dummy.get_output()[0], (x + c) % q, "plaintext");

            let X = en.encode_evaluator_inputs(&[x]);
            let Y = ev.eval(&mut circ, &[], &X).unwrap();
            assert_eq!(de.decode(&Y)[0], (x + c) % q, "garbled");
        }
    }
    //}}}
}

#[cfg(test)]
mod streaming {
    use super::*;
    use crate::fancy::Fancy;
    use crate::util::RngExt;
    use crate::FancyError;
    use itertools::Itertools;
    use rand::thread_rng;
    use std::fmt::{Debug, Display};
    use std::sync::{Arc, Mutex};

    // helper {{{
    fn streaming_test<F, G>(
        mut f_gb: F,
        mut f_ev: G,
        gb_inp: &[u16],
        ev_inp: &[u16],
        should_be: &[u16],
    ) where
        F: FnMut(&mut Garbler<AesRng>) + Send + Sync + Copy + 'static,
        G: FnMut(&mut Evaluator) + Send + Sync + Copy + 'static,
    {
        let rng = AesRng::new();
        let (sender, receiver) = std::sync::mpsc::sync_channel(20);
        let sender = Arc::new(Mutex::new(sender));
        let receiver = receiver.into_iter();
        let receiver = Arc::new(Mutex::new(receiver));

        std::thread::spawn(move || {
            let callback = move |m| sender.lock().unwrap().send(m).map_err(GarblerError::from);
            let mut garbler = Garbler::new(callback, rng);
            f_gb(&mut garbler);
        });

        let mut gb_inp_iter = gb_inp.to_vec().into_iter();
        let mut ev_inp_iter = ev_inp.to_vec().into_iter();

        // the evaluator's callback gets the next message from the garble iterator,
        // encodes the appropriate inputs, and sends it along
        let callback = move |_| {
            let blocks = match receiver.lock().unwrap().next().unwrap() {
                Message::UnencodedGarblerInput { zero, delta } => {
                    // Encode the garbler's next input
                    let x = gb_inp_iter.next().expect("not enough garbler inputs!");
                    vec![zero.plus(&delta.cmul(x)).as_block()]
                }

                Message::UnencodedEvaluatorInput { zero, delta } => {
                    // Encode the garbler's next input
                    let x = ev_inp_iter.next().expect("not enough evaluator inputs!");
                    vec![zero.plus(&delta.cmul(x)).as_block()]
                }
                Message::Constant { value: _, wire } => vec![wire.as_block()],
                Message::GarbledGate(gate) => gate,
                Message::OutputCiphertext(ct) => ct,
                _ => panic!(),
            };
            Ok(blocks)
        };

        let mut ev = Evaluator::new(callback);
        f_ev(&mut ev);

        let result = ev.decode_output();
        println!("gb_inp={:?} ev_inp={:?}", gb_inp, ev_inp);
        assert_eq!(result, should_be)
    }
    //}}}

    fn fancy_addition<
        W: Clone + HasModulus,
        E: Display + Debug + From<FancyError>,
        F: Fancy<Item = W, Error = E>,
    >(
        b: &mut F,
        q: u16,
    ) //{{{
    {
        let x = b.garbler_input(q, None).unwrap();
        let y = b.evaluator_input(q).unwrap();
        let z = b.add(&x, &y).unwrap();
        b.output(&z).unwrap();
    }

    #[test]
    fn addition() {
        let mut rng = thread_rng();
        for _ in 0..16 {
            let q = rng.gen_modulus();
            let x = rng.gen_u16() % q;
            let y = rng.gen_u16() % q;
            streaming_test(
                move |b| fancy_addition(b, q.clone()),
                move |b| fancy_addition(b, q.clone()),
                &[x],
                &[y],
                &[(x + y) % q],
            );
        }
    }
    //}}}

    fn fancy_subtraction<W: Clone + HasModulus, E: Display + Debug + From<FancyError>>(
        b: &mut Fancy<Item = W, Error = E>,
        q: u16,
    ) //{{{
    {
        let x = b.garbler_input(q, None).unwrap();
        let y = b.evaluator_input(q).unwrap();
        let z = b.sub(&x, &y).unwrap();
        b.output(&z).unwrap();
    }

    #[test]
    fn subtraction() {
        let mut rng = thread_rng();
        for _ in 0..16 {
            let q = rng.gen_modulus();
            let x = rng.gen_u16() % q;
            let y = rng.gen_u16() % q;
            streaming_test(
                move |b| fancy_subtraction(b, q),
                move |b| fancy_subtraction(b, q),
                &[x],
                &[y],
                &[(q + x - y) % q],
            );
        }
    }
    //}}}

    fn fancy_multiplication<W: Clone + HasModulus, E: Debug + Display + From<FancyError>>(
        b: &mut Fancy<Item = W, Error = E>,
        q: u16,
    ) // {{{
    {
        let x = b.garbler_input(q, None).unwrap();
        let y = b.evaluator_input(q).unwrap();
        let z = b.mul(&x, &y).unwrap();
        b.output(&z).unwrap();
    }

    #[test]
    fn multiplication() {
        let mut rng = thread_rng();
        for _ in 0..16 {
            let q = rng.gen_modulus();
            let x = rng.gen_u16() % q;
            let y = rng.gen_u16() % q;
            streaming_test(
                move |b| fancy_multiplication(b, q),
                move |b| fancy_multiplication(b, q),
                &[x],
                &[y],
                &[(x * y) % q],
            );
        }
    }
    //}}}

    fn fancy_cmul<W: Clone + HasModulus, E: Debug + Display + From<FancyError>>(
        b: &mut Fancy<Item = W, Error = E>,
        q: u16,
    ) // {{{
    {
        let x = b.garbler_input(q, None).unwrap();
        let z = b.cmul(&x, 5).unwrap();
        b.output(&z).unwrap();
    }

    #[test]
    fn cmul() {
        let mut rng = thread_rng();
        for _ in 0..16 {
            let q = rng.gen_modulus();
            let x = rng.gen_u16() % q;
            streaming_test(
                move |b| fancy_cmul(b, q),
                move |b| fancy_cmul(b, q),
                &[x],
                &[],
                &[(x * 5) % q],
            );
        }
    }
    //}}}

    fn fancy_projection<W: Clone + HasModulus, E: Debug + Display + From<FancyError>>(
        b: &mut Fancy<Item = W, Error = E>,
        q: u16,
    ) // {{{
    {
        let x = b.garbler_input(q, None).unwrap();
        let tab = (0..q).map(|i| (i + 1) % q).collect_vec();
        let z = b.proj(&x, q, Some(tab)).unwrap();
        b.output(&z).unwrap();
    }

    #[test]
    fn proj() {
        let mut rng = thread_rng();
        for _ in 0..16 {
            let q = rng.gen_modulus();
            let x = rng.gen_u16() % q;
            streaming_test(
                move |b| fancy_projection(b, q),
                move |b| fancy_projection(b, q),
                &[x],
                &[],
                &[(x + 1) % q],
            );
        }
    }
    //}}}
}

#[cfg(test)]
mod complex {
    use super::*;
    use crate::dummy::Dummy;
    use crate::error::EvaluatorError;
    use crate::fancy::BundleGadgets;
    use crate::fancy::Fancy;
    use crate::util::RngExt;
    use rand::thread_rng;
    use std::sync::{Arc, Mutex};

    fn complex_gadget<F, W>(b: &mut F, q: u128, n: usize)
    where
        W: Clone + HasModulus + Send,
        F: Fancy<Item = W> + Send,
    {
        let mut zs = Vec::with_capacity(n);
        for _ in 0..n {
            let c = b.constant_bundle_crt(1, q).unwrap();
            let x = b.garbler_input_bundle_crt(q, None).unwrap();
            let x = b.mul_bundles(&x, &c).unwrap();
            let z = b.relu(&x, "100%", None).unwrap();
            zs.push(z);
        }
        b.output_bundles(&zs).unwrap();
    }

    fn complex_gadget_<F, W>(b: &mut F, q: u128, n: usize)
    where
        W: Clone + HasModulus + Send,
        F: Fancy<Item = W> + Send,
    {
        let mut zs = Vec::with_capacity(n);
        for _ in 0..n {
            let c = b.constant_bundle_crt(1, q).unwrap();
            let x = b.evaluator_input_bundle_crt(q).unwrap();
            let x = b.mul_bundles(&x, &c).unwrap();
            let z = b.relu(&x, "100%", None).unwrap();
            zs.push(z);
        }
        b.output_bundles(&zs).unwrap();
    }

    #[test]
    fn test_complex_gadgets() {
        let mut rng = thread_rng();
        let N = 10;
        let Q = crate::util::modulus_with_width(10);
        for _ in 0..16 {
            let input = (0..N)
                .map(|_| crate::util::crt_factor(rng.gen_u128() % Q, Q))
                .flatten()
                .collect::<Vec<u16>>();

            // Compute the correct answer using `Dummy`.
            let input_ = input.clone();
            let mut dummy = Dummy::new(&input_, &[]);
            complex_gadget(&mut dummy, Q, N);
            let should_be = dummy.get_output();
            // Do 2PC computation.
            let (tx, rx) = std::sync::mpsc::channel();
            let tx = Arc::new(Mutex::new(tx));
            let rx = Arc::new(Mutex::new(rx));
            let mut input_ = input.clone();
            let callback = move |m| {
                let m = match m {
                    Message::UnencodedGarblerInput { zero, delta } => {
                        let x = input_.remove(0);
                        let w = zero.plus(&delta.cmul(x));
                        vec![w.as_block()]
                    }
                    Message::Constant { value: _, wire } => vec![wire.as_block()],
                    Message::GarbledGate(gate) => gate,
                    Message::OutputCiphertext(ct) => ct,
                    m => {
                        return Err(GarblerError::MessageError(format!("invalid message {}", m)));
                    }
                };
                tx.lock().unwrap().send(m).map_err(GarblerError::from)
            };

            std::thread::spawn(move || {
                let rng = AesRng::new();
                let mut garbler = Garbler::new(callback, rng);
                complex_gadget(&mut garbler, Q, N);
            });
            let mut evaluator = Evaluator::new(move |_| Ok(rx.lock().unwrap().recv().unwrap()));
            complex_gadget(&mut evaluator, Q, N);
            let result = evaluator.decode_output();
            assert_eq!(result, should_be);

            let (tx, rx) = std::sync::mpsc::channel();
            let tx = Arc::new(Mutex::new(tx));
            let rx = Arc::new(Mutex::new(rx));
            let mut input_ = input.clone();
            std::thread::spawn(move || {
                let callback = move |m| {
                    let m = match m {
                        Message::UnencodedEvaluatorInput { zero, delta } => {
                            let x = input_.remove(0);
                            let w = zero.plus(&delta.cmul(x));
                            vec![w.as_block()]
                        }
                        Message::Constant { value: _, wire } => vec![wire.as_block()],
                        Message::GarbledGate(gate) => gate,
                        Message::OutputCiphertext(ct) => ct,
                        m => {
                            return Err(GarblerError::MessageError(format!(
                                "invalid message {}",
                                m
                            )));
                        }
                    };
                    tx.lock().unwrap().send(m).map_err(GarblerError::from)
                };
                let rng = AesRng::new();
                let mut garbler = Garbler::new(callback, rng);
                complex_gadget_(&mut garbler, Q, N);
            });
            let mut evaluator =
                Evaluator::new(move |_| rx.lock().unwrap().recv().map_err(EvaluatorError::from));
            complex_gadget_(&mut evaluator, Q, N);
            let result = evaluator.decode_output();
            assert_eq!(result, should_be);
        }
    }
}
