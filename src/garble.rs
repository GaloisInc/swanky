//! Structs and functions for creating, streaming, and evaluating garbled circuits.

use crate::circuit::Circuit;
use crate::error::GarblerError;
use crate::fancy::{HasModulus, SyncIndex};
use crate::wire::Wire;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

mod evaluator;
mod garbler;

pub use crate::garble::evaluator::{Decoder, Encoder, Evaluator, GarbledCircuit};
pub use crate::garble::garbler::Garbler;

/// The ciphertext created by a garbled gate.
pub type GarbledGate = Vec<u128>;

/// Ciphertext created by the garbler for output gates.
pub type OutputCiphertext = Vec<u128>;

/// The outputs that can be emitted by a Garbler and consumed by an Evaluator.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub enum Message {
    /// Zero wire and delta for one of the garbler's inputs.
    ///
    /// This is produced by the Garbler, and must be transformed into GarblerInput before
    /// being sent to the Evaluator.
    UnencodedGarblerInput { zero: Wire, delta: Wire },

    /// Zero wire and delta for one of the evaluator's inputs.
    ///
    /// This is produced by the Garbler, and must be transformed into EvaluatorInput
    /// before being sent to the Evaluator.
    UnencodedEvaluatorInput { zero: Wire, delta: Wire },

    /// Encoded input for one of the garbler's inputs.
    GarblerInput(Wire),

    /// Encoded input for one of the evaluator's inputs.
    EvaluatorInput(Wire),

    /// Constant wire carrying the value.
    Constant { value: u16, wire: Wire },

    /// Garbled gate emitted by a projection or multiplication.
    GarbledGate(GarbledGate),

    /// Output decoding information.
    OutputCiphertext(OutputCiphertext),

    /// End synchronization mode.
    ///
    /// For large computations, the Evaluator postman can get far ahead of the threads,
    /// and we don't want it to receive non-sync messages.
    EndSync,
}

impl Message {
    pub fn to_u128s(self) -> Vec<u128> {
        match self {
            Message::GarblerInput(w) => vec![w.as_u128()],
            Message::EvaluatorInput(w) => vec![w.as_u128()],
            Message::Constant { wire, .. } => vec![wire.as_u128()],
            Message::GarbledGate(gate) => gate,
            Message::OutputCiphertext(ct) => ct,
            _ => panic!("[Message::to_bytes] message type not allowed"),
        }
    }
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
            Message::EndSync => "EndSync",
        })
    }
}

////////////////////////////////////////////////////////////////////////////////
// utils used by both garbler and evaluator

struct SyncInfo {
    starting_gate_id: usize,
    index_done: Vec<AtomicBool>,
    id_for_index: Vec<AtomicUsize>,
}

impl SyncInfo {
    fn new(starting_gate_id: usize, nindices: SyncIndex) -> SyncInfo {
        SyncInfo {
            starting_gate_id,
            index_done: (0..nindices).map(|_| AtomicBool::new(false)).collect_vec(),
            id_for_index: (0..nindices).map(|_| AtomicUsize::new(0)).collect_vec(),
        }
    }
}

/// The current non-free gate index of the garbling computation. Respects sync
/// ordering. This needs to be exactly the same in both Garbler and Evaluator
/// since it feeds into the tweaks used to encrypt garbled gates.
fn compute_gate_id(
    current_gate: &AtomicUsize,
    sync_index: Option<SyncIndex>,
    sync_info: &Option<SyncInfo>,
) -> usize {
    if let Some(ref info) = *sync_info {
        let ix = sync_index.expect("compute_gate_id: syncronization requires a sync index");

        // get id and bump the count
        let id = info.id_for_index[ix as usize].fetch_add(1, Ordering::SeqCst);

        // compute the sync id
        // 32 bits for gate index, 32 for id
        assert!((info.starting_gate_id + ix as usize) >> 32 == 0);
        assert!(id >> 32 == 0);
        info.starting_gate_id + ix as usize + (id << 32)
    } else {
        current_gate.fetch_add(1, Ordering::SeqCst)
    }
}

////////////////////////////////////////////////////////////////////////////////
// general user-facing garbling functions

/// Create an iterator over the messages produced by fancy garbling.
///
/// This creates a new thread for the garbler, which passes messages back through a
/// channel one by one. This function has a restrictive input type because
/// `fancy_computation` is sent to the new thread.
pub fn garble_iter<F>(mut fancy_computation: F) -> impl Iterator<Item = Message>
where
    F: FnMut(&Garbler) + Send + 'static,
{
    let (sender, receiver) = std::sync::mpsc::sync_channel(20);

    std::thread::spawn(move || {
        let send_func = move |_ix, m| {
            sender
                .send(m)
                .expect("garble_iter thread could not send message to iterator")
        };
        let mut garbler = Garbler::new(send_func);
        fancy_computation(&mut garbler);
    });

    receiver.into_iter()
}

/// Garble a circuit without streaming.
pub fn garble(c: &Circuit) -> Result<(Encoder, Decoder, GarbledCircuit), GarblerError> {
    let garbler_inputs = Arc::new(Mutex::new(Vec::new()));
    let evaluator_inputs = Arc::new(Mutex::new(Vec::new()));
    let garbled_gates = Arc::new(Mutex::new(Vec::new()));
    let constants = Arc::new(Mutex::new(HashMap::new()));
    let garbled_outputs = Arc::new(Mutex::new(Vec::new()));

    let send_func;
    {
        let garbler_inputs = garbler_inputs.clone();
        let evaluator_inputs = evaluator_inputs.clone();
        let garbled_gates = garbled_gates.clone();
        let constants = constants.clone();
        let garbled_outputs = garbled_outputs.clone();
        send_func = move |_ix, m| match m {
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
            m => panic!("unexpected message: {}", m),
        };
    }

    let garbler = Garbler::new(send_func);
    let outputs = c.eval(&garbler)?;
    c.process_outputs(&outputs, &garbler)?;
    let deltas = garbler.get_deltas();

    let en = Encoder::new(
        Arc::try_unwrap(garbler_inputs)
            .unwrap()
            .into_inner()
            .unwrap(),
        Arc::try_unwrap(evaluator_inputs)
            .unwrap()
            .into_inner()
            .unwrap(),
        deltas,
    );

    let ev = GarbledCircuit::new(
        Arc::try_unwrap(garbled_gates)
            .unwrap()
            .into_inner()
            .unwrap(),
        Arc::try_unwrap(constants).unwrap().into_inner().unwrap(),
    );

    let de = Decoder::new(
        Arc::try_unwrap(garbled_outputs)
            .unwrap()
            .into_inner()
            .unwrap(),
    );

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
    use itertools::Itertools;
    use rand::thread_rng;

    // helper {{{
    fn garble_test_helper<F>(f: F)
    where
        F: Fn(u16) -> Circuit,
    {
        let mut rng = thread_rng();
        for _ in 0..16 {
            let q = rng.gen_prime();
            let c = &f(q);
            let (en, de, ev) = garble(c).unwrap();
            println!("number of ciphertexts for mod {}: {}", q, ev.size());
            for _ in 0..16 {
                let inps = (0..c.num_evaluator_inputs())
                    .map(|i| rng.gen_u16() % c.evaluator_input_mod(i))
                    .collect_vec();
                let xs = &en.encode_evaluator_inputs(&inps);
                let ys = &ev.eval(c, &[], xs).unwrap();
                let decoded = de.decode(ys)[0];
                let dummy = Dummy::new(&[], &inps);
                let outputs = c.eval(&dummy).unwrap();
                c.process_outputs(&outputs, &dummy).unwrap();
                let should_be = dummy.get_output()[0];
                if decoded != should_be {
                    println!(
                        "inp={:?} q={} got={} should_be={}",
                        inps, q, decoded, should_be
                    );
                    panic!("failed test!");
                }
            }
        }
    }
    //}}}
    #[test] // add {{{
    fn add() {
        garble_test_helper(|q| {
            let b = CircuitBuilder::new();
            let x = b.evaluator_input(None, q).unwrap();
            let y = b.evaluator_input(None, q).unwrap();
            let z = b.add(&x, &y).unwrap();
            b.output(None, &z).unwrap();
            b.finish()
        });
    }
    //}}}
    #[test] // add_many {{{
    fn add_many() {
        garble_test_helper(|q| {
            let b = CircuitBuilder::new();
            let xs = b.evaluator_inputs(None, &vec![q; 16]).unwrap();
            let z = b.add_many(&xs).unwrap();
            b.output(None, &z).unwrap();
            b.finish()
        });
    }
    //}}}
    #[test] // or_many {{{
    fn or_many() {
        garble_test_helper(|_| {
            let b = CircuitBuilder::new();
            let xs = b.evaluator_inputs(None, &vec![2; 16]).unwrap();
            let z = b.or_many(None, &xs).unwrap();
            b.output(None, &z).unwrap();
            b.finish()
        });
    }
    //}}}
    #[test] // sub {{{
    fn sub() {
        garble_test_helper(|q| {
            let b = CircuitBuilder::new();
            let x = b.evaluator_input(None, q).unwrap();
            let y = b.evaluator_input(None, q).unwrap();
            let z = b.sub(&x, &y).unwrap();
            b.output(None, &z).unwrap();
            b.finish()
        });
    }
    //}}}
    #[test] // cmul {{{
    fn cmul() {
        garble_test_helper(|q| {
            let b = CircuitBuilder::new();
            let x = b.evaluator_input(None, q).unwrap();
            let _ = b.evaluator_input(None, q).unwrap();
            let z;
            if q > 2 {
                z = b.cmul(&x, 2).unwrap();
            } else {
                z = b.cmul(&x, 1).unwrap();
            }
            b.output(None, &z).unwrap();
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
            let b = CircuitBuilder::new();
            let x = b.evaluator_input(None, q).unwrap();
            let _ = b.evaluator_input(None, q).unwrap();
            let z = b.proj(None, &x, q, Some(tab)).unwrap();
            b.output(None, &z).unwrap();
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
            let b = CircuitBuilder::new();
            let x = b.evaluator_input(None, q).unwrap();
            let _ = b.evaluator_input(None, q).unwrap();
            let z = b.proj(None, &x, q, Some(tab)).unwrap();
            b.output(None, &z).unwrap();
            b.finish()
        });
    }
    //}}}
    #[test] // mod_change {{{
    fn mod_change() {
        garble_test_helper(|q| {
            let b = CircuitBuilder::new();
            let x = b.evaluator_input(None, q).unwrap();
            let z = b.mod_change(None, &x, q * 2).unwrap();
            b.output(None, &z).unwrap();
            b.finish()
        });
    }
    //}}}
    #[test] // half_gate {{{
    fn half_gate() {
        garble_test_helper(|q| {
            let b = CircuitBuilder::new();
            let x = b.evaluator_input(None, q).unwrap();
            let y = b.evaluator_input(None, q).unwrap();
            let z = b.mul(None, &x, &y).unwrap();
            b.output(None, &z).unwrap();
            b.finish()
        });
    }
    //}}}
    #[test] // half_gate_unequal_mods {{{
    fn half_gate_unequal_mods() {
        for q in 3..16 {
            let ymod = 2 + thread_rng().gen_u16() % 6; // lower mod is capped at 8 for now
            println!("\nTESTING MOD q={} ymod={}", q, ymod);

            let b = CircuitBuilder::new();
            let x = b.evaluator_input(None, q).unwrap();
            let y = b.evaluator_input(None, ymod).unwrap();
            let z = b.mul(None, &x, &y).unwrap();
            b.output(None, &z).unwrap();
            let c = b.finish();

            let (en, de, ev) = garble(&c).unwrap();

            let mut fail = false;
            for x in 0..q {
                for y in 0..ymod {
                    println!("TEST x={} y={}", x, y);
                    let xs = &en.encode_evaluator_inputs(&[x, y]);
                    let ys = &ev.eval(&c, &[], xs).unwrap();
                    let decoded = de.decode(ys)[0];
                    let dummy = Dummy::new(&[], &[x, y]);
                    let outputs = c.eval(&dummy).unwrap();
                    c.process_outputs(&outputs, &dummy).unwrap();
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

        let b = CircuitBuilder::new();
        let xs = b.evaluator_input_bundles(None, &mods, nargs).unwrap();
        let z = b.mixed_radix_addition(None, &xs).unwrap();
        b.output_bundle(None, &z).unwrap();
        let circ = b.finish();

        let (en, de, ev) = garble(&circ).unwrap();
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
            let Y = ev.eval(&circ, &[], &X).unwrap();
            let res = de.decode(&Y);
            assert_eq!(util::from_mixed_radix(&res, &mods), should_be);
        }
    }
    //}}}
    #[test] // basic constants {{{
    fn basic_constant() {
        let b = CircuitBuilder::new();
        let mut rng = thread_rng();

        let q = rng.gen_modulus();
        let c = rng.gen_u16() % q;

        let y = b.constant(None, c, q).unwrap();
        b.output(None, &y).unwrap();

        let circ = b.finish();
        let (_, de, ev) = garble(&circ).unwrap();

        for _ in 0..64 {
            let dummy = Dummy::new(&[], &[]);
            let outputs = circ.eval(&dummy).unwrap();
            circ.process_outputs(&outputs, &dummy).unwrap();
            assert_eq!(dummy.get_output()[0], c, "plaintext eval failed");
            let Y = ev.eval(&circ, &[], &[]).unwrap();
            assert_eq!(de.decode(&Y)[0], c, "garbled eval failed");
        }
    }
    //}}}
    #[test] // constants {{{
    fn constants() {
        let b = CircuitBuilder::new();
        let mut rng = thread_rng();

        let q = rng.gen_modulus();
        let c = rng.gen_u16() % q;

        let x = b.evaluator_input(None, q).unwrap();
        let y = b.constant(None, c, q).unwrap();
        let z = b.add(&x, &y).unwrap();
        b.output(None, &z).unwrap();

        let circ = b.finish();
        let (en, de, ev) = garble(&circ).unwrap();

        for _ in 0..64 {
            let x = rng.gen_u16() % q;
            let dummy = Dummy::new(&[], &[x]);
            let outputs = circ.eval(&dummy).unwrap();
            circ.process_outputs(&outputs, &dummy).unwrap();
            assert_eq!(dummy.get_output()[0], (x + c) % q, "plaintext");

            let X = en.encode_evaluator_inputs(&[x]);
            let Y = ev.eval(&circ, &[], &X).unwrap();
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
    use itertools::Itertools;
    use rand::thread_rng;
    use std::fmt::{Debug, Display};

    // helper {{{
    fn streaming_test<F, G>(
        mut f_gb: F,
        mut f_ev: G,
        gb_inp: &[u16],
        ev_inp: &[u16],
        should_be: &[u16],
    ) where
        F: FnMut(&Garbler) + Send + Copy + 'static,
        G: FnMut(&Evaluator) + Send + Copy + 'static,
    {
        let mut gb_iter = garble_iter(move |gb| f_gb(gb));

        let mut gb_inp_iter = gb_inp.to_vec().into_iter();
        let mut ev_inp_iter = ev_inp.to_vec().into_iter();

        // the evaluator's recv_function gets the next message from the garble iterator,
        // encodes the appropriate inputs, and sends it along
        let recv_func = move || {
            let m = match gb_iter.next().unwrap() {
                Message::UnencodedGarblerInput { zero, delta } => {
                    // Encode the garbler's next input
                    let x = gb_inp_iter.next().expect("not enough garbler inputs!");
                    Message::GarblerInput(zero.plus(&delta.cmul(x)))
                }

                Message::UnencodedEvaluatorInput { zero, delta } => {
                    // Encode the garbler's next input
                    let x = ev_inp_iter.next().expect("not enough evaluator inputs!");
                    Message::EvaluatorInput(zero.plus(&delta.cmul(x)))
                }
                m => m,
            };
            (None, m)
        };

        let mut ev = Evaluator::new(recv_func);
        f_ev(&mut ev);

        let result = ev.decode_output();
        println!("gb_inp={:?} ev_inp={:?}", gb_inp, ev_inp);
        assert_eq!(result, should_be)
    }
    //}}}
    fn fancy_addition<W: Clone + HasModulus, E: Display + Debug>(
        b: &dyn Fancy<Item = W, Error = E>,
        q: u16,
    ) //{{{
    {
        let x = b.garbler_input(None, q, None).unwrap();
        let y = b.evaluator_input(None, q).unwrap();
        let z = b.add(&x, &y).unwrap();
        b.output(None, &z).unwrap();
    }

    #[test]
    fn addition() {
        let mut rng = thread_rng();
        for _ in 0..16 {
            let q = rng.gen_modulus();
            let x = rng.gen_u16() % q;
            let y = rng.gen_u16() % q;
            streaming_test(
                move |b| fancy_addition(b, q),
                move |b| fancy_addition(b, q),
                &[x],
                &[y],
                &[(x + y) % q],
            );
        }
    }
    //}}}
    fn fancy_subtraction<W: Clone + HasModulus, E: Display + Debug>(
        b: &dyn Fancy<Item = W, Error = E>,
        q: u16,
    ) //{{{
    {
        let x = b.garbler_input(None, q, None).unwrap();
        let y = b.evaluator_input(None, q).unwrap();
        let z = b.sub(&x, &y).unwrap();
        b.output(None, &z).unwrap();
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
    fn fancy_multiplication<W: Clone + HasModulus, E: Debug + Display>(
        b: &dyn Fancy<Item = W, Error = E>,
        q: u16,
    ) // {{{
    {
        let x = b.garbler_input(None, q, None).unwrap();
        let y = b.evaluator_input(None, q).unwrap();
        let z = b.mul(None, &x, &y).unwrap();
        b.output(None, &z).unwrap();
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
    fn fancy_cmul<W: Clone + HasModulus, E: Debug + Display>(
        b: &dyn Fancy<Item = W, Error = E>,
        q: u16,
    ) // {{{
    {
        let x = b.garbler_input(None, q, None).unwrap();
        let z = b.cmul(&x, 5).unwrap();
        b.output(None, &z).unwrap();
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
    fn fancy_projection<W: Clone + HasModulus, E: Debug + Display>(
        b: &dyn Fancy<Item = W, Error = E>,
        q: u16,
    ) // {{{
    {
        let x = b.garbler_input(None, q, None).unwrap();
        let tab = (0..q).map(|i| (i + 1) % q).collect_vec();
        let z = b.proj(None, &x, q, Some(tab)).unwrap();
        b.output(None, &z).unwrap();
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
mod parallel {
    use super::*;
    use crate::dummy::Dummy;
    use crate::fancy::Fancy;
    use crate::fancy::{BundleGadgets, SyncIndex};
    use crate::util::RngExt;
    use itertools::Itertools;
    use rand::thread_rng;

    fn parallel_gadgets<F, W>(b: &F, Q: u128, N: SyncIndex, par: bool)
    // {{{
    where
        W: Clone + HasModulus + Send + Sync + std::fmt::Debug,
        F: Fancy<Item = W> + Send + Sync,
    {
        if par {
            crossbeam::scope(|scope| {
                b.begin_sync(N).unwrap();
                let hs = (0..N)
                    .map(|i| {
                        scope
                            .builder()
                            .name(format!("Thread {}", i))
                            .spawn(move |_| {
                                // let x = b.garbler_input(Some(i), 2 + i as u16);
                                // let c = b.constant(Some(i), 1, 2 + i as u16);
                                // let z = b.mul(Some(i), &x, &c);
                                let c = b.constant_bundle_crt(Some(i), 1, Q).unwrap();
                                let x = b.garbler_input_bundle_crt(Some(i), Q, None).unwrap();
                                let x = b.mul_bundles(Some(i), &x, &c).unwrap();
                                let z = b.relu(Some(i), &x, "100%", None).unwrap();
                                b.finish_index(i).unwrap();
                                z
                            })
                            .unwrap()
                    })
                    .collect_vec();
                let outs = hs.into_iter().map(|h| h.join().unwrap()).collect_vec();
                b.output_bundles(None, &outs).unwrap();
                // b.outputs(None, &outs);
            })
            .unwrap()
        } else {
            b.begin_sync(N).unwrap();
            let mut zs = Vec::new();
            for i in 0..N {
                // let x = b.garbler_input(Some(i), 2 + i as u16);
                // let c = b.constant(Some(i), 1, 2 + i as u16);
                // let z = b.mul(Some(i), &x, &c);
                let c = b.constant_bundle_crt(Some(i), 1, Q).unwrap();
                let x = b.garbler_input_bundle_crt(Some(i), Q, None).unwrap();
                let x = b.mul_bundles(Some(i), &x, &c).unwrap();
                let z = b.relu(Some(i), &x, "100%", None).unwrap();
                zs.push(z);
                b.finish_index(i).unwrap();
            }
            b.output_bundles(None, &zs).unwrap();
            // b.outputs(None, &zs);
        }
    }

    #[test]
    fn parallel_garbling() {
        let mut rng = thread_rng();
        let N = 10;
        let Q = crate::util::modulus_with_width(10);
        for _ in 0..16 {
            let mut input = (0..N)
                .map(|_| crate::util::crt_factor(rng.gen_u128() % Q, Q))
                .collect_vec();

            // compute the correct answer using Dummy
            let dummy_input = input.iter().flatten().cloned().collect_vec();
            let dummy = Dummy::new(&dummy_input, &[]);
            parallel_gadgets(&dummy, Q, N, true);
            let should_be_par = dummy.get_output();

            // check serial version agrees with parallel
            let dummy = Dummy::new(&dummy_input, &[]);
            parallel_gadgets(&dummy, Q, N, false);
            let should_be = dummy.get_output();

            assert_eq!(should_be, should_be_par);

            // set up garbler and evaluator
            let (tx, rx) = std::sync::mpsc::channel();

            let tx = tx.clone();
            let send_func = move |ix: Option<SyncIndex>, m| {
                let m = match m {
                    Message::UnencodedGarblerInput { zero, delta } => {
                        let x = input[ix.unwrap() as usize].remove(0);
                        let w = zero.plus(&delta.cmul(x));
                        Message::GarblerInput(w)
                    }
                    _ => m,
                };
                tx.send((ix, m)).unwrap();
            };

            // put garbler on another thread
            std::thread::spawn(move || {
                let garbler = Garbler::new(send_func);
                parallel_gadgets(&garbler, Q, N, true);
            });

            // run the evaluator on this one
            let evaluator = Evaluator::new(move || rx.recv().unwrap());
            parallel_gadgets(&evaluator, Q, N, false);

            let result = evaluator.decode_output();
            assert_eq!(result, should_be);
        }
    } // }}}
}
