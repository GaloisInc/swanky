//! Structs and functions for creating, streaming, and evaluating garbled circuits.

mod garbler;
mod evaluator;

pub use crate::garble::garbler::Garbler;
pub use crate::garble::evaluator::{Evaluator, Encoder, Decoder, GarbledCircuit};

use crate::circuit::{Circuit, Gate};
use crate::fancy::{Fancy, HasModulus};
use crate::wire::Wire;
use serde_derive::{Serialize, Deserialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use time::{Duration, PreciseTime};

/// The ciphertext created by a garbled gate.
pub type GarbledGate = Vec<u128>;

/// Ciphertext created by the garbler for output gates.
pub type OutputCiphertext = Vec<u128>;

/// The outputs that can be emitted by a Garbler and consumed by an Evaluator.
#[derive(Clone, Serialize, Deserialize, Debug)]
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
    UnencodedEvaluatorInput { zero: Wire, delta: Wire},

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
}

impl std::fmt::Display for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(match self {
            Message::UnencodedGarblerInput   {..} => "UnencodedGarblerInput",
            Message::UnencodedEvaluatorInput {..} => "UnencodedEvaluatorInput",
            Message::GarblerInput(_)              => "GarblerInput",
            Message::EvaluatorInput(_)            => "EvaluatorInput",
            Message::Constant {..}                => "Constant",
            Message::GarbledGate(_)               => "GarbledGate",
            Message::OutputCiphertext(_)          => "OutputCiphertext",
        })
    }
}

impl Message {
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("couldn't serialize Message")
    }

    pub fn from_bytes(bs: &[u8]) -> Result<Self, failure::Error> {
        bincode::deserialize(bs)
            .map_err(|_| failure::err_msg("error decoding Message from bytes"))
    }
}

/// Type of a gate, input to the Evaluator's recv function.
pub enum GateType {
    /// The Evaluator in 2PC needs to know to do OT for their own inputs. This as input to
    /// the recv function means the current gate is an evaluator input.
    EvaluatorInput { modulus: u16 },
    /// Some other kind of gate that does not require special OT.
    Other,
}

/// Create an iterator over the messages produced by fancy garbling.
///
/// This creates a new thread for the garbler, which passes messages back through a
/// channel one by one. This function has a restrictive input type because
/// `fancy_computation` is sent to the new thread.
pub fn garble_iter<F>(mut fancy_computation: F) -> impl Iterator<Item=Message>
  where F: FnMut(&Garbler) + Send + 'static
{
    let (sender, receiver) = std::sync::mpsc::sync_channel(20);

    std::thread::spawn(move || {
        let send_func = move |m| sender.send(m)
            .expect("garble_iter thread could not send message to iterator");
        let mut garbler = Garbler::new(send_func);
        fancy_computation(&mut garbler);
    });

    receiver.into_iter()
}

/// Garble a circuit without streaming.
pub fn garble(c: &Circuit) -> (Encoder, Decoder, GarbledCircuit) {
    let garbler_inputs   = Arc::new(Mutex::new(Vec::new()));
    let evaluator_inputs = Arc::new(Mutex::new(Vec::new()));
    let garbled_gates    = Arc::new(Mutex::new(Vec::new()));
    let constants        = Arc::new(Mutex::new(HashMap::new()));
    let garbled_outputs  = Arc::new(Mutex::new(Vec::new()));
    let deltas;

    let send_func;
    {
        let garbler_inputs   = garbler_inputs.clone();
        let evaluator_inputs = evaluator_inputs.clone();
        let garbled_gates    = garbled_gates.clone();
        let constants        = constants.clone();
        let garbled_outputs  = garbled_outputs.clone();
        send_func = move |m| {
            match m {
                Message::UnencodedGarblerInput   { zero, .. } => garbler_inputs.lock().unwrap().push(zero),
                Message::UnencodedEvaluatorInput { zero, .. } => evaluator_inputs.lock().unwrap().push(zero),
                Message::GarbledGate(w)      => garbled_gates.lock().unwrap().push(w),
                Message::OutputCiphertext(c) => garbled_outputs.lock().unwrap().push(c),
                Message::Constant { value, wire } => {
                    let q = wire.modulus();
                    constants.lock().unwrap().insert((value,q), wire);
                }
                m => panic!("unexpected message: {}", m),
            }
        };
    }

    {
        let garbler = Garbler::new(send_func);

        let mut wires = Vec::new();
        for (i, gate) in c.gates.iter().enumerate() {
            let q = c.modulus(i);
            let w = match gate {
                Gate::GarblerInput { .. }    => garbler.garbler_input(None, q),
                Gate::EvaluatorInput { .. }  => garbler.evaluator_input(None, q),
                Gate::Constant { val }       => garbler.constant(None, *val,q),
                Gate::Add { xref, yref }     => garbler.add(&wires[xref.ix], &wires[yref.ix]),
                Gate::Sub { xref, yref }     => garbler.sub(&wires[xref.ix], &wires[yref.ix]),
                Gate::Cmul { xref, c }       => garbler.cmul(&wires[xref.ix], *c),
                Gate::Mul { xref, yref, .. } => garbler.mul(None, &wires[xref.ix], &wires[yref.ix]),
                Gate::Proj { xref, tt, .. }  => garbler.proj(None, &wires[xref.ix], q, tt),
            };
            wires.push(w);
        }

        for r in c.output_refs.iter() {
            garbler.output(None, &wires[r.ix]);
        }

        deltas = garbler.get_deltas();
    }

    let en = Encoder::new(
        Arc::try_unwrap(garbler_inputs).unwrap().into_inner().unwrap(),
        Arc::try_unwrap(evaluator_inputs).unwrap().into_inner().unwrap(),
        deltas
    );

    let ev = GarbledCircuit::new(
        Arc::try_unwrap(garbled_gates).unwrap().into_inner().unwrap(),
        Arc::try_unwrap(constants).unwrap().into_inner().unwrap(),
    );

    let de = Decoder::new(
        Arc::try_unwrap(garbled_outputs).unwrap().into_inner().unwrap()
    );

    (en, de, ev)
}

////////////////////////////////////////////////////////////////////////////////
// benchmarking function

/// Run benchmark garbling and streaming on the function. Garbling function is evaluated
/// on another thread.
pub fn bench_garbling<GbF, EvF>(niters: usize, fancy_gb: GbF, fancy_ev: EvF)
  where GbF: Fn(&mut Garbler) + Send + Sync + 'static,
        EvF: Fn(&mut Evaluator)
{
    let fancy_gb = Arc::new(fancy_gb);

    let mut total_time = Duration::zero();

    println!("benchmarking garbler");
    let mut pb = pbr::ProgressBar::new(niters as u64);
    pb.message("test ");

    for _ in 0..niters {
        pb.inc();
        let mut garbler = Garbler::new(|_|());
        let start = PreciseTime::now();
        fancy_gb(&mut garbler);
        let end = PreciseTime::now();
        total_time = total_time + start.to(end);
    }
    pb.finish();

    total_time = total_time / niters as i32;
    println!("garbling took {} ms", total_time.num_milliseconds());

    // benchmark the garbler and the evaluator together
    println!("benchmarking garbler streaming to evaluator");
    let mut pb = pbr::ProgressBar::new(niters as u64);
    pb.message("test ");

    total_time = Duration::zero();
    for _ in 0..niters {
        pb.inc();
        // set up channel
        let (sender, receiver) = std::sync::mpsc::sync_channel(20);

        // start timer
        let start = PreciseTime::now();

        // compute garbler on another thread
        let fancy_gb = fancy_gb.clone();
        std::thread::spawn(move || {
            // set up garbler
            let callback = move |msg| {
                let m = match msg {
                    Message::UnencodedGarblerInput   { zero, .. } => Message::GarblerInput(zero),
                    Message::UnencodedEvaluatorInput { zero, .. } => Message::EvaluatorInput(zero),
                    m => m,
                };
                sender.send(m).expect("failed to send message");
            };
            // evaluate garbler
            let mut gb = Garbler::new(callback);
            fancy_gb(&mut gb);
        });

        // evaluate the evaluator
        let mut ev = Evaluator::new(move |_| receiver.recv().unwrap());
        fancy_ev(&mut ev);

        let end = PreciseTime::now();
        total_time = total_time + start.to(end);
    }
    pb.finish();

    total_time = total_time / niters as i32;
    println!("streaming took {} ms", total_time.num_milliseconds());
}

////////////////////////////////////////////////////////////////////////////////
// tests

#[cfg(test)]
mod classic {
    use super::*;
    use crate::circuit::{Circuit, CircuitBuilder};
    use crate::fancy::{Fancy, BundleGadgets};
    use crate::util::{self, RngExt};
    use itertools::Itertools;
    use rand::thread_rng;

    // helper {{{
    fn garble_test_helper<F>(f: F)
        where F: Fn(u16) -> Circuit
    {
        let mut rng = thread_rng();
        for _ in 0..16 {
            let q = rng.gen_prime();
            let c = &f(q);
            let (en, de, ev) = garble(c);
            println!("number of ciphertexts for mod {}: {}", q, ev.size());
            for _ in 0..16 {
                let inps = (0..c.num_evaluator_inputs()).map(|i| { rng.gen_u16() % c.evaluator_input_mod(i) }).collect_vec();
                let xs = &en.encode_evaluator_inputs(&inps);
                let ys = &ev.eval(c, &[], xs);
                let decoded = de.decode(ys)[0];
                let should_be = c.eval(&[], &inps)[0];
                if decoded != should_be {
                    println!("inp={:?} q={} got={} should_be={}", inps, q, decoded, should_be);
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
            let x = b.evaluator_input(None, q);
            let y = b.evaluator_input(None, q);
            let z = b.add(&x,&y);
            b.output(None, &z);
            b.finish()
        });
    }
//}}}
    #[test] // add_many {{{
    fn add_many() {
        garble_test_helper(|q| {
            let b = CircuitBuilder::new();
            let xs = b.evaluator_inputs(None, q, 16);
            let z = b.add_many(&xs);
            b.output(None, &z);
            b.finish()
        });
    }
//}}}
    #[test] // or_many {{{
    fn or_many() {
        garble_test_helper(|_| {
            let b = CircuitBuilder::new();
            let xs = b.evaluator_inputs(None, 2, 16);
            let z = b.or_many(None, &xs);
            b.output(None, &z);
            b.finish()
        });
    }
//}}}
    #[test] // sub {{{
    fn sub() {
        garble_test_helper(|q| {
            let b = CircuitBuilder::new();
            let x = b.evaluator_input(None, q);
            let y = b.evaluator_input(None, q);
            let z = b.sub(&x,&y);
            b.output(None, &z);
            b.finish()
        });
    }
//}}}
    #[test] // cmul {{{
    fn cmul() {
        garble_test_helper(|q| {
            let b = CircuitBuilder::new();
            let x = b.evaluator_input(None, q);
            let _ = b.evaluator_input(None, q);
            let z;
            if q > 2 {
                z = b.cmul(&x, 2);
            } else {
                z = b.cmul(&x, 1);
            }
            b.output(None, &z);
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
            let x = b.evaluator_input(None, q);
            let _ = b.evaluator_input(None, q);
            let z = b.proj(None, &x, q, &tab);
            b.output(None, &z);
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
            let x = b.evaluator_input(None, q);
            let _ = b.evaluator_input(None, q);
            let z = b.proj(None, &x, q, &tab);
            b.output(None, &z);
            b.finish()
        });
    }
//}}}
    #[test] // mod_change {{{
    fn mod_change() {
        garble_test_helper(|q| {
            let b = CircuitBuilder::new();
            let x = b.evaluator_input(None, q);
            let z = b.mod_change(None, &x, q*2);
            b.output(None, &z);
            b.finish()
        });
    }
//}}}
    #[test] // half_gate {{{
    fn half_gate() {
        garble_test_helper(|q| {
            let b = CircuitBuilder::new();
            let x = b.evaluator_input(None, q);
            let y = b.evaluator_input(None, q);
            let z = b.mul(None, &x, &y);
            b.output(None, &z);
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
            let x = b.evaluator_input(None, q);
            let y = b.evaluator_input(None, ymod);
            let z = b.mul(None, &x,&y);
            b.output(None, &z);
            let c = b.finish();

            let (en, de, ev) = garble(&c);

            let mut fail = false;
            for x in 0..q {
                for y in 0..ymod {
                    println!("TEST x={} y={}", x,y);
                    let xs = &en.encode_evaluator_inputs(&[x,y]);
                    let ys = &ev.eval(&c, &[], xs);
                    let decoded = de.decode(ys)[0];
                    let should_be = c.eval(&[], &[x,y])[0];
                    if decoded != should_be {
                        println!("FAILED inp={:?} q={} got={} should_be={}", [x,y], q, decoded, should_be);
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
        let mods = [3,7,10,2,13]; // fast

        let b = CircuitBuilder::new();
        let xs = b.evaluator_input_bundles(None, &mods, nargs);
        let z = b.mixed_radix_addition(None, &xs);
        b.output_bundle(None, &z);
        let circ = b.finish();

        let (en, de, ev) = garble(&circ);
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
            let Y = ev.eval(&circ, &[], &X);
            let res = de.decode(&Y);
            assert_eq!(util::from_mixed_radix(&res,&mods), should_be);
        }
    }
//}}}
    #[test] // basic constants {{{
    fn basic_constant() {
        let b = CircuitBuilder::new();
        let mut rng = thread_rng();

        let q = rng.gen_modulus();
        let c = rng.gen_u16() % q;

        let y = b.constant(None, c, q);
        b.output(None, &y);

        let circ = b.finish();
        let (_, de, ev) = garble(&circ);

        for _ in 0..64 {
            assert_eq!(circ.eval(&[],&[])[0], c, "plaintext eval failed");
            let Y = ev.eval(&circ, &[], &[]);
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

        let x = b.evaluator_input(None, q);
        let y = b.constant(None, c, q);
        let z = b.add(&x,&y);
        b.output(None, &z);

        let circ = b.finish();
        let (en, de, ev) = garble(&circ);

        for _ in 0..64 {
            let x = rng.gen_u16() % q;

            assert_eq!(circ.eval(&[],&[x])[0], (x+c)%q, "plaintext");

            let X = en.encode_evaluator_inputs(&[x]);
            let Y = ev.eval(&circ, &[], &X);
            assert_eq!(de.decode(&Y)[0], (x+c)%q, "garbled");
        }
    }
//}}}
    #[test] // serialization {{{
    fn serialization() {
        let mut rng = thread_rng();

        let nargs = 2 + rng.gen_usize() % 10;
        let mods = (0..7).map(|_| rng.gen_modulus()).collect_vec();

        let b = CircuitBuilder::new();
        let xs = b.evaluator_input_bundles(None, &mods, nargs);
        let z = b.mixed_radix_addition(None, &xs);
        b.output_bundle(None, &z);
        let circ = b.finish();

        let (en, de, ev) = garble(&circ);

        assert_eq!(ev, GarbledCircuit::from_bytes(&ev.to_bytes()).unwrap());
        assert_eq!(en, Encoder::from_bytes(&en.to_bytes()).unwrap());
        assert_eq!(de, Decoder::from_bytes(&de.to_bytes()).unwrap());
    }
//}}}
}

#[cfg(test)]
mod streaming {
    use super::*;
    use crate::util::RngExt;
    use rand::thread_rng;
    use itertools::Itertools;

    // helper {{{
    fn streaming_test<F>(mut f: F, gb_inp: &[u16], ev_inp: &[u16], should_be: &[u16])
      where F: FnMut(&dyn Fancy<Item=Wire>) + Send + Copy + 'static,
    {
        let mut gb_iter = garble_iter(move |gb| f(gb));

        let mut gb_inp_iter = gb_inp.to_vec().into_iter();
        let mut ev_inp_iter = ev_inp.to_vec().into_iter();

        // the evaluator's recv_function gets the next message from the garble iterator,
        // encodes the appropriate inputs, and sends it along
        let recv_func = move |_| {
            match gb_iter.next().unwrap() {
                Message::UnencodedGarblerInput { zero, delta } => {
                    // Encode the garbler's next input
                    let x = gb_inp_iter.next().expect("not enough garbler inputs!");
                    Message::GarblerInput( zero.plus(&delta.cmul(x)) )
                }

                Message::UnencodedEvaluatorInput { zero, delta } => {
                    // Encode the garbler's next input
                    let x = ev_inp_iter.next().expect("not enough evaluator inputs!");
                    Message::EvaluatorInput( zero.plus(&delta.cmul(x)) )
                }
                m => m,
            }
        };

        let mut ev = Evaluator::new(recv_func);
        f(&mut ev);

        let result = ev.decode_output();
        println!("gb_inp={:?} ev_inp={:?}", gb_inp, ev_inp);
        assert_eq!(result, should_be)
    }
//}}}
    fn fancy_addition<W: Clone + Default + HasModulus>(b: &dyn Fancy<Item=W>, q: u16) //{{{
    {
        let x = b.garbler_input(None, q);
        let y = b.evaluator_input(None, q);
        let z = b.add(&x,&y);
        b.output(None, &z);
    }

    #[test]
    fn addition() {
        let mut rng = thread_rng();
        for _ in 0..16 {
            let q = rng.gen_modulus();
            let x = rng.gen_u16() % q;
            let y = rng.gen_u16() % q;
            streaming_test(move |b| fancy_addition(b,q), &[x], &[y], &[(x+y)%q]);
        }
    }
//}}}
    fn fancy_subtraction<W: Clone + Default + HasModulus>(b: &dyn Fancy<Item=W>, q: u16) //{{{
    {
        let x = b.garbler_input(None, q);
        let y = b.evaluator_input(None, q);
        let z = b.sub(&x,&y);
        b.output(None, &z);
    }

    #[test]
    fn subtraction() {
        let mut rng = thread_rng();
        for _ in 0..16 {
            let q = rng.gen_modulus();
            let x = rng.gen_u16() % q;
            let y = rng.gen_u16() % q;
            streaming_test(move |b| fancy_subtraction(b,q), &[x], &[y], &[(q+x-y)%q]);
        }
    }
//}}}
    fn fancy_multiplication<W: Clone + Default + HasModulus>(b: &dyn Fancy<Item=W>, q: u16) // {{{
    {
        let x = b.garbler_input(None, q);
        let y = b.evaluator_input(None, q);
        let z = b.mul(None,&x,&y);
        b.output(None, &z);
    }

    #[test]
    fn multiplication() {
        let mut rng = thread_rng();
        for _ in 0..16 {
            let q = rng.gen_modulus();
            let x = rng.gen_u16() % q;
            let y = rng.gen_u16() % q;
            streaming_test(move |b| fancy_multiplication(b,q), &[x], &[y], &[(x*y)%q]);
        }
    }
//}}}
    fn fancy_cmul<W: Clone + Default + HasModulus>(b: &dyn Fancy<Item=W>, q: u16) // {{{
    {
        let x = b.garbler_input(None, q);
        let z = b.cmul(&x,5);
        b.output(None, &z);
    }

    #[test]
    fn cmul() {
        let mut rng = thread_rng();
        for _ in 0..16 {
            let q = rng.gen_modulus();
            let x = rng.gen_u16() % q;
            streaming_test(move |b|fancy_cmul(b,q), &[x], &[], &[(x*5)%q]);
        }
    }
//}}}
    fn fancy_projection<W: Clone + Default + HasModulus>(b: &dyn Fancy<Item=W>, q: u16) // {{{
    {
        let x = b.garbler_input(None, q);
        let tab = (0..q).map(|i| (i + 1) % q).collect_vec();
        let z = b.proj(None,&x,q,&tab);
        b.output(None,&z);
    }

    #[test]
    fn proj() {
        let mut rng = thread_rng();
        for _ in 0..16 {
            let q = rng.gen_modulus();
            let x = rng.gen_u16() % q;
            streaming_test(move |b|fancy_projection(b,q), &[x], &[], &[(x+1)%q]);
        }
    }
//}}}
}

#[cfg(test)]
mod parallel {
    use super::*;
    use itertools::Itertools;
    use crate::dummy::Dummy;
    use rand::thread_rng;
    use crate::util::RngExt;

    fn parallel_gadgets<F,W>(b: &F, N: usize, par: bool)
      where W: Clone + Default + HasModulus + Send + Sync + std::fmt::Debug,
            F: Fancy<Item=W> + Send + Sync,
     {
        let inps = (0..N).map(|i| {
            b.garbler_input(None, 2 + i as u16)
        }).collect_vec();

        if par {
            crossbeam::scope(|scope| {
                b.begin_sync(0,N);
                let hs = inps.iter().enumerate().map(|(i,inp)| {
                    scope.spawn(move |_| {
                        let c = b.constant(Some(i), 1, inp.modulus());
                        let m = b.mul(Some(i), inp, &c);
                        let x = b.mul(Some(i), &m, &c);
                        let z = b.mod_change(Some(i), &x, x.modulus() + 1);
                        b.finish_index(i);
                        z
                    })
                }).collect_vec();
                let outs = hs.into_iter().map(|h| h.join().unwrap()).collect_vec();
                b.outputs(None, &outs);
            }).unwrap()

        } else {
            b.begin_sync(0,N);
            let outs = inps.iter().enumerate().map(|(i,inp)| {
                let c = b.constant(Some(i), 1, inp.modulus());
                let m = b.mul(Some(i), inp, &c);
                let x = b.mul(Some(i), &m, &c);
                let z = b.mod_change(Some(i), &x, x.modulus() + 1);
                b.finish_index(i);
                z
            }).collect_vec();
            b.outputs(None, &outs);
        }
    }

    #[test]
    fn parallel_test() {
        let mut rng = thread_rng();
        let N = 10;
        for _ in 0..64 {
            let input = (0..N).map(|i| rng.gen_u16() % (2 + i as u16)).collect_vec();

            // compute the correct answer using Dummy (which cannot get out of sync)
            let dummy = Dummy::new(&input, &[]);
            parallel_gadgets(&dummy, N, true);
            let should_be_par = dummy.get_output();

            // check serial version agrees with parallel
            let dummy = Dummy::new(&input, &[]);
            parallel_gadgets(&dummy, N, false);
            let should_be = dummy.get_output();

            assert_eq!(should_be, should_be_par);

            // set up garbler and evaluator
            let (tx, rx) = std::sync::mpsc::channel();

            let mut input_iter = input.into_iter();
            let send_func = move |m| {
                let m = match m {
                    Message::UnencodedGarblerInput { zero, delta } => {
                        let x = input_iter.next().unwrap();
                        let w = zero.plus(&delta.cmul(x));
                        Message::GarblerInput(w)
                    }
                    _ => m,
                };
                tx.send(m).unwrap();
            };

            // put garbler on another thread
            std::thread::spawn(move || {
                let garbler = Garbler::new(send_func);
                parallel_gadgets(&garbler, N, true);
            });

            // run the evaluator on this one
            let evaluator = Evaluator::new(move |_| rx.recv().unwrap());
            parallel_gadgets(&evaluator, N, false);

            let result = evaluator.decode_output();
            assert_eq!(result, should_be);
        }
    }
}
