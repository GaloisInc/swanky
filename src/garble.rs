//! Structs and functions for creating, streaming, and evaluating garbled circuits.

use crate::wire::Wire;
use serde::{Deserialize, Serialize};

mod evaluator;
mod garbler;

pub use crate::garble::evaluator::Evaluator;
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
}

impl std::fmt::Display for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(match self {
            Message::UnencodedGarblerInput { .. } => "UnencodedGarblerInput",
            Message::UnencodedEvaluatorInput { .. } => "UnencodedEvaluatorInput",
        })
    }
}

////////////////////////////////////////////////////////////////////////////////
// tests

#[cfg(test)]
mod classic {
    use crate::circuit::{Circuit, CircuitBuilder};
    use crate::dummy::Dummy;
    use crate::fancy::{BundleGadgets, Fancy};
    use crate::r#static::garble;
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
            let mut c = &mut f(q);
            let (en, ev) = garble(&mut c).unwrap();
            for _ in 0..16 {
                let inps = (0..c.num_evaluator_inputs())
                    .map(|i| rng.gen_u16() % c.evaluator_input_mod(i))
                    .collect::<Vec<u16>>();
                // Run the garbled circuit evaluator.
                let xs = &en.encode_evaluator_inputs(&inps);
                let decoded = &ev.eval(&mut c, &[], xs).unwrap();
                // Run the dummy evaluator.
                let mut dummy = Dummy::new(&[], &inps);
                let outputs = c.eval(&mut dummy).unwrap();
                c.process_outputs(&outputs, &mut dummy).unwrap();
                let should_be = dummy.get_output();
                assert_eq!(decoded[0], should_be[0]);
            }
        }
    }
    //}}}
    #[test] // add {{{
    fn add() {
        garble_test_helper(|q| {
            let mut b = CircuitBuilder::new();
            let (_, xs) = b.init(&[], &[q, q], &[]).unwrap();
            let z = b.add(&xs[0], &xs[1]).unwrap();
            b.output(&z).unwrap();
            b.finish()
        });
    }
    //}}}
    #[test] // add_many {{{
    fn add_many() {
        garble_test_helper(|q| {
            let mut b = CircuitBuilder::new();
            let (_, xs) = b
                .init(&[], &itertools::repeat_n(q, 16).collect_vec(), &[])
                .unwrap();
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
            let (_, xs) = b
                .init(&[], &itertools::repeat_n(2, 16).collect_vec(), &[])
                .unwrap();
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
            let (_, xs) = b.init(&[], &[q, q], &[]).unwrap();
            let z = b.sub(&xs[0], &xs[1]).unwrap();
            b.output(&z).unwrap();
            b.finish()
        });
    }
    //}}}
    #[test] // cmul {{{
    fn cmul() {
        garble_test_helper(|q| {
            let mut b = CircuitBuilder::new();
            let (_, xs) = b.init(&[], &[q], &[]).unwrap();
            let z;
            if q > 2 {
                z = b.cmul(&xs[0], 2).unwrap();
            } else {
                z = b.cmul(&xs[0], 1).unwrap();
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
            let (_, xs) = b.init(&[], &[q], &[]).unwrap();
            let z = b.proj(&xs[0], q, Some(tab)).unwrap();
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
            let (_, xs) = b.init(&[], &[q], &[]).unwrap();
            let z = b.proj(&xs[0], q, Some(tab)).unwrap();
            b.output(&z).unwrap();
            b.finish()
        });
    }
    //}}}
    #[test] // mod_change {{{
    fn mod_change() {
        garble_test_helper(|q| {
            let mut b = CircuitBuilder::new();
            let (_, xs) = b.init(&[], &[q], &[]).unwrap();
            let z = b.mod_change(&xs[0], q * 2).unwrap();
            b.output(&z).unwrap();
            b.finish()
        });
    }
    //}}}
    #[test] // half_gate {{{
    fn half_gate() {
        garble_test_helper(|q| {
            let mut b = CircuitBuilder::new();
            let (_, xs) = b.init(&[], &[q, q], &[]).unwrap();
            let z = b.mul(&xs[0], &xs[1]).unwrap();
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
            let (_, xs) = b.init(&[], &[q, ymod], &[]).unwrap();
            let z = b.mul(&xs[0], &xs[1]).unwrap();
            b.output(&z).unwrap();
            let mut c = b.finish();

            let (en, ev) = garble(&mut c).unwrap();

            for x in 0..q {
                for y in 0..ymod {
                    println!("TEST x={} y={}", x, y);
                    let xs = &en.encode_evaluator_inputs(&[x, y]);
                    let decoded = &ev.eval(&mut c, &[], xs).unwrap();
                    let mut dummy = Dummy::new(&[], &[x, y]);
                    let outputs = c.eval(&mut dummy).unwrap();
                    c.process_outputs(&outputs, &mut dummy).unwrap();
                    let should_be = dummy.get_output();
                    assert_eq!(decoded[0], should_be[0]);
                }
            }
        }
    }
    //}}}
    #[test] // mixed_radix_addition {{{
    fn mixed_radix_addition() {
        let mut rng = thread_rng();

        let nargs = 2 + rng.gen_usize() % 100;
        // let mods = (0..7).map(|_| rng.gen_modulus()).collect_vec(); // slow
        let mods = vec![3, 7, 10, 2, 13]; // fast

        let mut b = CircuitBuilder::new();
        let (_, xs) = b
            .init_bundles(&[], &itertools::repeat_n(mods.clone(), nargs).collect_vec(), &[])
            .unwrap();
        let z = b.mixed_radix_addition(&xs).unwrap();
        b.output_bundle(&z).unwrap();
        let mut circ = b.finish();

        let (en, ev) = garble(&mut circ).unwrap();
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
            let outputs = ev.eval(&mut circ, &[], &X).unwrap();
            assert_eq!(util::from_mixed_radix(&outputs, &mods), should_be);
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
        let (_, ev) = garble(&mut circ).unwrap();

        for _ in 0..64 {
            let mut dummy = Dummy::new(&[], &[]);
            let outputs = circ.eval(&mut dummy).unwrap();
            circ.process_outputs(&outputs, &mut dummy).unwrap();
            assert_eq!(dummy.get_output()[0], c, "plaintext eval failed");
            let outputs = ev.eval(&mut circ, &[], &[]).unwrap();
            assert_eq!(outputs[0], c, "garbled eval failed");
        }
    }
    //}}}
    #[test] // constants {{{
    fn constants() {
        let mut b = CircuitBuilder::new();
        let mut rng = thread_rng();

        let q = rng.gen_modulus();
        let c = rng.gen_u16() % q;

        let (_, xs) = b.init(&[], &[q], &[]).unwrap();
        let y = b.constant(c, q).unwrap();
        let z = b.add(&xs[0], &y).unwrap();
        b.output(&z).unwrap();

        let mut circ = b.finish();
        let (en, ev) = garble(&mut circ).unwrap();

        for _ in 0..64 {
            let x = rng.gen_u16() % q;
            let mut dummy = Dummy::new(&[], &[x]);
            let outputs = circ.eval(&mut dummy).unwrap();
            circ.process_outputs(&outputs, &mut dummy).unwrap();
            assert_eq!(dummy.get_output()[0], (x + c) % q, "plaintext");

            let X = en.encode_evaluator_inputs(&[x]);
            let Y = ev.eval(&mut circ, &[], &X).unwrap();
            assert_eq!(Y[0], (x + c) % q, "garbled");
        }
    }
    //}}}
}

#[cfg(test)]
mod streaming {
    use crate::util::RngExt;
    use crate::FancyError;
    use crate::Message;
    use crate::{Evaluator, Garbler};
    use crate::{Fancy, HasModulus};
    use itertools::Itertools;
    use rand::thread_rng;
    use scuttlebutt::AesRng;
    use std::cell::RefCell;
    use std::fmt::{Debug, Display};
    use std::os::unix::net::UnixStream;
    use std::rc::Rc;

    type Reader = UnixStream;
    type Writer = UnixStream;

    // helper
    fn streaming_test<F, G>(
        mut f_gb: F,
        mut f_ev: G,
        gb_inp: &[u16],
        ev_inp: &[u16],
        should_be: &[u16],
    ) where
        F: FnMut(&mut Garbler<Writer, AesRng>) + Send + Sync + Copy + 'static,
        G: FnMut(&mut Evaluator<Reader>) + Send + Sync + Copy + 'static,
    {
        let rng = AesRng::new();
        let (sender, receiver) = UnixStream::pair().unwrap();

        let mut gb_inp_iter = gb_inp.to_vec().into_iter();
        let mut ev_inp_iter = ev_inp.to_vec().into_iter();

        std::thread::spawn(move || {
            let sender = Rc::new(RefCell::new(sender));
            let sender_ = sender.clone();
            let callback = move |m| {
                match m {
                    Message::UnencodedGarblerInput { zero, delta } => {
                        let x = gb_inp_iter.next().expect("not enough garbler inputs!");
                        let mut sender = sender_.borrow_mut();
                        zero.plus(&delta.cmul(x)).as_block().write(&mut *sender)?;
                    }
                    Message::UnencodedEvaluatorInput { zero, delta } => {
                        let x = ev_inp_iter.next().expect("not enough evaluator inputs!");
                        let mut sender = sender_.borrow_mut();
                        zero.plus(&delta.cmul(x)).as_block().write(&mut *sender)?;
                    }
                }
                Ok(())
            };
            let mut garbler = Garbler::new(sender, callback, rng);
            f_gb(&mut garbler);
        });

        let receiver = Rc::new(RefCell::new(receiver));
        let mut ev = Evaluator::new(receiver);
        f_ev(&mut ev);

        let result = ev.decode_output().unwrap();
        assert_eq!(result, should_be)
    }

    fn fancy_addition<
        W: Clone + HasModulus,
        E: Display + Debug + From<FancyError>,
        F: Fancy<Item = W, Error = E>,
    >(
        b: &mut F,
        q: u16,
    ) {
        let (xs, ys) = b.init(&[q], &[q], &[]).unwrap();
        let z = b.add(&xs[0], &ys[0]).unwrap();
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

    fn fancy_subtraction<W: Clone + HasModulus, E: Display + Debug + From<FancyError>>(
        b: &mut Fancy<Item = W, Error = E>,
        q: u16,
    ) {
        let (xs, ys) = b.init(&[q], &[q], &[]).unwrap();
        let z = b.sub(&xs[0], &ys[0]).unwrap();
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

    fn fancy_multiplication<W: Clone + HasModulus, E: Debug + Display + From<FancyError>>(
        b: &mut Fancy<Item = W, Error = E>,
        q: u16,
    ) {
        let (xs, ys) = b.init(&[q], &[q], &[]).unwrap();
        let z = b.mul(&xs[0], &ys[0]).unwrap();
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

    fn fancy_cmul<W: Clone + HasModulus, E: Debug + Display + From<FancyError>>(
        b: &mut Fancy<Item = W, Error = E>,
        q: u16,
    ) {
        let (xs, _) = b.init(&[q], &[], &[]).unwrap();
        let z = b.cmul(&xs[0], 5).unwrap();
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

    fn fancy_projection<W: Clone + HasModulus, E: Debug + Display + From<FancyError>>(
        b: &mut Fancy<Item = W, Error = E>,
        q: u16,
    ) {
        let (xs, _) = b.init(&[q], &[], &[]).unwrap();
        let tab = (0..q).map(|i| (i + 1) % q).collect_vec();
        let z = b.proj(&xs[0], q, Some(tab)).unwrap();
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

}

#[cfg(test)]
mod complex {
    use crate::dummy::Dummy;
    use crate::error::GarblerError;
    use crate::util::RngExt;
    use crate::{CrtGadgets, Evaluator, Fancy, Garbler, HasModulus, Message};
    use rand::thread_rng;
    use scuttlebutt::AesRng;
    use std::cell::RefCell;
    use std::os::unix::net::UnixStream;
    use std::rc::Rc;

    fn complex_gadget<F, W>(b: &mut F, q: u128, n: usize)
    where
        W: Clone + HasModulus,
        F: Fancy<Item = W>,
    {
        let mut zs = Vec::with_capacity(n);
        for _ in 0..n {
            let c = b.crt_constant_bundle(1, q).unwrap();
            let (_, xs) = b.crt_init(&[], &[q], &[]).unwrap();
            let x = b.crt_mul(&xs[0], &c).unwrap();
            let z = b.crt_relu(&x, "100%", None).unwrap();
            zs.push(z);
        }
        b.crt_outputs(&zs).unwrap();
    }

    fn complex_gadget_<F, W>(b: &mut F, q: u128, n: usize)
    where
        W: Clone + HasModulus,
        F: Fancy<Item = W>,
    {
        let mut zs = Vec::with_capacity(n);
        for _ in 0..n {
            let c = b.crt_constant_bundle(1, q).unwrap();
            let (_, xs) = b.crt_init(&[], &[q], &[]).unwrap();
            let x = b.crt_mul(&xs[0], &c).unwrap();
            let z = b.crt_relu(&x, "100%", None).unwrap();
            zs.push(z);
        }
        b.crt_outputs(&zs).unwrap();
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

            let (sender, receiver) = UnixStream::pair().unwrap();
            let mut input_ = input.clone();
            std::thread::spawn(move || {
                let sender = Rc::new(RefCell::new(sender));
                let sender_ = sender.clone();
                let callback = move |m| {
                    match m {
                        Message::UnencodedGarblerInput { zero, delta } => {
                            let x = input_.remove(0);
                            let w = zero.plus(&delta.cmul(x));
                            let mut sender = sender_.borrow_mut();
                            w.as_block().write(&mut *sender)?;
                        }
                        m => {
                            return Err(GarblerError::MessageError(format!(
                                "invalid message {}",
                                m
                            )));
                        }
                    };
                    Ok(())
                };
                let rng = AesRng::new();
                let mut garbler = Garbler::new(sender, callback, rng);
                complex_gadget(&mut garbler, Q, N);
            });
            let receiver = Rc::new(RefCell::new(receiver));
            let mut evaluator = Evaluator::new(receiver);
            complex_gadget(&mut evaluator, Q, N);
            let result = evaluator.decode_output().unwrap();
            assert_eq!(result, should_be);

            let (sender, receiver) = UnixStream::pair().unwrap();
            let mut input_ = input.clone();
            std::thread::spawn(move || {
                let sender = Rc::new(RefCell::new(sender));
                let sender_ = sender.clone();
                let callback = move |m| {
                    match m {
                        Message::UnencodedEvaluatorInput { zero, delta } => {
                            let x = input_.remove(0);
                            let w = zero.plus(&delta.cmul(x));
                            let mut sender = sender_.borrow_mut();
                            w.as_block().write(&mut *sender)?;
                        }
                        m => {
                            return Err(GarblerError::MessageError(format!(
                                "invalid message {}",
                                m
                            )));
                        }
                    };
                    Ok(())
                };
                let rng = AesRng::new();
                let mut garbler = Garbler::new(sender, callback, rng);
                complex_gadget_(&mut garbler, Q, N);
            });
            let receiver = Rc::new(RefCell::new(receiver));
            let mut evaluator = Evaluator::new(receiver);
            complex_gadget_(&mut evaluator, Q, N);
            let result = evaluator.decode_output().unwrap();
            assert_eq!(result, should_be);
        }
    }
}

// testing reused wirelabels
#[cfg(test)]
mod reuse {
    use super::*;
    use crate::*;
    use itertools::Itertools;
    use rand::random;
    use scuttlebutt::AesRng;
    use std::cell::RefCell;
    use std::os::unix::net::UnixStream;
    use std::rc::Rc;

    #[test]
    fn reuse_wirelabels() {
        let n = 16;

        let mut should_be = Vec::new();
        let mut inps = Vec::new();
        let mut mods = Vec::new();

        for _ in 0..n {
            let q = 2 + random::<u16>() % 100;
            let x = random::<u16>() % q;
            inps.push(x);
            mods.push(q);
            should_be.push(x);
        }

        let (sender, receiver) = UnixStream::pair().unwrap();
        let receiver = Rc::new(RefCell::new(receiver));

        let mut inps_ = inps.clone();
        let mods_ = mods.clone();
        std::thread::spawn(move || {
            let sender = Rc::new(RefCell::new(sender));
            let sender_ = sender.clone();
            let mut gb1 = Garbler::new(sender.clone(), move |m| {
                match m {
                    Message::UnencodedGarblerInput { zero, delta } => {
                        let x = inps_.remove(0);
                        let w = zero.plus(&delta.cmul(x));
                        let mut sender = sender_.borrow_mut();
                        w.as_block().write(&mut *sender)?;
                        Ok(())
                    }
                    _ => unimplemented!(),
                }
            }, AesRng::new());

            // get the input wirelabels for the garbler
            let (xs, _) = gb1.init(&mods_, &[], &[]).unwrap();
            // also get deltas for those wires
            let ds = xs.iter().map(|w| gb1.delta(w.modulus())).collect_vec();

            let mut gb2 = Garbler::new(sender.clone(), |_| unreachable!(), AesRng::new());
            // initialize deltas from previous garbler
            gb2.init(&[], &[], &ds).unwrap();
            // output the input wires from the previous garbler
            gb2.outputs(&xs).unwrap();
        });

        let mut ev1 = Evaluator::new(receiver.clone());
        let (xs, _) = ev1.init(&mods, &[], &[]).unwrap();

        let mut ev2 = Evaluator::new(receiver.clone());
        ev2.outputs(&xs).unwrap();

        let result = ev2.decode_output().unwrap();
        assert_eq!(result, should_be);
    }
}
