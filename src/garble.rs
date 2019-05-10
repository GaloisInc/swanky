//! Structs and functions for creating, streaming, and evaluating garbled circuits.

mod evaluator;
mod garbler;

pub use crate::garble::evaluator::Evaluator;
pub use crate::garble::garbler::Garbler;

////////////////////////////////////////////////////////////////////////////////
// tests

#[cfg(test)]
mod classic {
    use crate::circuit::{Circuit, CircuitBuilder};
    use crate::dummy::Dummy;
    use crate::dummy::DummyVal;
    use crate::fancy::{Bundle, BundleGadgets, Fancy};
    use crate::r#static::garble;
    use crate::util::{self, RngExt};
    use itertools::Itertools;
    use rand::thread_rng;

    // helper
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
                let mut inps = Vec::new();
                let mut dinps = Vec::new();
                for i in 0..c.num_evaluator_inputs() {
                    let q = c.evaluator_input_mod(i);
                    let x = rng.gen_u16() % q;
                    inps.push(x);
                    dinps.push(DummyVal::new(x, q));
                }
                // Run the garbled circuit evaluator.
                let xs = &en.encode_evaluator_inputs(&inps);
                let decoded = &ev.eval(&mut c, &[], xs).unwrap();
                // Run the dummy evaluator.
                let mut dummy = Dummy::new();
                let outputs = c.eval(&mut dummy, &[], &dinps).unwrap();
                c.process_outputs(&outputs, &mut dummy).unwrap();
                let should_be = dummy.get_output();
                assert_eq!(decoded[0], should_be[0]);
            }
        }
    }

    #[test] // add
    fn add() {
        garble_test_helper(|q| {
            let mut b = CircuitBuilder::new();
            let x = b.evaluator_input(q);
            let y = b.evaluator_input(q);
            let z = b.add(&x, &y).unwrap();
            b.output(&z).unwrap();
            b.finish()
        });
    }

    #[test] // add_many
    fn add_many() {
        garble_test_helper(|q| {
            let mut b = CircuitBuilder::new();
            let xs = b.evaluator_inputs(&vec![q; 16]);
            let z = b.add_many(&xs).unwrap();
            b.output(&z).unwrap();
            b.finish()
        });
    }

    #[test] // or_many
    fn or_many() {
        garble_test_helper(|_| {
            let mut b = CircuitBuilder::new();
            let xs = b.evaluator_inputs(&vec![2; 16]);
            let z = b.or_many(&xs).unwrap();
            b.output(&z).unwrap();
            b.finish()
        });
    }

    #[test] // sub
    fn sub() {
        garble_test_helper(|q| {
            let mut b = CircuitBuilder::new();
            let x = b.evaluator_input(q);
            let y = b.evaluator_input(q);
            let z = b.sub(&x, &y).unwrap();
            b.output(&z).unwrap();
            b.finish()
        });
    }

    #[test] // cmul
    fn cmul() {
        garble_test_helper(|q| {
            let mut b = CircuitBuilder::new();
            let x = b.evaluator_input(q);
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

    #[test] // proj_cycle
    fn proj_cycle() {
        garble_test_helper(|q| {
            let mut tab = Vec::new();
            for i in 0..q {
                tab.push((i + 1) % q);
            }
            let mut b = CircuitBuilder::new();
            let x = b.evaluator_input(q);
            let z = b.proj(&x, q, Some(tab)).unwrap();
            b.output(&z).unwrap();
            b.finish()
        });
    }

    #[test] // proj_rand
    fn proj_rand() {
        garble_test_helper(|q| {
            let mut rng = thread_rng();
            let mut tab = Vec::new();
            for _ in 0..q {
                tab.push(rng.gen_u16() % q);
            }
            let mut b = CircuitBuilder::new();
            let x = b.evaluator_input(q);
            let z = b.proj(&x, q, Some(tab)).unwrap();
            b.output(&z).unwrap();
            b.finish()
        });
    }

    #[test] // mod_change
    fn mod_change() {
        garble_test_helper(|q| {
            let mut b = CircuitBuilder::new();
            let x = b.evaluator_input(q);
            let z = b.mod_change(&x, q * 2).unwrap();
            b.output(&z).unwrap();
            b.finish()
        });
    }

    #[test] // half_gate
    fn half_gate() {
        garble_test_helper(|q| {
            let mut b = CircuitBuilder::new();
            let x = b.evaluator_input(q);
            let y = b.evaluator_input(q);
            let z = b.mul(&x, &y).unwrap();
            b.output(&z).unwrap();
            b.finish()
        });
    }

    #[test] // half_gate_unequal_mods
    fn half_gate_unequal_mods() {
        for q in 3..16 {
            let ymod = 2 + thread_rng().gen_u16() % 6; // lower mod is capped at 8 for now
            println!("\nTESTING MOD q={} ymod={}", q, ymod);

            let mut b = CircuitBuilder::new();
            let x = b.evaluator_input(q);
            let y = b.evaluator_input(ymod);
            let z = b.mul(&x, &y).unwrap();
            b.output(&z).unwrap();
            let mut c = b.finish();

            let (en, ev) = garble(&mut c).unwrap();

            for x in 0..q {
                for y in 0..ymod {
                    println!("TEST x={} y={}", x, y);
                    let xs = &en.encode_evaluator_inputs(&[x, y]);
                    let decoded = &ev.eval(&mut c, &[], xs).unwrap();
                    let mut dummy = Dummy::new();
                    let outputs = c
                        .eval(
                            &mut dummy,
                            &[],
                            &[DummyVal::new(x, q), DummyVal::new(y, ymod)],
                        )
                        .unwrap();
                    c.process_outputs(&outputs, &mut dummy).unwrap();
                    let should_be = dummy.get_output();
                    assert_eq!(decoded[0], should_be[0]);
                }
            }
        }
    }

    #[test] // mixed_radix_addition
    fn mixed_radix_addition() {
        let mut rng = thread_rng();

        let nargs = 2 + rng.gen_usize() % 100;
        let mods = vec![3, 7, 10, 2, 13];

        let mut b = CircuitBuilder::new();
        let xs = (0..nargs)
            .map(|_| Bundle::new(b.evaluator_inputs(&mods)))
            .collect_vec();
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

    #[test] // basic constants
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
            let mut dummy = Dummy::new();
            let outputs = circ.eval(&mut dummy, &[], &[]).unwrap();
            circ.process_outputs(&outputs, &mut dummy).unwrap();
            assert_eq!(dummy.get_output()[0], c, "plaintext eval failed");
            let outputs = ev.eval(&mut circ, &[], &[]).unwrap();
            assert_eq!(outputs[0], c, "garbled eval failed");
        }
    }

    #[test] // constants
    fn constants() {
        let mut b = CircuitBuilder::new();
        let mut rng = thread_rng();

        let q = rng.gen_modulus();
        let c = rng.gen_u16() % q;

        let x = b.evaluator_input(q);
        let y = b.constant(c, q).unwrap();
        let z = b.add(&x, &y).unwrap();
        b.output(&z).unwrap();

        let mut circ = b.finish();
        let (en, ev) = garble(&mut circ).unwrap();

        for _ in 0..64 {
            let x = rng.gen_u16() % q;
            let mut dummy = Dummy::new();
            let outputs = circ.eval(&mut dummy, &[], &[DummyVal::new(x, q)]).unwrap();
            circ.process_outputs(&outputs, &mut dummy).unwrap();
            assert_eq!(dummy.get_output()[0], (x + c) % q, "plaintext");

            let X = en.encode_evaluator_inputs(&[x]);
            let Y = ev.eval(&mut circ, &[], &X).unwrap();
            assert_eq!(Y[0], (x + c) % q, "garbled");
        }
    }

}

#[cfg(test)]
mod streaming {
    use crate::dummy::{Dummy, DummyVal};
    use crate::util::RngExt;
    use crate::Fancy;
    use crate::{Evaluator, Garbler, Wire};
    use itertools::Itertools;
    use rand::thread_rng;
    use scuttlebutt::AesRng;
    use std::cell::RefCell;
    use std::os::unix::net::UnixStream;
    use std::rc::Rc;

    // helper - checks that Streaming evaluation of a fancy function equals Dummy
    // evaluation of the same function
    fn streaming_test<FGB, FEV, FDU>(
        mut f_gb: FGB,
        mut f_ev: FEV,
        mut f_du: FDU,
        input_mods: &[u16],
    ) where
        FGB: FnMut(&mut Garbler<UnixStream, AesRng>, &[Wire]) + Send + Sync + Copy + 'static,
        FEV: FnMut(&mut Evaluator<UnixStream>, &[Wire]) + Send + Sync + Copy + 'static,
        FDU: FnMut(&mut Dummy, &[DummyVal]) + Send + Sync + Copy + 'static,
    {
        let mut rng = AesRng::new();

        let inputs = input_mods.iter().map(|q| rng.gen_u16() % q).collect_vec();

        // evaluate f_gb as a dummy
        let mut dummy = Dummy::new();
        let dinps = Dummy::encode_inputs(&inputs, input_mods).unwrap();
        f_du(&mut dummy, &dinps);
        let should_be = dummy.get_output();

        let (sender, receiver) = UnixStream::pair().unwrap();

        let input_mods_ = input_mods.to_vec();
        std::thread::spawn(move || {
            let sender = Rc::new(RefCell::new(sender));
            let mut gb = Garbler::new(sender, rng, &[]);
            let (gb_inp, ev_inp) = gb.encode_many(&inputs, &input_mods_);
            for w in ev_inp.iter() {
                gb.send_wire(w).unwrap();
            }
            f_gb(&mut gb, &gb_inp);
        });

        let receiver = Rc::new(RefCell::new(receiver));
        let mut ev = Evaluator::new(receiver);
        let ev_inp = input_mods
            .iter()
            .map(|q| ev.read_wire(*q).unwrap())
            .collect_vec();
        f_ev(&mut ev, &ev_inp);

        let result = ev.decode_output().unwrap();

        assert_eq!(result, should_be)
    }

    #[test]
    fn addition() {
        fn fancy_addition<F: Fancy>(b: &mut F, xs: &[F::Item]) {
            let z = b.add(&xs[0], &xs[1]).unwrap();
            b.output(&z).unwrap();
        }

        let mut rng = thread_rng();
        for _ in 0..16 {
            let q = rng.gen_modulus();
            streaming_test(
                move |b, xs| fancy_addition(b, xs),
                move |b, xs| fancy_addition(b, xs),
                move |b, xs| fancy_addition(b, xs),
                &[q, q],
            );
        }
    }

    #[test]
    fn subtraction() {
        fn fancy_subtraction<F: Fancy>(b: &mut F, xs: &[F::Item]) {
            let z = b.sub(&xs[0], &xs[1]).unwrap();
            b.output(&z).unwrap();
        }

        let mut rng = thread_rng();
        for _ in 0..16 {
            let q = rng.gen_modulus();
            streaming_test(
                move |b, xs| fancy_subtraction(b, xs),
                move |b, xs| fancy_subtraction(b, xs),
                move |b, xs| fancy_subtraction(b, xs),
                &[q, q],
            );
        }
    }

    #[test]
    fn multiplication() {
        fn fancy_multiplication<F: Fancy>(b: &mut F, xs: &[F::Item]) {
            let z = b.mul(&xs[0], &xs[1]).unwrap();
            b.output(&z).unwrap();
        }

        let mut rng = thread_rng();
        for _ in 0..16 {
            let q = rng.gen_modulus();
            streaming_test(
                move |b, xs| fancy_multiplication(b, xs),
                move |b, xs| fancy_multiplication(b, xs),
                move |b, xs| fancy_multiplication(b, xs),
                &[q, q],
            );
        }
    }

    #[test]
    fn cmul() {
        fn fancy_cmul<F: Fancy>(b: &mut F, xs: &[F::Item]) {
            let z = b.cmul(&xs[0], 5).unwrap();
            b.output(&z).unwrap();
        }

        let mut rng = thread_rng();
        for _ in 0..16 {
            let q = rng.gen_modulus();
            streaming_test(
                move |b, xs| fancy_cmul(b, xs),
                move |b, xs| fancy_cmul(b, xs),
                move |b, xs| fancy_cmul(b, xs),
                &[q],
            );
        }
    }

    #[test]
    fn proj() {
        fn fancy_projection<F: Fancy>(b: &mut F, xs: &[F::Item], q: u16) {
            let tab = (0..q).map(|i| (i + 1) % q).collect_vec();
            let z = b.proj(&xs[0], q, Some(tab)).unwrap();
            b.output(&z).unwrap();
        }

        let mut rng = thread_rng();
        for _ in 0..16 {
            let q = rng.gen_modulus();
            streaming_test(
                move |b, xs| fancy_projection(b, xs, q),
                move |b, xs| fancy_projection(b, xs, q),
                move |b, xs| fancy_projection(b, xs, q),
                &[q],
            );
        }
    }

}

#[cfg(test)]
mod complex {
    use crate::dummy::Dummy;
    use crate::util::RngExt;
    use crate::{CrtBundle, CrtGadgets, Evaluator, Fancy, Garbler};
    use itertools::Itertools;
    use rand::thread_rng;
    use scuttlebutt::AesRng;
    use std::cell::RefCell;
    use std::os::unix::net::UnixStream;
    use std::rc::Rc;

    fn complex_gadget<F: Fancy>(b: &mut F, xs: &[CrtBundle<F::Item>]) {
        let zs = xs
            .iter()
            .map(|x| {
                let c = b.crt_constant_bundle(1, x.composite_modulus()).unwrap();
                let y = b.crt_mul(x, &c).unwrap();
                b.crt_relu(&y, "100%", None).unwrap()
            })
            .collect_vec();
        b.crt_outputs(&zs).unwrap();
    }

    #[test]
    fn test_complex_gadgets() {
        let mut rng = thread_rng();
        let N = 10;
        let qs = crate::util::primes_with_width(10);
        let Q = crate::util::product(&qs);
        for _ in 0..16 {
            let input = (0..N).map(|_| rng.gen_u128() % Q).collect_vec();

            // Compute the correct answer using `Dummy`.
            let mut dummy = Dummy::new();
            let dinps = input
                .iter()
                .map(|x| {
                    let xs = crate::util::crt(*x, &qs);
                    CrtBundle::new(Dummy::encode_inputs(&xs, &qs).unwrap())
                })
                .collect_vec();
            complex_gadget(&mut dummy, &dinps);
            let should_be = dummy.get_output();

            // test streaming garbler and evaluator
            let (sender, receiver) = UnixStream::pair().unwrap();

            let input_ = input.clone();
            std::thread::spawn(move || {
                let sender = Rc::new(RefCell::new(sender));
                let mut garbler = Garbler::new(sender, AesRng::new(), &[]);

                // encode input and send it to the evaluator
                let mut gb_inp = Vec::with_capacity(N);
                for X in &input_ {
                    let (zero, enc) = garbler.crt_encode(*X, Q);
                    for w in enc.iter() {
                        garbler.send_wire(w).unwrap();
                    }
                    gb_inp.push(zero);
                }
                complex_gadget(&mut garbler, &gb_inp);
            });

            let receiver = Rc::new(RefCell::new(receiver));
            let mut evaluator = Evaluator::new(receiver);

            // receive encoded wires from the garbler thread
            let mut ev_inp = Vec::with_capacity(N);
            for _ in 0..N {
                let ws = qs
                    .iter()
                    .map(|q| evaluator.read_wire(*q).unwrap())
                    .collect_vec();
                ev_inp.push(CrtBundle::new(ws));
            }

            complex_gadget(&mut evaluator, &ev_inp);
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

        let inps_ = inps.clone();
        let mods_ = mods.clone();
        std::thread::spawn(move || {
            let sender = Rc::new(RefCell::new(sender));
            let mut gb1 = Garbler::new(sender.clone(), AesRng::new(), &[]);

            // get the input wirelabels
            let (gb_inps, ev_inps) = gb1.encode_many(&inps_, &mods_);

            for w in ev_inps.iter() {
                gb1.send_wire(w).unwrap()
            }

            // get deltas for input wires
            let ds = mods_.into_iter().map(|q| gb1.delta(q)).collect_vec();

            let mut gb2 = Garbler::new(sender, AesRng::new(), &ds);

            // output the input wires from the previous garbler
            gb2.outputs(&gb_inps).unwrap();
        });

        let receiver = Rc::new(RefCell::new(receiver));
        let mut ev1 = Evaluator::new(receiver.clone());

        let xs = mods
            .iter()
            .map(|q| ev1.read_wire(*q).unwrap())
            .collect_vec();

        let mut ev2 = Evaluator::new(receiver);
        ev2.outputs(&xs).unwrap();

        let result = ev2.decode_output().unwrap();
        assert_eq!(result, should_be);
    }
}
