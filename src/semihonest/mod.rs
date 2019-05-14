// -*- mode: rust; -*-
//
// This file is part of twopac.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Implementation of semi-honest two-party computation.

mod evaluator;
mod garbler;

pub use evaluator::Evaluator;
pub use garbler::Garbler;

#[cfg(test)]
mod tests {
    use super::*;
    use fancy_garbling::dummy::Dummy;
    use fancy_garbling::util::RngExt;
    use fancy_garbling::{CrtBundle, CrtGadgets, Fancy};
    use scuttlebutt::AesRng;
    use std::cell::RefCell;
    use std::io::{BufReader, BufWriter};
    use std::os::unix::net::UnixStream;
    use std::rc::Rc;
    use fancy_garbling::circuit::Circuit;
    use ocelot::ot::{ChouOrlandiReceiver, ChouOrlandiSender};
    use itertools::Itertools;

    type Reader = BufReader<UnixStream>;
    type Writer = BufWriter<UnixStream>;

    fn addition<F: Fancy>(f: &mut F, a: &F::Item, b: &F::Item) -> Result<(), F::Error> {
        let c = f.add(&a, &b)?;
        f.output(&c)?;
        Ok(())
    }

    #[test]
    fn test_addition_circuit() {
        for a in 0..2 {
            for b in 0..2 {
                let (sender, receiver) = UnixStream::pair().unwrap();
                let (tx, rx) = std::sync::mpsc::channel();
                std::thread::spawn(move || {
                    let rng = AesRng::new();
                    let reader = Rc::new(RefCell::new(BufReader::new(sender.try_clone().unwrap())));
                    let writer = Rc::new(RefCell::new(BufWriter::new(sender)));
                    let mut gb =
                        Garbler::<Reader, Writer, AesRng, ChouOrlandiSender>::new(reader, writer, rng)
                            .unwrap();

                    // perform ot for the evaluator's input
                    let ev_inps = gb.evaluator_inputs(&[3]).unwrap();

                    // encode garbler's input and send it
                    let (b_gb, b_ev) = gb.encode(b, 3);
                    tx.send(b_ev).unwrap();

                    addition(&mut gb, &ev_inps[0], &b_gb).unwrap();
                });
                let rng = AesRng::new();
                let reader = Rc::new(RefCell::new(BufReader::new(receiver.try_clone().unwrap())));
                let writer = Rc::new(RefCell::new(BufWriter::new(receiver)));

                let mut ev =
                    Evaluator::<Reader, Writer, AesRng, ChouOrlandiReceiver>::new(reader, writer, rng)
                        .unwrap();

                // perform ot
                let ev_inps = ev.evaluator_inputs(&[b], &[3]).unwrap();

                // receive garbler's input
                let b_ev = rx.recv().unwrap();

                addition(&mut ev, &ev_inps[0], &b_ev).unwrap();

                let output = ev.decode_output().unwrap();
                assert_eq!(vec![(a + b) % 3], output);
            }
        }
    }

    fn relu<F: Fancy>(b: &mut F, xs: &[CrtBundle<F::Item>]) {
        for x in xs.iter() {
            let q = x.composite_modulus();
            let c = b.crt_constant_bundle(1, q).unwrap();
            let y = b.crt_mul(&x, &c).unwrap();
            let z = b.crt_relu(&y, "100%", None).unwrap();
            for w in z.iter() {
                b.output(w).unwrap();
            }
        }
    }

    #[test]
    fn test_complex_circuit() {
        let mut rng = rand::thread_rng();
        let n = 10;
        let ps = fancy_garbling::util::primes_with_width(10);
        let q = fancy_garbling::util::product(&ps);
        let input = (0..n)
            .map(|_| rng.gen_u128() % q)
            .collect::<Vec<u128>>();

        // Run dummy version.
        let mut dummy = Dummy::new();
        let dummy_input = input.iter().map(|x| fancy_garbling::dummy::DummyVal::crt_factor(*x,q)).collect_vec();
        relu(&mut dummy, &dummy_input);
        let target = dummy.get_output();

        // Run 2PC version.
        let (sender, receiver) = UnixStream::pair().unwrap();
        std::thread::spawn(move || {
            let rng = AesRng::new();
            let reader = Rc::new(RefCell::new(BufReader::new(sender.try_clone().unwrap())));
            let writer = Rc::new(RefCell::new(BufWriter::new(sender)));
            let mut gb = Garbler::<Reader, Writer, AesRng, ChouOrlandiSender>::new(
                reader, writer, &input, rng,
            )
            .unwrap();
            relu(&mut gb, q, n);
        });
        let rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut ev = Evaluator::<Reader, Writer, AesRng, ChouOrlandiReceiver>::new(
            Rc::new(RefCell::new(reader)),
            Rc::new(RefCell::new(writer)),
            &[],
            rng,
        )
        .unwrap();
        relu(&mut ev, q, n);
        let result = ev.decode_output();
        assert_eq!(target, result);
    }

    #[test]
    fn test_aes() {
        let mut circ = Circuit::parse("circuits/AES-non-expanded.txt").unwrap();
        let mut circ_ = circ.clone();
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let rng = AesRng::new();
            let reader = Rc::new(RefCell::new(BufReader::new(sender.try_clone().unwrap())));
            let writer = Rc::new(RefCell::new(BufWriter::new(sender)));
            let mut gb = Garbler::<Reader, Writer, AesRng, ChouOrlandiSender>::new(
                reader,
                writer,
                &vec![0u16; 128],
                rng,
            )
            .unwrap();
            circ_.eval(&mut gb).unwrap();
        });
        let rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut ev = Evaluator::<Reader, Writer, AesRng, ChouOrlandiReceiver>::new(
            Rc::new(RefCell::new(reader)),
            Rc::new(RefCell::new(writer)),
            &vec![0u16; 128],
            rng,
        )
        .unwrap();
        circ.eval(&mut ev).unwrap();
        handle.join().unwrap();
    }
}
