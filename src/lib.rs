// -*- mode: rust; -*-
//
// This file is part of twopac.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! `twopac` implements (semi-honest) garbled-circuit-based two-party secure
//! computation in rust, using `ocelot` for oblivious transfer and
//! `fancy-garbling` for garbled circuits.
//!
//! **THIS IS VERY MUCH RESEARCH CODE!** (for now)

#![feature(non_ascii_idents)]
#![feature(test)]

mod comm;
mod evaluator;
mod garbler;

pub use evaluator::Evaluator;
pub use garbler::Garbler;

use fancy_garbling::Wire;
use ocelot::Block;

#[inline(always)]
fn wire_to_block(w: Wire) -> Block {
    Block::from(w.as_u128().to_le_bytes())
}
#[inline(always)]
fn block_to_wire(b: Block, q: u16) -> Wire {
    Wire::from_u128(b.into(), q)
}

#[cfg(test)]
mod tests {
    extern crate test;
    use super::*;
    use fancy_garbling::dummy::Dummy;
    use fancy_garbling::util::RngExt;
    use fancy_garbling::{BundleGadgets, Fancy, HasModulus, SyncIndex};
    use itertools::Itertools;
    use ocelot::*;
    use std::io::{BufReader, BufWriter};
    use std::os::unix::net::UnixStream;

    type Reader = BufReader<UnixStream>;
    type Writer = BufWriter<UnixStream>;

    fn c1<F: Fancy<Item = W>, W: HasModulus + Clone>(f: &mut F) {
        let a = f.garbler_input(None, 3, None);
        let b = f.evaluator_input(None, 3);
        let c = f.add(&a, &b);
        f.output(None, &c);
    }

    fn test_c1<
        OTSender: ObliviousTransferSender<Reader, Writer, Msg = Block>,
        OTReceiver: ObliviousTransferReceiver<Reader, Writer, Msg = Block>,
    >(
        a: u16,
        b: u16,
    ) {
        let (sender, receiver) = UnixStream::pair().unwrap();
        std::thread::spawn(move || {
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut gb = Garbler::<Reader, Writer, OTSender>::new(reader, writer, &[a]).unwrap();
            c1(&mut gb);
        });
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut ev = Evaluator::<Reader, Writer, OTReceiver>::new(reader, writer, &[b]).unwrap();
        c1(&mut ev);
        let output = ev.decode_output();
        assert_eq!(vec![(a + b) % 3], output);
    }

    type ChouOrlandiSender = chou_orlandi::ChouOrlandiOTSender<Reader, Writer>;
    type ChouOrlandiReceiver = chou_orlandi::ChouOrlandiOTReceiver<Reader, Writer>;

    #[test]
    fn test_simple_circuits() {
        test_c1::<ChouOrlandiSender, ChouOrlandiReceiver>(0, 0);
        test_c1::<ChouOrlandiSender, ChouOrlandiReceiver>(1, 0);
        test_c1::<ChouOrlandiSender, ChouOrlandiReceiver>(2, 0);
        test_c1::<ChouOrlandiSender, ChouOrlandiReceiver>(0, 1);
        test_c1::<ChouOrlandiSender, ChouOrlandiReceiver>(0, 2);
        test_c1::<ChouOrlandiSender, ChouOrlandiReceiver>(1, 1);
        test_c1::<ChouOrlandiSender, ChouOrlandiReceiver>(2, 1);
        test_c1::<ChouOrlandiSender, ChouOrlandiReceiver>(1, 2);
        test_c1::<ChouOrlandiSender, ChouOrlandiReceiver>(2, 2);
    }

    fn c2<F: Fancy<Item = W>, W: HasModulus + Clone>(f: &F, q: u128, n: SyncIndex) {
        // f.begin_sync(n);
        let mut zs = Vec::new();
        for i in 0..n {
            // let idx = Some(i);
            let idx = None;
            let c = f.constant_bundle_crt(idx, 1, q);
            let x = f.evaluator_input_bundle_crt(idx, q);
            let x = f.mul_bundles(idx, &x, &c);
            let z = f.relu(idx, &x, "100%", None);
            zs.push(z);
            // f.finish_index(i);
        }
        f.output_bundles(None, &zs);
    }

    #[test]
    fn test_complex_circuit() {
        let mut rng = rand::thread_rng();
        let n = 10;
        let q = fancy_garbling::util::modulus_with_width(10);
        let input = (0..n)
            .map(|_| fancy_garbling::util::crt_factor(rng.gen_u128() % q, q))
            .collect_vec();
        let input = input.iter().flatten().cloned().collect_vec();
        let dummy = Dummy::new(&[], &input);
        c2(&dummy, q, n);
        let target = dummy.get_output();
        let (sender, receiver) = UnixStream::pair().unwrap();
        std::thread::spawn(move || {
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let gb =
                Garbler::<Reader, Writer, ChouOrlandiSender>::new(reader, writer, &[]).unwrap();
            c2(&gb, q, n);
        });
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let ev =
            Evaluator::<Reader, Writer, ChouOrlandiReceiver>::new(reader, writer, &input).unwrap();
        c2(&ev, q, n);
        let result = ev.decode_output();
        assert_eq!(target, result);
    }

    // fn parallel_gadgets<F, W>(b: &F, q: u128, ix: SyncIndex, par: bool)
    // where
    //     W: Clone + HasModulus + Send + Sync + std::fmt::Debug,
    //     F: Fancy<Item = W> + Send + Sync,
    // {
    //     if par {
    //         crossbeam::scope(|scope| {
    //             b.begin_sync(ix);
    //             let hs = (0..ix)
    //                 .map(|i| {
    //                     scope
    //                         .builder()
    //                         .name(format!("Thread {}", i))
    //                         .spawn(move |_| {
    //                             let c = b.constant_bundle_crt(Some(i), 1, q);
    //                             let x = b.garbler_input_bundle_crt(Some(i), q);
    //                             let x = b.mul_bundles(Some(i), &x, &c);
    //                             let z = b.relu(Some(i), &x, "100%");
    //                             b.finish_index(i);
    //                             z
    //                         })
    //                         .unwrap()
    //                 })
    //                 .collect_vec();
    //             let outs = hs.into_iter().map(|h| h.join().unwrap()).collect_vec();
    //             b.output_bundles(None, &outs);
    //         })
    //         .unwrap()
    //     } else {
    //         b.begin_sync(ix);
    //         let mut zs = Vec::new();
    //         for i in 0..ix {
    //             let c = b.constant_bundle_crt(Some(i), 1, q);
    //             let x = b.garbler_input_bundle_crt(Some(i), q);
    //             let x = b.mul_bundles(Some(i), &x, &c);
    //             let z = b.relu(Some(i), &x, "100%");
    //             zs.push(z);
    //             b.finish_index(i);
    //         }
    //         b.output_bundles(None, &zs);
    //     }
    // }

    // #[test]
    // fn parallel_garbling() {
    //     let mut rng = rand::thread_rng();
    //     let n = 10;
    //     let q = fancy_garbling::util::modulus_with_width(10);
    //     for _ in 0..16 {
    //         let input = (0..n)
    //             .map(|_| fancy_garbling::util::crt_factor(rng.gen_u128() % q, q))
    //             .collect_vec();
    //         // compute the correct answer using Dummy
    //         let input = input.iter().flatten().cloned().collect_vec();
    //         let dummy = Dummy::new(&input, &[]);
    //         parallel_gadgets(&dummy, q, n, false);
    //         let should_be_par = dummy.get_output();

    //         // check serial version agrees with parallel
    //         let dummy = Dummy::new(&input, &[]);
    //         parallel_gadgets(&dummy, q, n, false);
    //         let should_be = dummy.get_output();

    //         assert_eq!(should_be, should_be_par);

    //         let (sender, receiver) = UnixStream::pair().unwrap();
    //         std::thread::spawn(move || {
    //             let gb = Garbler::<UnixStream, ChouOrlandiOT<UnixStream>>::new(sender, &input);
    //             parallel_gadgets(&gb, q, n, false);
    //         });
    //         let ev = Evaluator::<UnixStream, ChouOrlandiOT<UnixStream>>::new(receiver, &[]);
    //         parallel_gadgets(&ev, q, n, false);
    //         let result = ev.decode_output();
    //         assert_eq!(result, should_be);
    //     }
    // }

}
