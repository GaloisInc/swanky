// -*- mode: rust; -*-
//
// This file is part of twopac.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use crate::comm;
use failure::Error;
use fancy_garbling::{Evaluator as Ev, Fancy, Message, SyncIndex, Wire};
use ocelot::ObliviousTransferReceiver;
use rand::{CryptoRng, RngCore};
use scuttlebutt::Block;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

pub struct Evaluator<
    R: Read + Send,
    W: Write + Send,
    RNG: CryptoRng + RngCore,
    OT: ObliviousTransferReceiver,
> {
    evaluator: Ev,
    reader: Arc<Mutex<R>>,
    writer: Arc<Mutex<W>>,
    inputs: Arc<Mutex<Vec<u16>>>,
    ot: Arc<Mutex<OT>>,
    rng: Arc<Mutex<RNG>>,
}

impl<
        R: Read + Send + 'static,
        W: Write + Send,
        RNG: CryptoRng + RngCore,
        OT: ObliviousTransferReceiver<Msg = Block>,
    > Evaluator<R, W, RNG, OT>
{
    pub fn new(mut reader: R, mut writer: W, inputs: &[u16], mut rng: RNG) -> Result<Self, Error> {
        let ot = OT::init(&mut reader, &mut writer, &mut rng)?;
        let inputs = Arc::new(Mutex::new(inputs.to_vec()));
        let reader = Arc::new(Mutex::new(reader));
        let writer = Arc::new(Mutex::new(writer));
        let reader_ = Arc::clone(&reader);
        let callback = move || {
            let mut reader = reader_.lock().unwrap();
            let idx = comm::receive(&mut *reader).unwrap(); // XXX: unwrap
            let bytes = comm::receive(&mut *reader).unwrap(); // XXX: unwrap
            let msg = Message::from_bytes(&bytes).unwrap(); // XXX: unwrap
            let idx = if idx[0] == 0xFF { None } else { Some(idx[0]) };
            (idx, msg)
        };
        let evaluator = Ev::new(callback);
        let ot = Arc::new(Mutex::new(ot));
        let rng = Arc::new(Mutex::new(rng));
        Ok(Evaluator {
            evaluator,
            reader,
            writer,
            inputs,
            ot,
            rng,
        })
    }

    pub fn decode_output(&self) -> Vec<u16> {
        self.evaluator.decode_output()
    }

    fn run_ot(&self, inputs: &[bool]) -> Vec<Block> {
        let mut ot = self.ot.lock().unwrap();
        let mut reader = self.reader.lock().unwrap();
        let mut writer = self.writer.lock().unwrap();
        let mut rng = self.rng.lock().unwrap();
        ot.receive(&mut *reader, &mut *writer, &inputs, &mut *rng)
            .unwrap() // XXX: remove unwrap
    }
}

fn combine(wires: &[Block], q: u16) -> Wire {
    wires
        .into_iter()
        .enumerate()
        .fold(Wire::zero(q), |acc, (i, w)| {
            let w = super::block_to_wire(*w, q);
            acc.plus(&w.cmul(1 << i))
        })
}

impl<
        R: Read + Send + 'static,
        W: Write + Send,
        RNG: CryptoRng + RngCore,
        OT: ObliviousTransferReceiver<Msg = Block>,
    > Fancy for Evaluator<R, W, RNG, OT>
{
    type Item = Wire;

    fn garbler_input(&self, ix: Option<SyncIndex>, q: u16, opt_x: Option<u16>) -> Wire {
        self.evaluator.garbler_input(ix, q, opt_x)
    }

    fn evaluator_input(&self, _ix: Option<SyncIndex>, q: u16) -> Wire {
        let ℓ = (q as f32).log(2.0).ceil() as u16;
        let input = self.inputs.lock().unwrap().remove(0);
        let bs = (0..ℓ)
            .into_iter()
            .map(|i| input & (1 << i) != 0)
            .collect::<Vec<bool>>();
        let wires = self.run_ot(&bs);
        combine(&wires, q)
    }

    fn evaluator_inputs(&self, _ix: Option<SyncIndex>, qs: &[u16]) -> Vec<Wire> {
        println!("Evaluator: evaluator_inputs");
        let ℓs = qs
            .into_iter()
            .map(|q| (*q as f32).log(2.0).ceil() as usize)
            .collect::<Vec<usize>>();
        let mut bs = Vec::with_capacity(ℓs.iter().sum());
        for ℓ in ℓs.iter() {
            let input = self.inputs.lock().unwrap().remove(0);
            for b in (0..*ℓ).into_iter().map(|i| input & (1 << i) != 0) {
                bs.push(b);
            }
        }
        let wires = self.run_ot(&bs);
        let mut start = 0;
        ℓs.into_iter()
            .zip(qs.into_iter())
            .map(|(ℓ, q)| {
                let range = start..start + ℓ;
                let chunk = &wires[range];
                start = start + ℓ;
                combine(chunk, *q)
            })
            .collect::<Vec<Wire>>()
    }

    fn constant(&self, ix: Option<SyncIndex>, x: u16, q: u16) -> Wire {
        self.evaluator.constant(ix, x, q)
    }

    fn add(&self, x: &Wire, y: &Wire) -> Wire {
        self.evaluator.add(&x, &y)
    }

    fn sub(&self, x: &Wire, y: &Wire) -> Wire {
        self.evaluator.sub(&x, &y)
    }

    fn cmul(&self, x: &Wire, c: u16) -> Wire {
        self.evaluator.cmul(&x, c)
    }

    fn mul(&self, ix: Option<SyncIndex>, x: &Wire, y: &Wire) -> Wire {
        self.evaluator.mul(ix, &x, &y)
    }

    fn proj(&self, ix: Option<SyncIndex>, x: &Wire, q: u16, tt: Option<Vec<u16>>) -> Wire {
        self.evaluator.proj(ix, &x, q, tt)
    }

    fn output(&self, ix: Option<SyncIndex>, x: &Wire) {
        self.evaluator.output(ix, &x)
    }

    fn begin_sync(&self, n: SyncIndex) {
        self.evaluator.begin_sync(n)
    }

    fn finish_index(&self, ix: SyncIndex) {
        self.evaluator.finish_index(ix)
    }
}
