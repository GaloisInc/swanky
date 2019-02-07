// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use crate::comm;
use fancy_garbling::{Evaluator as Ev, Fancy, Message, SyncIndex, Wire};
use ocelot::{Block, BlockObliviousTransfer};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

pub struct Evaluator<S: Send + Sync + Read + Write, OT: BlockObliviousTransfer<S>> {
    evaluator: Ev,
    stream: Arc<Mutex<S>>,
    inputs: Arc<Mutex<Vec<u16>>>,
    ot: Arc<Mutex<OT>>,
}

impl<S: Send + Sync + Read + Write + 'static, OT: BlockObliviousTransfer<S>> Evaluator<S, OT> {
    pub fn new(stream: S, stream_: S, inputs: &[u16]) -> Self {
        let inputs = Arc::new(Mutex::new(inputs.to_vec()));
        let stream = Arc::new(Mutex::new(stream));
        let stream_ = Arc::new(Mutex::new(stream_));
        let callback = move || {
            // println!("Evaluator: Before lock");
            let mut stream = stream_.lock().unwrap();
            let idx = comm::receive(&mut *stream).unwrap(); // XXX: unwrap
            let bytes = comm::receive(&mut *stream).unwrap(); // XXX: unwrap
            let msg = Message::from_bytes(&bytes).unwrap(); // XXX: unwrap
            let idx = if idx[0] == 0xFF { None } else { Some(idx[0]) };
            // println!("Evaluator: {:?}, {:?}", idx, msg);
            (idx, msg)
        };
        let evaluator = Ev::new(callback);
        let ot = Arc::new(Mutex::new(OT::new()));
        Evaluator {
            evaluator,
            stream,
            inputs,
            ot,
        }
    }

    pub fn decode_output(&self) -> Vec<u16> {
        self.evaluator.decode_output()
    }

    fn run_ot(&self, inputs: &[bool]) -> Vec<Block> {
        let mut ot = self.ot.lock().unwrap();
        let mut stream = self.stream.lock().unwrap();
        ot.receive(&mut *stream, &inputs).unwrap() // XXX: remove unwrap
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

impl<S: Send + Sync + Read + Write + 'static, OT: BlockObliviousTransfer<S>> Fancy
    for Evaluator<S, OT>
{
    type Item = Wire;

    fn garbler_input(&self, ix: Option<SyncIndex>, q: u16) -> Wire {
        self.evaluator.garbler_input(ix, q)
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
