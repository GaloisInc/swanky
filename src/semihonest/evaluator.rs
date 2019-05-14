// -*- mode: rust; -*-
//
// This file is part of twopac.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use crate::errors::Error;
use fancy_garbling::{Evaluator as Ev, Fancy, Wire};
use ocelot::ot::Receiver as OtReceiver;
use rand::{CryptoRng, RngCore};
use scuttlebutt::Block;
use std::cell::RefCell;
use std::fmt::Debug;
use std::io::{Read, Write};
use std::rc::Rc;

/// Semi-honest evaluator.
pub struct Evaluator<R, W, RNG, OT> {
    evaluator: Ev<R>,
    reader: Rc<RefCell<R>>,
    writer: Rc<RefCell<W>>,
    ot: OT,
    rng: RNG,
}

impl<
        R: Read + Send + Debug + 'static,
        W: Write + Send + Debug,
        RNG: CryptoRng + RngCore,
        OT: OtReceiver<Msg = Block>,
    > Evaluator<R, W, RNG, OT>
{
    /// Make a new `Evaluator`.
    pub fn new(
        reader: Rc<RefCell<R>>,
        writer: Rc<RefCell<W>>,
        mut rng: RNG,
    ) -> Result<Self, Error> {
        let ot = OT::init(
            &mut *reader.borrow_mut(),
            &mut *writer.borrow_mut(),
            &mut rng,
        )?;
        let evaluator = Ev::new(reader.clone());
        Ok(Evaluator {
            evaluator,
            reader,
            writer,
            ot,
            rng,
        })
    }

    /// Decode the output post-evaluation.
    pub fn decode_output(&self) -> Result<Vec<u16>, Error> {
        let outs = self.evaluator.decode_output()?;
        Ok(outs)
    }

    fn run_ot(&mut self, inputs: &[bool]) -> Result<Vec<Block>, Error> {
        self.ot
            .receive(
                &mut *self.reader.borrow_mut(),
                &mut *self.writer.borrow_mut(),
                &inputs,
                &mut self.rng,
            )
            .map_err(Error::from)
    }

    /// Receive a garbler input wire.
    #[inline]
    pub fn garbler_input(&mut self, modulus: u16) -> Result<Wire, Error> {
        let w = self.evaluator.read_wire(modulus)?;
        Ok(w)
    }

    /// Receive garbler input wires.
    #[inline]
    pub fn garbler_inputs(&mut self, moduli: &[u16]) -> Result<Vec<Wire>, Error> {
        moduli.iter().map(|q| self.garbler_input(*q)).collect()
    }

    /// Perform OT and obtain wires for the evaluator's inputs.
    #[inline]
    pub fn evaluator_inputs(&mut self, inputs: &[u16], moduli: &[u16]) -> Result<Vec<Wire>, Error> {
        let mut lens = Vec::new();
        let mut bs = Vec::new();
        for (x, q) in inputs.iter().zip(moduli.iter()) {
            let len = (*q as f32).log(2.0).ceil() as usize;
            for b in (0..len).map(|i| x & (1 << i) != 0) {
                bs.push(b);
            }
            lens.push(len);
        }
        let wires = self.run_ot(&bs)?;
        let mut start = 0;
        Ok(lens
            .into_iter()
            .zip(moduli.iter())
            .map(|(len, q)| {
                let range = start..start + len;
                let chunk = &wires[range];
                start += len;
                combine(chunk, *q)
            })
            .collect::<Vec<Wire>>())
    }
}

fn combine(wires: &[Block], q: u16) -> Wire {
    wires.iter().enumerate().fold(Wire::zero(q), |acc, (i, w)| {
        let w = Wire::from_block(*w, q);
        acc.plus(&w.cmul(1 << i))
    })
}

impl<
        R: Read + Send + Debug + 'static,
        W: Write + Send + Debug,
        RNG: CryptoRng + RngCore,
        OT: OtReceiver<Msg = Block>,
    > Fancy for Evaluator<R, W, RNG, OT>
{
    type Item = Wire;
    type Error = Error;

    #[inline]
    fn constant(&mut self, x: u16, q: u16) -> Result<Self::Item, Self::Error> {
        self.evaluator.constant(x, q).map_err(Self::Error::from)
    }

    #[inline]
    fn add(&mut self, x: &Wire, y: &Wire) -> Result<Self::Item, Self::Error> {
        self.evaluator.add(&x, &y).map_err(Self::Error::from)
    }

    #[inline]
    fn sub(&mut self, x: &Wire, y: &Wire) -> Result<Self::Item, Self::Error> {
        self.evaluator.sub(&x, &y).map_err(Self::Error::from)
    }

    #[inline]
    fn cmul(&mut self, x: &Wire, c: u16) -> Result<Self::Item, Self::Error> {
        self.evaluator.cmul(&x, c).map_err(Self::Error::from)
    }

    #[inline]
    fn mul(&mut self, x: &Wire, y: &Wire) -> Result<Self::Item, Self::Error> {
        self.evaluator.mul(&x, &y).map_err(Self::Error::from)
    }

    #[inline]
    fn proj(&mut self, x: &Wire, q: u16, tt: Option<Vec<u16>>) -> Result<Self::Item, Self::Error> {
        self.evaluator.proj(&x, q, tt).map_err(Self::Error::from)
    }

    #[inline]
    fn output(&mut self, x: &Wire) -> Result<(), Self::Error> {
        self.evaluator.output(&x).map_err(Self::Error::from)
    }
}
