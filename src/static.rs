// -*- mode: rust; -*-
//
// This file is part of `fancy-garbling`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Provides objects and functions for statically garbling and evaluating a
//! circuit.

use crate::circuit::Circuit;
use crate::error::{EvaluatorError, GarblerError};
use crate::fancy::HasModulus;
use crate::garble::{Evaluator, Garbler};
use crate::wire::Wire;
use crate::Fancy;
use scuttlebutt::{AesRng, Block};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::HashMap;
use std::convert::TryInto;
use std::rc::Rc;

/// Static evaluator for a circuit, created by the `garble` function.
///
/// Uses `Evaluator` under the hood to actually implement the evaluation.
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct GarbledCircuit {
    blocks: Vec<Block>,
}

impl GarbledCircuit {
    /// Create a new object from a vector of garbled gates and constant wires.
    pub fn new(blocks: Vec<Block>) -> Self {
        GarbledCircuit { blocks }
    }

    /// The number of garbled rows and constant wires in the garbled circuit.
    #[inline]
    pub fn size(&self) -> usize {
        self.blocks.len()
    }

    /// Evaluate the garbled circuit.
    pub fn eval(
        &self,
        c: &mut Circuit,
        garbler_inputs: &[Wire],
        evaluator_inputs: &[Wire],
    ) -> Result<Vec<u16>, EvaluatorError> {
        let mut evaluator = StaticEvaluator::new(garbler_inputs, evaluator_inputs, &self.blocks);
        let outputs = c.eval(&mut evaluator)?;
        c.process_outputs(&outputs, &mut evaluator)?;
        evaluator.evaluator.decode_output()
    }
}

/// Implementation of the `Write` trait for use by `Garbler`.
#[derive(Debug)]
pub struct GarbledWriter {
    blocks: Vec<Block>,
}

impl GarbledWriter {
    /// Make a new `GarbledWriter`.
    pub fn new(ngates: Option<usize>) -> Self {
        let blocks = if let Some(n) = ngates {
            Vec::with_capacity(2 * n)
        } else {
            Vec::new()
        };
        Self { blocks }
    }
}

impl std::io::Write for GarbledWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        for item in buf.chunks(16) {
            let bytes: [u8; 16] = match item.try_into() {
                Ok(bytes) => bytes,
                Err(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "unable to map bytes to block",
                    ));
                }
            };
            self.blocks.push(Block::from(bytes));
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Garble a circuit without streaming.
pub fn garble(c: &mut Circuit) -> Result<(Encoder, GarbledCircuit), GarblerError> {
    let gb_inputs = Vec::with_capacity(c.num_garbler_inputs());
    let ev_inputs = Vec::with_capacity(c.num_evaluator_inputs());
    let writer = GarbledWriter::new(Some(c.num_nonfree_gates));
    let writer = Rc::new(RefCell::new(writer));
    let writer_ = writer.clone();
    let gb_inputs = Rc::new(RefCell::new(gb_inputs));
    let ev_inputs = Rc::new(RefCell::new(ev_inputs));
    let gb_inputs_ = gb_inputs.clone();
    let ev_inputs_ = ev_inputs.clone();
    let deltas = {
        let callback = move |m| {
            match m {
                Message::UnencodedGarblerInput { zero, .. } => gb_inputs_.borrow_mut().push(zero),
                Message::UnencodedEvaluatorInput { zero, .. } => ev_inputs_.borrow_mut().push(zero),
            }
            Ok(())
        };

        let rng = AesRng::new();
        let mut garbler = Garbler::new(writer_, callback, rng);
        let outputs = c.eval(&mut garbler)?;
        c.process_outputs(&outputs, &mut garbler)?;
        garbler.get_deltas()
    };
    let en = Encoder::new(
        Rc::try_unwrap(gb_inputs).unwrap().into_inner(),
        Rc::try_unwrap(ev_inputs).unwrap().into_inner(),
        deltas,
    );
    let gc = GarbledCircuit::new(Rc::try_unwrap(writer).unwrap().into_inner().blocks);

    Ok((en, gc))
}

////////////////////////////////////////////////////////////////////////////////
// static evaluator

/// Object for statically evaluating a circuit.
pub struct StaticEvaluator {
    garbler_inputs: Vec<Wire>,
    evaluator_inputs: Vec<Wire>,
    evaluator: Evaluator<GarbledReader>,
}

impl StaticEvaluator {
    /// Make a new `StaticEvaluator` object.
    pub fn new(garbler_inputs: &[Wire], evaluator_inputs: &[Wire], blocks: &[Block]) -> Self {
        let reader = GarbledReader::new(blocks);
        let evaluator = Evaluator::new(Rc::new(RefCell::new(reader)));
        Self {
            garbler_inputs: garbler_inputs.to_vec(),
            evaluator_inputs: evaluator_inputs.to_vec(),
            evaluator,
        }
    }
}

impl Fancy for StaticEvaluator {
    type Item = Wire;
    type Error = EvaluatorError;

    fn constant(&mut self, val: u16, q: u16) -> Result<Self::Item, Self::Error> {
        self.evaluator.constant(val, q)
    }

    fn add(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error> {
        self.evaluator.add(x, y)
    }

    fn sub(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error> {
        self.evaluator.sub(x, y)
    }

    fn mul(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error> {
        self.evaluator.mul(x, y)
    }

    fn cmul(&mut self, x: &Self::Item, c: u16) -> Result<Self::Item, Self::Error> {
        self.evaluator.cmul(x, c)
    }

    fn proj(
        &mut self,
        x: &Self::Item,
        q: u16,
        tt: Option<Vec<u16>>,
    ) -> Result<Self::Item, Self::Error> {
        self.evaluator.proj(x, q, tt)
    }

    fn output(&mut self, x: &Self::Item) -> Result<(), Self::Error> {
        self.evaluator.output(x)
    }
}

#[derive(Debug)]
struct GarbledReader {
    blocks: Vec<Block>,
    index: usize,
}

impl GarbledReader {
    fn new(blocks: &[Block]) -> Self {
        Self {
            blocks: blocks.to_vec(),
            index: 0,
        }
    }
}

impl std::io::Read for GarbledReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        assert_eq!(buf.len() % 16, 0);
        for data in buf.chunks_mut(16) {
            let block: [u8; 16] = self.blocks[self.index].into();
            for (a, b) in data.iter_mut().zip(block.iter()) {
                *a = *b;
            }
            self.index += 1;
        }
        Ok(buf.len())
    }
}

////////////////////////////////////////////////////////////////////////////////
// Encoder

/// Encode inputs statically.
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Encoder {
    garbler_inputs: Vec<Wire>,
    evaluator_inputs: Vec<Wire>,
    deltas: HashMap<u16, Wire>,
}

impl Encoder {
    /// Make a new `Encoder` from lists of garbler and evaluator inputs,
    /// alongside a map of moduli-to-wire-offsets.
    pub fn new(
        garbler_inputs: Vec<Wire>,
        evaluator_inputs: Vec<Wire>,
        deltas: HashMap<u16, Wire>,
    ) -> Self {
        Encoder {
            garbler_inputs,
            evaluator_inputs,
            deltas,
        }
    }

    /// Output the number of garbler inputs.
    pub fn num_garbler_inputs(&self) -> usize {
        self.garbler_inputs.len()
    }

    /// Output the number of evaluator inputs.
    pub fn num_evaluator_inputs(&self) -> usize {
        self.evaluator_inputs.len()
    }

    /// Encode a single garbler input into its associated wire-label.
    pub fn encode_garbler_input(&self, x: u16, id: usize) -> Wire {
        let X = &self.garbler_inputs[id];
        let q = X.modulus();
        X.plus(&self.deltas[&q].cmul(x))
    }

    /// Encode a single evaluator input into its associated wire-label.
    pub fn encode_evaluator_input(&self, x: u16, id: usize) -> Wire {
        let X = &self.evaluator_inputs[id];
        let q = X.modulus();
        X.plus(&self.deltas[&q].cmul(x))
    }

    /// Encode a slice of garbler inputs into their associated wire-labels.
    pub fn encode_garbler_inputs(&self, inputs: &[u16]) -> Vec<Wire> {
        debug_assert_eq!(inputs.len(), self.garbler_inputs.len());
        (0..inputs.len())
            .zip(inputs)
            .map(|(id, &x)| self.encode_garbler_input(x, id))
            .collect()
    }

    /// Encode a slice of evaluator inputs into their associated wire-labels.
    pub fn encode_evaluator_inputs(&self, inputs: &[u16]) -> Vec<Wire> {
        debug_assert_eq!(inputs.len(), self.evaluator_inputs.len());
        (0..inputs.len())
            .zip(inputs)
            .map(|(id, &x)| self.encode_evaluator_input(x, id))
            .collect()
    }
}
