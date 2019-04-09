// -*- mode: rust; -*-
//
// This file is part of `fancy-garbling`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Provides objects for statically garbling and evaluating a circuit.

use crate::circuit::Circuit;
use crate::error::{EvaluatorError, GarblerError};
use crate::fancy::HasModulus;
use crate::garble::{Evaluator, Garbler, Message};
use crate::util::output_tweak;
use crate::wire::Wire;
use crate::Fancy;
use arrayref::array_ref;
use scuttlebutt::{AesRng, Block};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

struct GarbledWriter {
    gb_inputs: Vec<Wire>,
    ev_inputs: Vec<Wire>,
    data: Vec<Block>,
}

impl GarbledWriter {
    fn new() -> Self {
        let gb_inputs = Vec::new();
        let ev_inputs = Vec::new();
        let data = Vec::new();
        Self {
            gb_inputs,
            ev_inputs,
            data,
        }
    }
}

impl std::io::Write for GarbledWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        assert_eq!(buf.len() % 16, 0);
        for item in buf.chunks(16) {
            self.data.push(Block::from(*array_ref![item, 0, 16]));
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Garble a circuit without streaming.
pub fn garble(c: &mut Circuit) -> Result<(Encoder, GarbledCircuit), GarblerError> {
    let writer = Arc::new(Mutex::new(GarbledWriter::new()));
    let writer_ = writer.clone();
    let callback = move |m| {
        match m {
            Message::UnencodedGarblerInput { zero, .. } => {
                writer_.lock().unwrap().gb_inputs.push(zero)
            }
            Message::UnencodedEvaluatorInput { zero, .. } => {
                writer_.lock().unwrap().ev_inputs.push(zero)
            }
        }
        Ok(())
    };

    let deltas = {
        let rng = AesRng::new();
        let mut garbler = Garbler::new(writer.clone(), callback, rng);
        let outputs = c.eval(&mut garbler)?;
        c.process_outputs(&outputs, &mut garbler)?;
        garbler.get_deltas()
    };
    let gb_inputs = writer.lock().unwrap().gb_inputs.clone();
    let ev_inputs = writer.lock().unwrap().ev_inputs.clone();
    let en = Encoder::new(gb_inputs, ev_inputs, deltas);
    let gc = GarbledCircuit::new(&writer.lock().unwrap().data);

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
        let evaluator = Evaluator::new(Arc::new(Mutex::new(reader)));
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

    fn garbler_input(&mut self, _: u16, _: Option<u16>) -> Result<Self::Item, Self::Error> {
        if self.garbler_inputs.is_empty() {
            return Err(EvaluatorError::NotEnoughGarblerInputs);
        }
        let wire = self.garbler_inputs.remove(0);
        Ok(wire)
    }

    fn evaluator_input(&mut self, _: u16) -> Result<Self::Item, Self::Error> {
        if self.evaluator_inputs.is_empty() {
            return Err(EvaluatorError::NotEnoughEvaluatorInputs);
        }
        let wire = self.evaluator_inputs.remove(0);
        Ok(wire)
    }

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

/// Static evaluator for a circuit, created by the `garble` function.
///
/// Uses `Evaluator` under the hood to actually implement the evaluation.
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct GarbledCircuit {
    blocks: Vec<Block>,
    output_wires: Vec<Wire>,
    output_cts: Vec<Vec<Block>>,
}

impl GarbledCircuit {
    /// Create a new object from a vector of garbled gates and constant wires.
    pub fn new(blocks: &[Block]) -> Self {
        GarbledCircuit {
            blocks: blocks.to_vec(),
            output_wires: vec![],
            output_cts: vec![],
        }
    }

    /// The number of garbled rows and constant wires in the garbled circuit.
    #[inline]
    pub fn size(&self) -> usize {
        self.blocks.len()
    }

    /// Evaluate the garbled circuit.
    pub fn eval(
        &mut self,
        c: &mut Circuit,
        garbler_inputs: &[Wire],
        evaluator_inputs: &[Wire],
    ) -> Result<Vec<Wire>, EvaluatorError> {
        let mut evaluator = StaticEvaluator::new(garbler_inputs, evaluator_inputs, &self.blocks);
        let outputs = c.eval(&mut evaluator)?;
        c.process_outputs(&outputs, &mut evaluator)?;
        self.output_wires = evaluator.evaluator.output_wires.clone();
        self.output_cts = evaluator.evaluator.output_cts.clone();
        Ok(outputs)
    }

    /// Decode the output received during the Fancy computation.
    pub fn decode_output(&self) -> Vec<u16> {
        Decoder::new(self.output_cts.clone()).decode(&self.output_wires)
    }
}

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
            for (a, b) in data.iter_mut().zip(block.into_iter()) {
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

////////////////////////////////////////////////////////////////////////////////
// Decoder

/// Decode outputs statically.
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Decoder {
    outputs: Vec<Vec<Block>>,
}

impl Decoder {
    /// Make a new `Decoder` from a set of output ciphertexts.
    pub fn new(outputs: Vec<Vec<Block>>) -> Self {
        Decoder { outputs }
    }

    /// Decode a slice of wire-labels `ws`.
    pub fn decode(&self, ws: &[Wire]) -> Vec<u16> {
        debug_assert_eq!(
            ws.len(),
            self.outputs.len(),
            "got {} wires, but have {} output ciphertexts",
            ws.len(),
            self.outputs.len()
        );

        let mut outs = Vec::with_capacity(ws.len());
        for i in 0..ws.len() {
            let q = ws[i].modulus();
            debug_assert_eq!(q as usize, self.outputs[i].len());
            for k in 0..q {
                let h = ws[i].hash(output_tweak(i, k));
                if h == self.outputs[i][k as usize] {
                    outs.push(k);
                    break;
                }
            }
        }
        debug_assert_eq!(
            ws.len(),
            outs.len(),
            "decoding failed! decoded {} out of {} wires",
            outs.len(),
            ws.len()
        );
        outs
    }
}
