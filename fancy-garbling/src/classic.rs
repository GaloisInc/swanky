// -*- mode: rust; -*-
//
// This file is part of `fancy-garbling`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Provides objects and functions for statically garbling and evaluating a
//! circuit without streaming.

use crate::{
    circuit::{eval_eval, eval_prepare, Circuit, CircuitRef, Gate},
    errors::{EvaluatorError, GarblerError},
    fancy::HasModulus,
    garble::{Evaluator, Garbler},
    wire::Wire,
};
use itertools::Itertools;
use scuttlebutt::{AbstractChannel, AesRng, Block, Channel};
use std::{collections::HashMap, convert::TryInto, rc::Rc};

/// Static evaluator for a circuit, created by the `garble` function.
///
/// Uses `Evaluator` under the hood to actually implement the evaluation.
// #[derive(Debug)]
#[cfg_attr(feature = "serde1", derive(serde::Serialize, serde::Deserialize))]
pub struct GarbledCircuit {
    blocks: Vec<Block>,
    // TODO(interstellar) remove Circuit; and possibly refactor output_refs/cache/etc
    // TODO(interstellar) are Evaluator and output_refs OK to be kept around? are they serializable?
    output_refs: Vec<CircuitRef>,
    cache: Vec<Option<Wire>>,
    // This fields allows calling "eval" repeatedly on the same GarbledCircuit(Evaluator)
    // Without it, it fails with eg "panicked at 'index out of bounds: the len is 12 but the index is 12'"
    reader_index: usize,
    evaluator_current_gate: usize,
}

impl GarbledCircuit {
    /// Create a new object from a vector of garbled gates and constant wires.
    pub fn new(
        blocks: Vec<Block>,
        output_refs: Vec<CircuitRef>,
        cache: Vec<Option<Wire>>,
        reader_index: usize,
        evaluator_current_gate: usize,
    ) -> Self {
        GarbledCircuit {
            blocks,
            output_refs,
            cache,
            reader_index,
            evaluator_current_gate,
        }
    }

    /// The number of garbled rows and constant wires in the garbled circuit.
    pub fn size(&self) -> usize {
        self.blocks.len()
    }

    /// Evaluate the garbled circuit.
    pub fn eval(
        &mut self,
        garbler_inputs: &[Wire],
        evaluator_inputs: &[Wire],
    ) -> Result<Vec<u16>, EvaluatorError> {
        let reader = GarbledReader::new_with_index(&self.blocks, self.reader_index);
        let channel = Channel::new(reader, GarbledWriter::new(None));

        let mut evaluator = Evaluator::new_with_current_gate(channel, self.evaluator_current_gate);

        // We MUST set garbler_inputs/evaluator_inputs to their correct values.
        // This is what "fn eval_prepare" is doing.
        for (i, garbler_input_wire) in garbler_inputs.iter().enumerate() {
            self.cache[i] = Some(garbler_input_wire.clone());
        }
        for (i, evaluator_input_wire) in evaluator_inputs.iter().enumerate() {
            self.cache[i] = Some(evaluator_input_wire.clone());
        }

        let outputs = eval_eval(&self.cache, &mut evaluator, &self.output_refs)?;

        Ok(outputs.expect("evaluator outputs always are Some(u16)"))
    }
}

/// Garble a circuit without streaming.
pub fn garble(c: Circuit) -> Result<(Encoder, GarbledCircuit), GarblerError> {
    let channel = Channel::new(
        GarbledReader::new(&[]),
        GarbledWriter::new(Some(c.num_nonfree_gates)),
    );
    let channel_ = channel.clone();

    let rng = AesRng::new();
    let mut garbler = Garbler::new(channel_, rng);

    // get input wires, ignoring encoded values
    let gb_inps = (0..c.num_garbler_inputs())
        .map(|i| {
            let q = c.garbler_input_mod(i);
            let (zero, _) = garbler.encode_wire(0, q);
            zero
        })
        .collect_vec();

    let ev_inps = (0..c.num_evaluator_inputs())
        .map(|i| {
            let q = c.evaluator_input_mod(i);
            let (zero, _) = garbler.encode_wire(0, q);
            zero
        })
        .collect_vec();

    let cache = eval_prepare(&mut garbler, &gb_inps, &ev_inps, &c.gates, &c.gate_moduli)?;
    eval_eval(&cache, &mut garbler, &c.output_refs)?;

    let en = Encoder::new(gb_inps, ev_inps, garbler.get_deltas());

    let blocks = Rc::try_unwrap(channel.writer())
        .unwrap()
        .into_inner()
        .blocks;

    // BEGIN BLOCK
    // TODO(interstellar) how to prepare "generic inputs" at this stage??? We DO NOT want to set them in stone now!

    let channel = Channel::new(GarbledReader::new(&blocks), GarbledWriter::new(None));
    let mut evaluator = Evaluator::new(channel);

    let evaluator_inputs = vec![1; c.num_evaluator_inputs()];
    let evaluator_inputs = &en.encode_evaluator_inputs(&evaluator_inputs);
    let garbler_inputs = vec![0; c.num_garbler_inputs()];
    let garbler_inputs = &en.encode_garbler_inputs(&garbler_inputs);

    let cache2 = eval_prepare(
        &mut evaluator,
        &garbler_inputs,
        &evaluator_inputs,
        &c.gates,
        &c.gate_moduli,
    )
    .unwrap();

    // TODO(interstellar) pass map_garbler_inputs_id_to_gate_id+map_evaluator_input_id_to_gate_id to GarbledCircuit::new
    //  and use them during "fn eval"
    let mut map_garbler_inputs_id_to_gate_id = vec![None; c.num_garbler_inputs()];
    let mut map_evaluator_input_id_to_gate_id = vec![None; c.num_evaluator_inputs()];
    for (i, gate) in c.gates.iter().enumerate() {
        match *gate {
            Gate::GarblerInput { id } => {
                map_garbler_inputs_id_to_gate_id[i] = Some(id);
            }
            Gate::EvaluatorInput { id } => {
                map_evaluator_input_id_to_gate_id[i] = Some(id);
            }
            _ => {}
        };
    }

    // END BLOCK

    // TODO(interstellar) modify Swanky API to get "index" properly
    let reader: &GarbledReader = unsafe { &(*evaluator.get_channel_ref().reader_ptr()) };

    let gc = GarbledCircuit::new(
        blocks,
        c.output_refs,
        cache2,
        reader.index,
        evaluator.get_current_gate(),
    );

    Ok((en, gc))
}

////////////////////////////////////////////////////////////////////////////////
// Encoder

/// Encode inputs statically.
#[derive(Debug)]
#[cfg_attr(feature = "serde1", derive(serde::Serialize, serde::Deserialize))]
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
// Reader and Writer impls for simple local structures to collect and release blocks

/// Implementation of the `Read` trait for use by the `Evaluator`.
#[derive(Debug)]
pub struct GarbledReader {
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

    fn new_with_index(blocks: &[Block], index: usize) -> Self {
        Self {
            blocks: blocks.to_vec(),
            index: index,
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
