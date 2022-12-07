// -*- mode: rust; -*-
//
// This file is part of `fancy-garbling`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Provides objects and functions for statically garbling and evaluating a
//! circuit without streaming.

use crate::{
    circuit::Circuit,
    errors::{EvaluatorError, GarblerError},
    fancy::HasModulus,
    garble::{Evaluator, Garbler},
    wire::Wire,
};
use itertools::Itertools;
use scuttlebutt::{AbstractChannel, AesRng, Block, Channel};
use std::collections::hash_map::DefaultHasher;
use std::hash::BuildHasherDefault;
use std::{collections::HashMap, convert::TryInto, rc::Rc};

type MyBuildHasher = BuildHasherDefault<DefaultHasher>;

/// Static evaluator for a circuit, created by the `garble` function.
///
/// Uses `Evaluator` under the hood to actually implement the evaluation.
// #[derive(Debug)]
#[cfg_attr(feature = "serde1", derive(serde::Serialize, serde::Deserialize))]
pub struct GarbledCircuit {
    blocks: Vec<Block>,
    // TODO(interstellar) can we remove Circuit; and possibly refactor output_refs/cache/etc
    //  Should we remove Circuit? Does it leak critical data to the client?
    circuit: Circuit,
    /// Only needed for "eval_with_prealloc"
    cache: Vec<Option<Wire>>,
    temp_blocks: Vec<Wire>,
    // default hasher:
    // ---- tests::bench_garble_display_message_640x360_2digits_42 stdout ----
    // eval_times : [65, 60, 56, 55, 56, 57, 58, 58, 57, 59]
    // eval_datas : 10
    // -----------------------------------------------------------------------
    // twox-hash = "1.6.3"
    // use twox_hash::XxHash64;
    // BuildHasherDefault<XxHash64>
    // ---- tests::bench_garble_display_message_640x360_2digits_42 stdout ----
    // eval_times : [82, 67, 66, 67, 66, 64, 66, 67, 65, 65]
    // eval_datas : 10
    // -----------------------------------------------------------------------
    // fnv = "1.0.7"
    // ---- tests::bench_garble_display_message_640x360_2digits_42 stdout ----
    // eval_times : [77, 64, 65, 66, 63, 68, 66, 68, 67, 64]
    // eval_datas : 10
    hashes_cache: HashMap<(Wire, usize, u16), Block, MyBuildHasher>,
}

impl GarbledCircuit {
    /// Create a new object from a vector of garbled gates and constant wires.
    pub fn new(blocks: Vec<Block>, circuit: Circuit) -> Self {
        GarbledCircuit {
            blocks,
            circuit,
            cache: Vec::new(),
            temp_blocks: Vec::new(),
            hashes_cache: HashMap::default(),
        }
    }

    /// The number of garbled rows and constant wires in the garbled circuit.
    pub fn size(&self) -> usize {
        self.blocks.len()
    }

    /// Evaluate the garbled circuit.
    pub fn eval(
        &self,
        garbler_inputs: &[Wire],
        evaluator_inputs: &[Wire],
    ) -> Result<Vec<u16>, EvaluatorError> {
        let reader = GarbledReader::new(&self.blocks);
        let channel = Channel::new(reader, GarbledWriter::new(None));

        let mut evaluator = Evaluator::new(channel);

        let outputs = self
            .circuit
            .eval(&mut evaluator, &garbler_inputs, &evaluator_inputs)?;

        Ok(outputs.expect("evaluator outputs always are Some(u16)"))
    }

    /// Evaluate the garbled circuit.
    pub fn eval_with_prealloc<'garb>(
        &'garb mut self,
        garbler_inputs: &[Wire],
        evaluator_inputs: &[Wire],
        outputs: &mut Vec<Option<u16>>,
    ) -> Result<(), EvaluatorError> {
        let reader = GarbledReader::new(&self.blocks);
        let channel = Channel::new(reader, GarbledWriter::new(None));

        let mut evaluator = Evaluator::new(channel);

        self.circuit.eval_with_prealloc(
            &mut evaluator,
            &garbler_inputs,
            &evaluator_inputs,
            outputs,
            // TODO!!! expect("cache not init! MUST call init_cache()")
            &mut self.cache,
            &mut self.temp_blocks,
            &mut self.hashes_cache,
        )?;

        // eval_prepare_with_prealloc(
        //     &mut evaluator,
        //     garbler_inputs,
        //     evaluator_inputs,
        //     &self.circuit.gates,
        //     &self.circuit.gate_moduli,
        //     &mut self.cache,
        // )?;

        // eval_eval_with_prealloc(
        //     &mut self.cache,
        //     &mut evaluator,
        //     &self.circuit.output_refs,
        //     outputs,
        //     &mut self.temp_blocks,
        //     &mut self.hashes_cache,
        // )?;

        Ok(())
    }

    // TODO(interstellar) remove?
    pub fn init_cache(&mut self) {
        self.cache = vec![None; self.circuit.gates.len()];
        self.temp_blocks = vec![Wire::default(); 2];
        // TODO(interstellar)!!! try different hashers; the default "provide resistance against HashDoS attacks"
        //  but this MAY not be needed
        // NOTE: typically there are around self.circuit.gates.len() / 2 entries in "hashes_cache" after "fn eval_with_prealloc"
        // TODO(interstellar) bne with capacity: self.circuit.gates.len()

        // self.hashes_cache = HashMap::with_capacity_and_hasher(
        //     self.circuit.gates.len(),
        //     BuildHasherDefault::from(RandomXxHashBuilder64::default()),
        // );

        // self.hashes_cache = HashMap
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

    c.eval(&mut garbler, &gb_inps, &ev_inps)?;

    let en = Encoder::new(gb_inps, ev_inps, garbler.get_deltas());

    let blocks = Rc::try_unwrap(channel.writer())
        .unwrap()
        .into_inner()
        .blocks;

    let gc = GarbledCircuit::new(blocks, c);

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
