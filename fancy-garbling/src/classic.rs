//! Provides objects and functions for statically garbling and evaluating a
//! circuit without streaming.

use crate::{
    circuit::EvaluableCircuit,
    errors::{EvaluatorError, GarblerError},
    garble::{Evaluator, Garbler},
    WireLabel,
};
use itertools::Itertools;
use scuttlebutt::{AbstractChannel, AesRng, Block, Channel};
use std::{collections::HashMap, marker::PhantomData, rc::Rc};

/// Static evaluator for a circuit, created by the `garble` function.
///
/// Uses `Evaluator` under the hood to actually implement the evaluation.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GarbledCircuit<W, C> {
    blocks: Vec<Block>,
    _phantom_wire: PhantomData<W>,
    _phantom_circ: PhantomData<C>,
}

impl<W, C> GarbledCircuit<W, C> {
    /// Create a new object from a vector of garbled gates and constant wires.
    pub fn new(blocks: Vec<Block>) -> Self {
        GarbledCircuit {
            blocks,
            _phantom_wire: PhantomData,
            _phantom_circ: PhantomData,
        }
    }

    /// The number of garbled rows and constant wires in the garbled circuit.
    pub fn size(&self) -> usize {
        self.blocks.len()
    }
}

type Ev<Wire> = Evaluator<Channel<GarbledReader, GarbledWriter>, Wire>;
type Gb<Wire> = Garbler<Channel<GarbledReader, GarbledWriter>, AesRng, Wire>;

impl<Wire: WireLabel, Circuit: EvaluableCircuit<Ev<Wire>>> GarbledCircuit<Wire, Circuit> {
    /// Evaluate the garbled circuit.
    pub fn eval(
        &self,
        c: &Circuit,
        garbler_inputs: &[Wire],
        evaluator_inputs: &[Wire],
    ) -> Result<Vec<u16>, EvaluatorError> {
        let channel = Channel::new(GarbledReader::new(&self.blocks), GarbledWriter::new(None));
        let mut evaluator = Evaluator::new(channel);
        let outputs = c.eval(&mut evaluator, garbler_inputs, evaluator_inputs)?;
        Ok(outputs.expect("evaluator outputs always are Some(u16)"))
    }
}

/// Garble a circuit without streaming.
pub fn garble<Wire: WireLabel, Circuit: EvaluableCircuit<Gb<Wire>>>(
    c: &Circuit,
) -> Result<(Encoder<Wire>, GarbledCircuit<Wire, Circuit>), GarblerError> {
    let channel = Channel::new(
        GarbledReader::new(&[]),
        GarbledWriter::new(Some(c.get_num_nonfree_gates())),
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

    let gc = GarbledCircuit::new(
        Rc::try_unwrap(channel.writer())
            .unwrap()
            .into_inner()
            .blocks,
    );

    Ok((en, gc))
}

////////////////////////////////////////////////////////////////////////////////
// Encoder

/// Encode inputs statically.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Encoder<Wire> {
    garbler_inputs: Vec<Wire>,
    evaluator_inputs: Vec<Wire>,
    deltas: HashMap<u16, Wire>,
}

impl<Wire: WireLabel> Encoder<Wire> {
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
