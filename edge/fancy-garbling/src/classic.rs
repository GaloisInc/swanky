//! Provides objects and functions for statically garbling and evaluating a
//! circuit without streaming.

use crate::{
    WireLabel,
    garble::{Evaluator, Garbler},
    util::output_tweak,
};
use fancy_traits::{Circuit, CircuitInputMapper, CircuitOutputMapper, FancyOutput};
use rand::{CryptoRng, Rng};
use std::collections::HashMap;
use swanky_channel::Channel;
use swanky_error::ErrorKind;
use vectoreyes::U8x16;

/// A garbled circuit.
///
/// A garbled circuit at its core is just a vector of garbled rows and constant
/// wirelabels.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GarbledCircuit {
    blocks: Vec<U8x16>,
}

impl GarbledCircuit {
    /// Create a [`GarbledCircuit`] from a vector of garbled rows and constant
    /// wirelabels.
    pub fn new(blocks: Vec<U8x16>) -> Self {
        GarbledCircuit { blocks }
    }

    /// The number of garbled rows and constant wires in the garbled circuit.
    pub fn size(&self) -> usize {
        self.blocks.len()
    }

    /// Garble a circuit.
    ///
    /// This outputs three things:
    /// 1. An [`Encoder`] for encoding inputs to valid input wirelabels.
    /// 2. The garbled circuit itself.
    /// 3. An [`OutputMapping`] mapping for mapping output wirelabels to their
    ///    associated underlying values.
    pub fn garble<
        Wire: WireLabel,
        C: CircuitInputMapper<Garbler<RNG, Wire>> + CircuitOutputMapper<Garbler<RNG, Wire>>,
        RNG: CryptoRng + Rng,
    >(
        circuit: &C,
        rng: RNG,
    ) -> swanky_error::Result<(Encoder<Wire>, Self, OutputMapping)> {
        let mut garbler = Garbler::new(rng);

        // Produce zero wirelabels for the inputs.
        let inputs = (0..circuit.ninputs())
            .map(|i| {
                let q = circuit.modulus(i);
                garbler.encode_zero(q)
            })
            .collect::<Vec<_>>();

        let mut channel = GarbledChannel::new_writer(None);
        let (en, output_mapping) = Channel::with(&mut channel, |channel| {
            // First, garble the circuit, outputting the zero wirelabels
            // associated with the output.
            let zeros = circuit.execute(&mut garbler, circuit.map(inputs.clone()), channel)?;
            let zeros = C::flatten(zeros);
            // Next, map the zero output wirelabels to the set of valid outputs.
            // This is needed for evaluators that don't use the output
            // mapping provided as output; in that case, we need the channel to
            // contain that mapping, which is what the below does.
            garbler.outputs(&zeros, channel)?;

            let deltas = garbler.get_deltas();
            let en = Encoder::new(inputs, deltas.clone());
            let output_mapping = OutputMapping::new(&zeros, &deltas);

            Ok((en, output_mapping))
        })?;
        let gc = GarbledCircuit::new(channel.finish_writing());
        Ok((en, gc, output_mapping))
    }

    /// Evaluate the garbled circuit on the provided inputs, mapping the output
    /// wirelabels to their associated values.
    pub fn eval<Wire: WireLabel, C: CircuitOutputMapper<Evaluator<Wire>>>(
        &self,
        circuit: &C,
        inputs: C::Input,
        output_mapping: &OutputMapping,
    ) -> swanky_error::Result<Vec<u16>> {
        let wirelabels = self.eval_to_wirelabels(circuit, inputs)?;
        output_mapping.to_outputs(&C::flatten(wirelabels))
    }

    /// Evaluate the garbled circuit on the provided inputs, returning the
    /// output wirelabels.
    pub fn eval_to_wirelabels<Wire: WireLabel, C: Circuit<Evaluator<Wire>>>(
        &self,
        circuit: &C,
        inputs: C::Input,
    ) -> swanky_error::Result<C::Output> {
        let mut evaluator = Evaluator::new();
        Channel::with(GarbledChannel::from(self), |channel| {
            circuit.execute(&mut evaluator, inputs, channel)
        })
    }
}

/// Encoder for input wirelabels.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Encoder<Wire> {
    inputs: Vec<Wire>,
    deltas: HashMap<u16, Wire>,
}

impl<Wire: WireLabel> Encoder<Wire> {
    /// Make a new [`Encoder`] from lists of inputs, alongside a map of
    /// moduli-to-wire-offsets.
    pub fn new(inputs: Vec<Wire>, deltas: HashMap<u16, Wire>) -> Self {
        Encoder { inputs, deltas }
    }

    /// Encode input values into their associated wirelabels.
    ///
    /// # Panics
    /// This panics if `inputs.len()` does not equal the expected number of
    /// garbler inputs.
    pub fn encode_inputs(&self, inputs: &[u16]) -> Vec<Wire> {
        assert_eq!(inputs.len(), self.inputs.len());
        self.inputs
            .iter()
            .zip(inputs)
            .map(|(zero, x)| {
                let q = zero.modulus();
                zero.clone() + self.deltas[&q].clone() * *x
            })
            .collect()
    }
}

/// A mapping of output wirelabels to their associated underlying values.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OutputMapping(Vec<Vec<U8x16>>);

impl OutputMapping {
    /// Construct a new [`OutputMapping`] from a set of zero wirelabels and
    /// their associated deltas.
    pub fn new<Wire: WireLabel>(zeros: &[Wire], deltas: &HashMap<u16, Wire>) -> Self {
        let mut outputs = Vec::with_capacity(zeros.len());
        for (i, zero) in zeros.iter().enumerate() {
            let q = zero.modulus();
            let mut wirelabels = Vec::with_capacity(q as usize);
            for k in 0..q {
                let wirelabel = zero.clone() + deltas[&q].clone() * k;
                let hashed = wirelabel.hash(output_tweak(i, k));
                wirelabels.push(hashed);
            }
            outputs.push(wirelabels);
        }
        Self(outputs)
    }

    /// Map output wirelabels to their underlying values.
    ///
    /// # Errors
    /// This returns an error if it is unable to find a valid mapping for a
    /// given output wirelabel.
    pub fn to_outputs<Wire: WireLabel>(
        &self,
        wirelabels: &[Wire],
    ) -> swanky_error::Result<Vec<u16>> {
        let mut outputs = Vec::new();
        for (i, wirelabel) in wirelabels.iter().enumerate() {
            let q = wirelabel.modulus();
            let mut decoded = None;
            for k in 0..q {
                let hashed = wirelabel.hash(output_tweak(i, k));
                if hashed == self.0[i][k as usize] {
                    decoded = Some(k);
                    break;
                }
            }
            if let Some(output) = decoded {
                outputs.push(output);
            } else {
                swanky_error::bail!(ErrorKind::OtherError, "Decoding failed");
            }
        }
        Ok(outputs)
    }
}

/// Type for writing and reading a garbled circuit from memory.
///
/// A [`GarbledChannel`] provides a way to use the [`Channel`] interface to
/// write a garbled circuit to memory, alongside the ability to read it from
/// memory for evaluation.
///
/// A [`GarbledChannel`] can be instantiated in one of two ways: either by
/// calling [`GarbledChannel::new_writer`] to store the garbled circuit in
/// memory, or [`GarbledChannel::from`] on an existing [`GarbledCircuit`] to
/// evaluate the garbled circuit.
///
/// Note that a [`GarbledChannel`] cannot be both a writer and a reader. For
/// example, calling [`GarbledChannel::finish_writing`] on a [`GarbledChannel`]
/// reader results in a panic.
pub struct GarbledChannel {
    reader: Option<GarbledReader>,
    writer: Option<GarbledWriter>,
}

impl GarbledChannel {
    /// Construct a new [`GarbledChannel`] for writing a garbled circuit.
    pub fn new_writer(ngates: Option<usize>) -> Self {
        Self {
            reader: None,
            writer: Some(GarbledWriter::new(ngates)),
        }
    }

    /// Consume the [`GarbledChannel`], outputting the resulting garbled circuit.
    ///
    /// # Panics
    /// Panics if there is no valid writer for the [`GarbledChannel`].
    pub fn finish_writing(self) -> Vec<U8x16> {
        self.writer.unwrap().finish()
    }
}

impl std::io::Read for GarbledChannel {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let reader = self.reader.as_mut().unwrap();
        reader.read(buf)
    }
}

impl std::io::Write for GarbledChannel {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let writer = self.writer.as_mut().unwrap();
        writer.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let writer = self.writer.as_mut().unwrap();
        writer.flush()
    }
}

impl From<&GarbledCircuit> for GarbledChannel {
    fn from(value: &GarbledCircuit) -> Self {
        Self {
            reader: Some(GarbledReader::new(&value.blocks)),
            writer: None,
        }
    }
}

/// Implementation of the `Read` trait for use by the `Evaluator`.
#[derive(Debug)]
struct GarbledReader {
    blocks: Vec<U8x16>,
    index: usize,
}

impl GarbledReader {
    fn new(blocks: &[U8x16]) -> Self {
        Self {
            blocks: blocks.to_vec(),
            index: 0,
        }
    }
}

impl std::io::Read for GarbledReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        assert_eq!(buf.len() % 16, 0);
        let start = self.index;
        for data in buf.chunks_mut(16) {
            let block: [u8; 16] = self.blocks[self.index].into();
            for (a, b) in data.iter_mut().zip(block.iter()) {
                *a = *b;
            }
            self.index += 1;
            if self.index == self.blocks.len() {
                // We've read all that we can from the vector of `Block`s, so
                // return the length of bytes that we've read to satisfy the
                // `read` API.
                return Ok(16 * (self.index - start));
            }
        }
        Ok(buf.len())
    }
}

/// Implementation of the `Write` trait for use by `Garbler`.
#[derive(Debug)]
struct GarbledWriter {
    blocks: Vec<U8x16>,
}

impl GarbledWriter {
    /// Make a new [`GarbledWriter`].
    fn new(ngates: Option<usize>) -> Self {
        let blocks = if let Some(n) = ngates {
            Vec::with_capacity(2 * n)
        } else {
            Vec::new()
        };
        Self { blocks }
    }

    /// Consume the [`GarbledWriter`], outputting the resulting garbled circuit.
    fn finish(self) -> Vec<U8x16> {
        self.blocks
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
            self.blocks.push(bytes.into());
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
