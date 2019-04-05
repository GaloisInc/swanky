use super::{GarbledGate, OutputCiphertext};
use crate::circuit::{Circuit, Gate};
use crate::error::{EvaluatorError, FancyError};
use crate::fancy::{Fancy, HasModulus};
use crate::util::{output_tweak, tweak, tweak2};
use crate::wire::Wire;
use scuttlebutt::Block;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Streaming evaluator using a callback to receive ciphertexts as needed.
///
/// Evaluates a garbled circuit on the fly, using messages containing ciphertexts and
/// wires. Parallelizable.
pub struct Evaluator {
    callback: Box<FnMut(usize) -> Result<Vec<Block>, EvaluatorError> + Send + Sync>,
    current_gate: usize,
    output_cts: Vec<OutputCiphertext>,
    output_wires: Vec<Wire>,
}

impl Evaluator {
    /// Create a new `Evaluator`.
    ///
    /// `callback` enables streaming by producing messages during the `Fancy`
    /// computation, which contain ciphertexts and wire-labels.
    pub fn new<F>(callback: F) -> Evaluator
    where
        F: FnMut(usize) -> Result<Vec<Block>, EvaluatorError> + Send + Sync + 'static,
    {
        Evaluator {
            callback: Box::new(callback),
            current_gate: 0,
            output_cts: Vec::new(),
            output_wires: Vec::new(),
        }
    }

    /// Decode the output received during the Fancy computation.
    pub fn decode_output(&self) -> Vec<u16> {
        Decoder::new(self.output_cts.clone()).decode(&self.output_wires)
    }

    #[inline]
    fn recv_wire(&mut self, q: u16) -> Result<Wire, EvaluatorError> {
        let blocks = (self.callback)(1)?;
        Ok(Wire::from_block(blocks[0], q))
    }

    #[inline]
    fn recv_gate(&mut self, ngates: usize) -> Result<GarbledGate, EvaluatorError> {
        let blocks = (self.callback)(ngates)?;
        Ok(blocks)
    }

    #[inline]
    fn recv_outputs(&mut self, noutputs: usize) -> Result<OutputCiphertext, EvaluatorError> {
        let blocks = (self.callback)(noutputs)?;
        Ok(blocks)
    }

    /// The current non-free gate index of the garbling computation.
    #[inline]
    fn current_gate(&mut self) -> usize {
        let current = self.current_gate;
        self.current_gate += 1;
        current
    }
}

impl Fancy for Evaluator {
    type Item = Wire;
    type Error = EvaluatorError;

    #[inline]
    fn garbler_input(&mut self, q: u16, _: Option<u16>) -> Result<Wire, EvaluatorError> {
        self.recv_wire(q)
    }
    #[inline]
    fn evaluator_input(&mut self, q: u16) -> Result<Wire, EvaluatorError> {
        self.recv_wire(q)
    }
    #[inline]
    fn constant(&mut self, _: u16, q: u16) -> Result<Wire, EvaluatorError> {
        self.recv_wire(q)
    }
    #[inline]
    fn add(&mut self, x: &Wire, y: &Wire) -> Result<Wire, EvaluatorError> {
        if x.modulus() != y.modulus() {
            return Err(EvaluatorError::FancyError(FancyError::UnequalModuli));
        }
        Ok(x.plus(y))
    }
    #[inline]
    fn sub(&mut self, x: &Wire, y: &Wire) -> Result<Wire, EvaluatorError> {
        if x.modulus() != y.modulus() {
            return Err(EvaluatorError::FancyError(FancyError::UnequalModuli));
        }
        Ok(x.minus(y))
    }
    #[inline]
    fn cmul(&mut self, x: &Wire, c: u16) -> Result<Wire, EvaluatorError> {
        Ok(x.cmul(c))
    }
    #[inline]
    fn mul(&mut self, A: &Wire, B: &Wire) -> Result<Wire, EvaluatorError> {
        if A.modulus() < A.modulus() {
            return self.mul(B, A);
        }
        let q = A.modulus();
        let qb = B.modulus();
        let unequal = A.modulus() != B.modulus();
        let gate = self.recv_gate(q as usize + qb as usize - 2 + unequal as usize)?;
        let gate_num = self.current_gate();
        let g = tweak2(gate_num as u64, 0);

        // garbler's half gate
        let L = if A.color() == 0 {
            A.hashback(g, q)
        } else {
            let ct_left = gate[A.color() as usize - 1];
            Wire::from_block(ct_left ^ A.hash(g), q)
        };

        // evaluator's half gate
        let R = if B.color() == 0 {
            B.hashback(g, q)
        } else {
            let ct_right = gate[(q + B.color()) as usize - 2];
            Wire::from_block(ct_right ^ B.hash(g), q)
        };

        // hack for unequal mods
        let new_b_color = if unequal {
            let minitable = *gate.last().unwrap();
            let ct = u128::from(minitable) >> (B.color() * 16);
            let pt = u128::from(B.hash(tweak2(gate_num as u64, 1))) ^ ct;
            pt as u16
        } else {
            B.color()
        };

        let res = L.plus_mov(&R.plus_mov(&A.cmul(new_b_color)));
        Ok(res)
    }
    #[inline]
    fn proj(&mut self, x: &Wire, q: u16, _tt: Option<Vec<u16>>) -> Result<Wire, EvaluatorError> {
        let ngates = (x.modulus() - 1) as usize;
        let gate = self.recv_gate(ngates)?;
        let t = tweak(self.current_gate());
        if x.color() == 0 {
            Ok(x.hashback(t, q))
        } else {
            let ct = gate[x.color() as usize - 1];
            Ok(Wire::from_block(ct ^ x.hash(t), q))
        }
    }
    #[inline]
    fn output(&mut self, x: &Wire) -> Result<(), EvaluatorError> {
        let noutputs = x.modulus() as usize;
        let cts = self.recv_outputs(noutputs)?;
        self.output_cts.push(cts);
        self.output_wires.push(x.clone());
        Ok(())
    }
}

////////////////////////////////////////////////////////////////////////////////
// static evaluator

/// Static evaluator for a circuit, created by the `garble` function.
///
/// Uses `Evaluator` under the hood to actually implement the evaluation.
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct GarbledCircuit {
    gates: Vec<GarbledGate>,
    consts: HashMap<(u16, u16), Wire>,
}

impl GarbledCircuit {
    /// Create a new object from a vector of garbled gates and constant wires.
    pub fn new(gates: Vec<GarbledGate>, consts: HashMap<(u16, u16), Wire>) -> Self {
        GarbledCircuit { gates, consts }
    }

    /// The number of garbled rows and constant wires in the garbled circuit.
    #[inline]
    pub fn size(&self) -> usize {
        self.gates
            .iter()
            .fold(self.consts.len(), |acc, g| acc + g.len())
    }

    /// Evaluate the garbled circuit.
    pub fn eval(
        &self,
        c: &mut Circuit,
        garbler_inputs: &[Wire],
        evaluator_inputs: &[Wire],
    ) -> Result<Vec<Wire>, EvaluatorError> {
        // create a message iterator to pass as the Evaluator recv function
        let mut msgs = c
            .gates
            .iter()
            .enumerate()
            .filter_map(|(i, gate)| match *gate {
                Gate::GarblerInput { id } => Some(vec![garbler_inputs[id].as_block()]),
                Gate::EvaluatorInput { id } => Some(vec![evaluator_inputs[id].as_block()]),
                Gate::Constant { val } => Some(vec![self.consts[&(val, c.modulus(i))].as_block()]),
                Gate::Mul { id, .. } => Some(self.gates[id].clone()),
                Gate::Proj { id, .. } => Some(self.gates[id].clone()),
                _ => None,
            })
            .collect::<Vec<Vec<Block>>>()
            .into_iter();
        let mut eval = Evaluator::new(move |_| Ok(msgs.next().unwrap()));
        c.eval(&mut eval)
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
    outputs: Vec<OutputCiphertext>,
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

        let mut outs = Vec::new();
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

////////////////////////////////////////////////////////////////////////////////
// tests

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn evaluator_has_send_and_sync() {
        fn check_send(_: impl Send) {}
        // fn check_sync(_: impl Sync) {}
        check_send(Evaluator::new(|_| unimplemented!()));
        // check_sync(Evaluator::new(|_| unimplemented!()));
    }
}
