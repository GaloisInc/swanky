use crate::circuit::{Circuit, Gate};
use crate::fancy::{Fancy, HasModulus};
use crate::util::{tweak2, output_tweak};
use crate::wire::Wire;
use itertools::Itertools;
use serde_derive::{Serialize, Deserialize};
use std::collections::HashMap;
use std::ops::DerefMut;
use std::sync::{Arc, Mutex};

use super::{Message, GarbledGate, OutputCiphertext};

/// Streaming evaluator using a callback to recieve ciphertexts as needed.
///
/// Evaluates a garbled circuit on the fly, using messages containing ciphertexts and
/// wires.
pub struct Evaluator {
    recv_function:  Arc<Mutex<Box<FnMut() -> Message + Send>>>,
    constants: HashMap<(u16,u16),Wire>,
    current_gate: usize,
    output_ciphertexts: Vec<OutputCiphertext>,
    output_wires: Vec<Wire>,
}

impl Evaluator {
    /// Create a new Evaluator.
    ///
    /// `recv_function` enables streaming by producing messages during the `Fancy`
    /// computation, which contain ciphertexts and wirelabels.
    pub fn new(recv_function: Box<FnMut() -> Message + Send>) -> Evaluator {
        Evaluator {
            recv_function: Arc::new(Mutex::new(recv_function)),
            constants: HashMap::new(),
            current_gate: 0,
            output_ciphertexts: Vec::new(),
            output_wires: Vec::new(),
        }
    }

    /// Recieve the next message.
    fn recv(&self) -> Message {
        (self.recv_function.lock().unwrap().deref_mut())()
    }

    /// The current nonfree gate index of the garbling computation.
    fn current_gate(&mut self) -> usize {
        let c = self.current_gate;
        self.current_gate += 1;
        c
    }

    /// Decode the output recieved during the Fancy computation.
    pub fn decode_output(self) -> Vec<u16> {
        Decoder::new(self.output_ciphertexts).decode(&self.output_wires)
    }
}

// TODO: error handling here, by changing `type Wire = Result<Error, Wire>`?
impl Fancy for Evaluator {
    type Item = Wire;

    fn garbler_input(&mut self, _q: u16) -> Wire { //{{{
        match self.recv() {
            Message::GarblerInput(w) => w,
            m => panic!("Expected message GarblerInput but got {}", m),
        }
    }
    //}}}
    fn evaluator_input(&mut self, _q: u16) -> Wire { //{{{
        match self.recv() {
            Message::EvaluatorInput(w) => w,
            m => panic!("Expected message EvaluatorInput but got {}", m),
        }
    }
    //}}}
    fn constant(&mut self, x: u16, q: u16) -> Wire { //{{{
        if self.constants.contains_key(&(x,q)) {
            return self.constants[&(x,q)].clone();
        }
        let w = match self.recv() {
            Message::Constant { wire, .. } => wire,
            m => panic!("Expected message Constant but got {}", m),
        };
        self.constants.insert((x,q),w.clone());
        w
    }
    //}}}
    fn add(&mut self, x: &Wire, y: &Wire) -> Wire { //{{{
        x.plus(y)
    }
    //}}}
    fn sub(&mut self, x: &Wire, y: &Wire) -> Wire { //{{{
        x.minus(y)
    }
    //}}}
    fn cmul(&mut self, x: &Wire, c: u16) -> Wire { //{{{
        x.cmul(c)
    }
    //}}}
    fn mul(&mut self, A: &Wire, B: &Wire) -> Wire { //{{{
        if A.modulus() < A.modulus() {
            return self.mul(B,A);
        }

        let gate = match self.recv() {
            Message::GarbledGate(g) => g,
            m => panic!("Expected message GarbledGate but got {}", m),
        };
        let gate_num = self.current_gate();
        let g = tweak2(gate_num as u64, 0);
        let q = A.modulus();

        // garbler's half gate
        let L = if A.color() == 0 {
            A.hashback(g,q)
        } else {
            let ct_left = gate[A.color() as usize - 1];
            Wire::from_u128(ct_left ^ A.hash(g), q)
        };

        // evaluator's half gate
        let R = if B.color() == 0 {
            B.hashback(g,q)
        } else {
            let ct_right = gate[(q + B.color()) as usize - 2];
            Wire::from_u128(ct_right ^ B.hash(g), q)
        };

        // hack for unequal mods
        let new_b_color = if A.modulus() != B.modulus() {
            let minitable = *gate.last().unwrap();
            let ct = minitable >> (B.color() * 16);
            let pt = B.hash(tweak2(gate_num as u64, 1)) ^ ct;
            pt as u16
        } else {
            B.color()
        };

        L.plus(&R.plus(&A.cmul(new_b_color)))
    }
    //}}}
    fn proj(&mut self, x: &Wire, q: u16, _tt: &[u16]) -> Wire { //{{{
        let gate = match self.recv() {
            Message::GarbledGate(g) => g,
            m => panic!("Expected message GarbledGate but got {}", m),
        };
        let gate_num = self.current_gate();
        let w = if x.color() == 0 {
            x.hashback(gate_num as u128, q)
        } else {
            let ct = gate[x.color() as usize - 1];
            Wire::from_u128(ct ^ x.hash(gate_num as u128), q)
        };
        w
    }
    //}}}
    fn output(&mut self, x: &Wire) { //{{{
        match self.recv() {
            Message::OutputCiphertext(c) => self.output_ciphertexts.push(c),
            m => panic!("Expected message OutputCiphertext but got {}", m),
        }
        self.output_wires.push(x.clone());
    }
    //}}}
}
////////////////////////////////////////////////////////////////////////////////
// static evaluator

/// Static evaluator for a circuit, created by the `garble` function.
///
/// Uses `Evaluator` under the hood to actually implement the evaluation.
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct GarbledCircuit {
    gates  : Vec<GarbledGate>,
    consts : HashMap<(u16,u16),Wire>,
}

impl GarbledCircuit {
    /// Create a new GarbledCircuit from a vec of garbled gates and constant wires.
    pub fn new(gates: Vec<GarbledGate>, consts: HashMap<(u16,u16),Wire>) -> Self {
        GarbledCircuit { gates, consts }
    }

    /// The number of 128 bit ciphertexts and constant wires in the garbled circuit.
    pub fn size(&self) -> usize {
        let mut c = self.consts.len();
        for g in self.gates.iter() {
            c += g.len();
        }
        c
    }

    /// Evaluate the garbled circuit.
    pub fn eval(&self, c: &Circuit, garbler_inputs: &[Wire], evaluator_inputs: &[Wire]) -> Vec<Wire> {
        // create a message iterator to pass as the Evaluator recv function
        let mut msgs = c.gates.iter().enumerate().filter_map(|(i,gate)| {
            let q = c.modulus(i);
            match *gate {
                Gate::GarblerInput { id }   => Some(Message::GarblerInput(garbler_inputs[id].clone())),
                Gate::EvaluatorInput { id } => Some(Message::EvaluatorInput(evaluator_inputs[id].clone())),
                Gate::Constant { val }      => Some(Message::Constant { value: val, wire: self.consts[&(val,q)].clone() }),
                Gate::Mul { id, .. }        => Some(Message::GarbledGate(self.gates[id].clone())),
                Gate::Proj { id, .. }       => Some(Message::GarbledGate(self.gates[id].clone())),
                _ => None,
            }
        }).collect_vec().into_iter();

        let mut eval = Evaluator::new(Box::new(move || msgs.next().unwrap()));

        let mut wires: Vec<Wire> = Vec::new();
        for (i,gate) in c.gates.iter().enumerate() {
            let q = c.modulus(i);
            let w = match *gate {
                Gate::GarblerInput { .. }    => eval.garbler_input(q),
                Gate::EvaluatorInput { .. }  => eval.evaluator_input(q),
                Gate::Constant { val }       => eval.constant(val, q),
                Gate::Add { xref, yref }     => wires[xref.ix].plus(&wires[yref.ix]),
                Gate::Sub { xref, yref }     => wires[xref.ix].minus(&wires[yref.ix]),
                Gate::Cmul { xref, c }       => wires[xref.ix].cmul(c),
                Gate::Proj { xref, .. }      => eval.proj(&wires[xref.ix], q, &[]),
                Gate::Mul { xref, yref, .. } => eval.mul(&wires[xref.ix], &wires[yref.ix]),
            };
            wires.push(w);
        }

        c.output_refs.iter().map(|&r| {
            wires[r.ix].clone()
        }).collect()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("couldn't serialize Evaluator")
    }

    pub fn from_bytes(bs: &[u8]) -> Result<Self, failure::Error> {
        bincode::deserialize(bs)
            .map_err(|_| failure::err_msg("error decoding Evaluator from bytes"))
    }
}

////////////////////////////////////////////////////////////////////////////////
// Encoder

/// Encode inputs statically.
///
/// Created by the `garble` function.
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Encoder {
    garbler_inputs : Vec<Wire>,
    evaluator_inputs : Vec<Wire>,
    deltas : HashMap<u16,Wire>,
}

impl Encoder {
    pub fn new(garbler_inputs: Vec<Wire>, evaluator_inputs: Vec<Wire>, deltas: HashMap<u16,Wire>) -> Self {
        Encoder { garbler_inputs, evaluator_inputs, deltas }
    }

    pub fn num_garbler_inputs(&self) -> usize {
        self.garbler_inputs.len()
    }

    pub fn num_evaluator_inputs(&self) -> usize {
        self.evaluator_inputs.len()
    }

    pub fn encode_garbler_input(&self, x: u16, id: usize) -> Wire {
        let X = &self.garbler_inputs[id];
        let q = X.modulus();
        X.plus(&self.deltas[&q].cmul(x))
    }

    pub fn encode_evaluator_input(&self, x: u16, id: usize) -> Wire {
        let X = &self.evaluator_inputs[id];
        let q = X.modulus();
        X.plus(&self.deltas[&q].cmul(x))
    }

    pub fn encode_garbler_inputs(&self, inputs: &[u16]) -> Vec<Wire> {
        debug_assert_eq!(inputs.len(), self.garbler_inputs.len());
        (0..inputs.len()).zip(inputs).map(|(id,&x)| {
            self.encode_garbler_input(x,id)
        }).collect()
    }

    pub fn encode_evaluator_inputs(&self, inputs: &[u16]) -> Vec<Wire> {
        debug_assert_eq!(inputs.len(), self.evaluator_inputs.len());
        (0..inputs.len()).zip(inputs).map(|(id,&x)| {
            self.encode_evaluator_input(x,id)
        }).collect()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("couldn't serialize Encoder")
    }

    pub fn from_bytes(bs: &[u8]) -> Result<Self, failure::Error> {
        bincode::deserialize(bs)
            .map_err(|_| failure::err_msg("error decoding Encoder from bytes"))
    }
}

////////////////////////////////////////////////////////////////////////////////
// Decoder

/// Decode outputs.
///
/// Created by the `garble` function.
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Decoder {
    outputs : Vec<OutputCiphertext>,
}

impl Decoder {
    pub fn new(outputs: Vec<Vec<u128>>) -> Self {
        Decoder { outputs }
    }

    pub fn decode(&self, ws: &[Wire]) -> Vec<u16> {
        debug_assert_eq!(ws.len(), self.outputs.len());
        let mut outs = Vec::new();
        for i in 0..ws.len() {
            let q = ws[i].modulus();
            for k in 0..q {
                let h = ws[i].hash(output_tweak(i,k));
                if h == self.outputs[i][k as usize] {
                    outs.push(k);
                    break;
                }
            }
        }
        debug_assert_eq!(ws.len(), outs.len(), "decoding failed");
        outs
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("couldn't serialize Decoder")
    }

    pub fn from_bytes(bs: &[u8]) -> Result<Self, failure::Error> {
        bincode::deserialize(bs)
            .map_err(|_| failure::err_msg("error decoding Decoder from bytes"))
    }
}

