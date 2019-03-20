use crossbeam::queue::SegQueue;
use itertools::Itertools;
use serde::{Deserialize, Serialize};

use std::collections::{HashMap, VecDeque};
use std::ops::DerefMut;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex, RwLock};

use crate::circuit::{Circuit, Gate};
use crate::error::{EvaluatorError, FancyError, SyncError};
use crate::fancy::{Fancy, HasModulus, SyncIndex};
use crate::util::{output_tweak, tweak2};
use crate::wire::Wire;

use super::{GarbledGate, Message, OutputCiphertext, SyncInfo};

/// Streaming evaluator using a callback to receive ciphertexts as needed.
///
/// Evaluates a garbled circuit on the fly, using messages containing ciphertexts and
/// wires. Parallelizable.
pub struct Evaluator {
    recv_function: Arc<Mutex<FnMut() -> (Option<SyncIndex>, Message) + Send>>,
    current_gate: Arc<AtomicUsize>,
    output_cts: Arc<Mutex<Vec<OutputCiphertext>>>,
    output_wires: Arc<Mutex<Vec<Wire>>>,
    sync_info: Arc<RwLock<Option<SyncInfo>>>,
    requests: Arc<RwLock<Option<Vec<SegQueue<Sender<Message>>>>>>,
}

impl Evaluator {
    /// Create a new Evaluator.
    ///
    /// `recv_function` enables streaming by producing messages during the `Fancy`
    /// computation, which contain ciphertexts and wirelabels.
    pub fn new<F>(recv_function: F) -> Evaluator
    where
        F: FnMut() -> (Option<SyncIndex>, Message) + Send + 'static,
    {
        Evaluator {
            recv_function: Arc::new(Mutex::new(recv_function)),
            current_gate: Arc::new(AtomicUsize::new(0)),
            output_cts: Arc::new(Mutex::new(Vec::new())),
            output_wires: Arc::new(Mutex::new(Vec::new())),
            sync_info: Arc::new(RwLock::new(None)),
            requests: Arc::new(RwLock::new(None)),
        }
    }

    /// Decode the output received during the Fancy computation.
    pub fn decode_output(&self) -> Vec<u16> {
        let cts = self.output_cts.lock().unwrap();
        let outs = self.output_wires.lock().unwrap();
        Decoder::new(cts.clone()).decode(&outs)
    }

    /// Receive the next message.
    fn recv(&self, ix: Option<SyncIndex>) -> Result<Message, EvaluatorError> {
        if let Some(ix) = ix {
            // request next message for this index
            let (tx, rx) = std::sync::mpsc::channel();
            self.requests.read().unwrap().as_ref().unwrap()[ix as usize].push(tx);
            // block until postman delivers message
            Ok(rx.recv().unwrap())
        } else {
            let (ix, m) = (self.recv_function.lock().unwrap().deref_mut())();
            if m == Message::EndSync {
                return self.recv(ix);
            }
            if ix.is_some() {
                Err(EvaluatorError::IndexReceivedInSyncMode)?;
            }
            Ok(m)
        }
    }

    fn internal_begin_sync(
        &self,
        num_indices: SyncIndex,
    ) -> Result<(), FancyError<EvaluatorError>> {
        let mut opt_info = self.sync_info.write().unwrap();
        if opt_info.is_some() {
            Err(EvaluatorError::from(SyncError::SyncStartedInSync))?;
        }
        *opt_info = Some(SyncInfo::new(
            self.current_gate.load(Ordering::SeqCst),
            num_indices,
        ));
        *self.requests.write().unwrap() =
            Some((0..num_indices).map(|_| SegQueue::new()).collect_vec());
        start_postman(
            num_indices,
            self.sync_info.clone(),
            self.requests.clone(),
            self.recv_function.clone(),
        );
        Ok(())
    }

    fn internal_finish_index(&self, index: SyncIndex) {
        let mut done = false;
        if let Some(ref info) = *self.sync_info.read().unwrap() {
            info.index_done[index as usize].store(true, Ordering::SeqCst);
            if info.index_done.iter().all(|x| x.load(Ordering::SeqCst)) {
                done = true;
            }
        }
        if done {
            *self.sync_info.write().unwrap() = None;
            *self.requests.write().unwrap() = None;
            self.current_gate.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// The current non-free gate index of the garbling computation. Respects sync
    /// ordering. Must agree with Garbler hence compute_gate_id is in the parent mod.
    fn current_gate(&self, sync_index: Option<SyncIndex>) -> usize {
        super::compute_gate_id(
            &self.current_gate,
            sync_index,
            &*self.sync_info.read().unwrap(),
        )
    }
}

fn start_postman(
    nindices: SyncIndex,
    sync_info: Arc<RwLock<Option<SyncInfo>>>,
    requests: Arc<RwLock<Option<Vec<SegQueue<Sender<Message>>>>>>,
    recv_msg: Arc<Mutex<FnMut() -> (Option<SyncIndex>, Message) + Send>>,
) {
    std::thread::spawn(move || {
        let mut awaiting = vec![VecDeque::new(); nindices as usize];
        let mut done_receiving = false;

        loop {
            std::thread::yield_now();

            if sync_info.read().unwrap().is_none() {
                // sync is done, exit
                return;
            }

            if !done_receiving {
                // receive a message
                let (ix, m) = (recv_msg.lock().unwrap().deref_mut())();
                if m == Message::EndSync {
                    done_receiving = true;
                } else {
                    let ix = ix.unwrap_or_else(|| {
                        panic!(
                            "evaluator: message {} received without index in sync mode",
                            m
                        )
                    });
                    awaiting[ix as usize].push_back(m);
                }
            }

            // answer requests if possible
            if let Some(ref requests) = *requests.read().unwrap() {
                for (ix, reqs) in requests.iter().enumerate() {
                    if !awaiting[ix].is_empty() {
                        if let Ok(tx) = reqs.pop() {
                            tx.send(awaiting[ix].pop_front().unwrap()).unwrap();
                        }
                    }
                }
            }
        }
    });
}

impl Fancy for Evaluator {
    type Item = Wire;
    type Error = EvaluatorError;

    #[inline]
    fn garbler_input(
        &self,
        ix: Option<SyncIndex>,
        q: u16,
        _opt_x: Option<u16>,
    ) -> Result<Wire, FancyError<EvaluatorError>> {
        match self.recv(ix)? {
            Message::GarblerInput(w) => {
                if w.modulus() != q {
                    Err(EvaluatorError::InvalidMessage {
                        expected: format!("GarblerInput with modulus {}", q),
                        got: format!("GarblerInput with modulus {}", w.modulus()),
                    })?
                } else {
                    Ok(w)
                }
            }
            m => Err(EvaluatorError::InvalidMessage {
                expected: "GarblerInput".to_string(),
                got: format!("{}", m),
            })?,
        }
    }
    #[inline]
    fn evaluator_input(
        &self,
        ix: Option<SyncIndex>,
        q: u16,
    ) -> Result<Wire, FancyError<EvaluatorError>> {
        match self.recv(ix)? {
            Message::EvaluatorInput(w) => {
                if w.modulus() != q {
                    Err(EvaluatorError::InvalidMessage {
                        expected: format!("EvaluatorInput with modulus {}", q),
                        got: format!("EvaluatorInput with modulus {}", w.modulus()),
                    })?
                } else {
                    Ok(w)
                }
            }
            m => Err(EvaluatorError::InvalidMessage {
                expected: "EvaluatorInput".to_string(),
                got: format!("{}", m),
            })?,
        }
    }
    #[inline]
    fn constant(
        &self,
        ix: Option<SyncIndex>,
        x: u16,
        q: u16,
    ) -> Result<Wire, FancyError<EvaluatorError>> {
        match self.recv(ix)? {
            Message::Constant { wire, value } => {
                if x == value && wire.modulus() == q {
                    Ok(wire)
                } else {
                    Err(EvaluatorError::InvalidMessage {
                        expected: format!("Constant with value {} and modulus {}", x, q),
                        got: format!(
                            "Constant with value {} and modulus {}",
                            value,
                            wire.modulus()
                        ),
                    })?
                }
            }
            m => Err(EvaluatorError::InvalidMessage {
                expected: format!("Constant with value {} and modulus {}", x, q),
                got: format!("{}", m),
            })?,
        }
    }
    #[inline]
    fn add(&self, x: &Wire, y: &Wire) -> Result<Wire, FancyError<EvaluatorError>> {
        if x.modulus() != y.modulus() {
            return Err(FancyError::UnequalModuli);
        }
        Ok(x.plus(y))
    }
    #[inline]
    fn sub(&self, x: &Wire, y: &Wire) -> Result<Wire, FancyError<EvaluatorError>> {
        if x.modulus() != y.modulus() {
            return Err(FancyError::UnequalModuli);
        }
        Ok(x.minus(y))
    }
    #[inline]
    fn cmul(&self, x: &Wire, c: u16) -> Result<Wire, FancyError<EvaluatorError>> {
        Ok(x.cmul(c))
    }
    #[inline]
    fn mul(
        &self,
        ix: Option<SyncIndex>,
        A: &Wire,
        B: &Wire,
    ) -> Result<Wire, FancyError<EvaluatorError>> {
        if A.modulus() < A.modulus() {
            return self.mul(ix, B, A);
        }

        let gate = match self.recv(ix)? {
            Message::GarbledGate(g) => g,
            m => {
                return Err(EvaluatorError::InvalidMessage {
                    expected: "GarbledGate".to_string(),
                    got: format!("{}", m),
                })?;
            }
        };
        let gate_num = self.current_gate(ix);
        let g = tweak2(gate_num as u64, 0);
        let q = A.modulus();

        // garbler's half gate
        let L = if A.color() == 0 {
            A.hashback(g, q)
        } else {
            let ct_left = gate[A.color() as usize - 1];
            Wire::from_u128(ct_left ^ A.hash(g), q)
        };

        // evaluator's half gate
        let R = if B.color() == 0 {
            B.hashback(g, q)
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

        let res = L.plus_mov(&R.plus_mov(&A.cmul(new_b_color)));
        Ok(res)
    }
    #[inline]
    fn proj(
        &self,
        ix: Option<SyncIndex>,
        x: &Wire,
        q: u16,
        _tt: Option<Vec<u16>>,
    ) -> Result<Wire, FancyError<EvaluatorError>> {
        let gate = match self.recv(ix)? {
            Message::GarbledGate(g) => g,
            m => {
                return Err(EvaluatorError::InvalidMessage {
                    expected: "GarbledGate".to_string(),
                    got: format!("{}", m),
                })?;
            }
        };
        if gate.len() as u16 != x.modulus() - 1 {
            return Err(EvaluatorError::InvalidMessage {
                expected: format!("GarbledGate of len {}", q - 1),
                got: format!("GarbledGate of len {}", gate.len()),
            })?;
        }
        let gate_num = self.current_gate(ix);
        if x.color() == 0 {
            Ok(x.hashback(gate_num as u128, q))
        } else {
            let ct = gate[x.color() as usize - 1];
            Ok(Wire::from_u128(ct ^ x.hash(gate_num as u128), q))
        }
    }
    #[inline]
    fn output(&self, ix: Option<SyncIndex>, x: &Wire) -> Result<(), FancyError<EvaluatorError>> {
        match self.recv(ix)? {
            Message::OutputCiphertext(c) => {
                if c.len() as u16 != x.modulus() {
                    Err(EvaluatorError::InvalidMessage {
                        expected: format!("OutputCiphertext of len {}", x.modulus()),
                        got: format!("OutputCiphertext of len {}", c.len()),
                    })?
                }
                self.output_cts.lock().unwrap().push(c);
            }
            m => {
                return Err(EvaluatorError::InvalidMessage {
                    expected: "OutputCiphertext".to_string(),
                    got: format!("{}", m),
                })?;
            }
        }
        self.output_wires.lock().unwrap().push(x.clone());
        Ok(())
    }
    #[inline]
    fn begin_sync(&self, num_indices: SyncIndex) -> Result<(), FancyError<EvaluatorError>> {
        self.internal_begin_sync(num_indices)
    }
    #[inline]
    fn finish_index(&self, index: SyncIndex) -> Result<(), FancyError<EvaluatorError>> {
        self.internal_finish_index(index);
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
    /// Create a new GarbledCircuit from a vec of garbled gates and constant wires.
    pub fn new(gates: Vec<GarbledGate>, consts: HashMap<(u16, u16), Wire>) -> Self {
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
    pub fn eval(
        &self,
        c: &Circuit,
        garbler_inputs: &[Wire],
        evaluator_inputs: &[Wire],
    ) -> Result<Vec<Wire>, FancyError<EvaluatorError>> {
        // create a message iterator to pass as the Evaluator recv function
        let mut msgs = c
            .gates
            .iter()
            .enumerate()
            .filter_map(|(i, gate)| match *gate {
                Gate::GarblerInput { id } => {
                    Some(Message::GarblerInput(garbler_inputs[id].clone()))
                }
                Gate::EvaluatorInput { id } => {
                    Some(Message::EvaluatorInput(evaluator_inputs[id].clone()))
                }
                Gate::Constant { val } => Some(Message::Constant {
                    value: val,
                    wire: self.consts[&(val, c.modulus(i))].clone(),
                }),
                Gate::Mul { id, .. } => Some(Message::GarbledGate(self.gates[id].clone())),
                Gate::Proj { id, .. } => Some(Message::GarbledGate(self.gates[id].clone())),
                _ => None,
            })
            .collect_vec()
            .into_iter();

        let eval = Evaluator::new(move || (None, msgs.next().unwrap()));
        c.eval(&eval)
    }
}

////////////////////////////////////////////////////////////////////////////////
// Encoder

/// Encode inputs statically. Created by the `garble` function.
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Encoder {
    garbler_inputs: Vec<Wire>,
    evaluator_inputs: Vec<Wire>,
    deltas: HashMap<u16, Wire>,
}

impl Encoder {
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
        (0..inputs.len())
            .zip(inputs)
            .map(|(id, &x)| self.encode_garbler_input(x, id))
            .collect()
    }

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

/// Decode outputs statically. Created by the `garble` function.
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Decoder {
    outputs: Vec<OutputCiphertext>,
}

impl Decoder {
    pub fn new(outputs: Vec<Vec<u128>>) -> Self {
        Decoder { outputs }
    }

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
        fn check_sync(_: impl Sync) {}
        check_send(Evaluator::new(|| unimplemented!()));
        check_sync(Evaluator::new(|| unimplemented!()));
    }
}
