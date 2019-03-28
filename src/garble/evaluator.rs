use super::{GarbledGate, Message, OutputCiphertext, SyncInfo};
use crate::circuit::{Circuit, Gate};
use crate::error::{EvaluatorError, FancyError, SyncError};
use crate::fancy::{Fancy, HasModulus, SyncIndex};
use crate::util::{output_tweak, tweak2};
use crate::wire::Wire;
use crossbeam::queue::SegQueue;
use itertools::Itertools;
use scuttlebutt::Block;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::ops::DerefMut;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex, RwLock};

/// Streaming evaluator using a callback to receive ciphertexts as needed.
///
/// Evaluates a garbled circuit on the fly, using messages containing ciphertexts and
/// wires. Parallelizable.
pub struct Evaluator {
    callback:
        Arc<Mutex<FnMut(usize) -> Result<(Option<SyncIndex>, Vec<Block>), EvaluatorError> + Send>>,
    current_gate: Arc<AtomicUsize>,
    output_cts: Arc<Mutex<Vec<OutputCiphertext>>>,
    output_wires: Arc<Mutex<Vec<Wire>>>,
    sync_info: Arc<RwLock<Option<SyncInfo>>>,
    requests: Arc<RwLock<Option<Vec<SegQueue<Sender<Vec<u8>>>>>>>,
}

impl Evaluator {
    /// Create a new `Evaluator`.
    ///
    /// `callback` enables streaming by producing messages during the `Fancy`
    /// computation, which contain ciphertexts and wire-labels.
    pub fn new<F>(callback: F) -> Evaluator
    where
        F: FnMut(usize) -> Result<(Option<SyncIndex>, Vec<Block>), EvaluatorError> + Send + 'static,
    {
        Evaluator {
            callback: Arc::new(Mutex::new(callback)),
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

    #[inline]
    fn recv_wire(&self, ix: Option<SyncIndex>, q: u16) -> Result<Wire, EvaluatorError> {
        if let Some(ix) = ix {
            unimplemented!();
        // // request next message for this index
        // let (sender, receiver) = std::sync::mpsc::channel();
        // self.requests.read().unwrap().as_ref().unwrap()[ix as usize].push(sender);
        // // block until postman delivers message
        // Ok(receiver.recv().unwrap())
        } else {
            let (ix, blocks) = (self.callback.lock().unwrap().deref_mut())(1)?;
            Ok(Wire::from_block(blocks[0], q))
        }
    }

    #[inline]
    fn recv_gate(
        &self,
        ix: Option<SyncIndex>,
        ngates: usize,
    ) -> Result<GarbledGate, EvaluatorError> {
        if let Some(ix) = ix {
            unimplemented!();
        // // request next message for this index
        // let (tx, rx) = std::sync::mpsc::channel();
        // self.requests.read().unwrap().as_ref().unwrap()[ix as usize].push(tx);
        // // block until postman delivers message
        // Ok(rx.recv().unwrap())
        } else {
            let (ix, blocks) = (self.callback.lock().unwrap().deref_mut())(ngates)?;
            Ok(blocks)
        }
    }

    #[inline]
    fn recv_outputs(
        &self,
        ix: Option<SyncIndex>,
        noutputs: usize,
    ) -> Result<OutputCiphertext, EvaluatorError> {
        if let Some(ix) = ix {
            unimplemented!();
        } else {
            let (ix, blocks) = (self.callback.lock().unwrap().deref_mut())(noutputs)?;
            Ok(blocks)
        }
    }

    fn internal_begin_sync(&self, num_indices: SyncIndex) -> Result<(), EvaluatorError> {
        let mut opt_info = self.sync_info.write().unwrap();
        if opt_info.is_some() {
            return Err(EvaluatorError::from(SyncError::SyncStartedInSync));
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
            self.callback.clone(),
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
    requests: Arc<RwLock<Option<Vec<SegQueue<Sender<Vec<u8>>>>>>>,
    callback: Arc<
        Mutex<FnMut(usize) -> Result<(Option<SyncIndex>, Vec<Block>), EvaluatorError> + Send>,
    >,
) {
    unimplemented!();
    //     std::thread::spawn(move || {
    //         let mut awaiting = vec![VecDeque::new(); nindices as usize];
    //         let mut done_receiving = false;

    //         loop {
    //             std::thread::yield_now();

    //             if sync_info.read().unwrap().is_none() {
    //                 // sync is done, exit
    //                 return;
    //             }

    //             if !done_receiving {
    //                 // receive a message
    //                 let (ix, bytes) = (callback.lock().unwrap().deref_mut())().unwrap(); // XXX: remove this `unwrap`
    //                 if m == Message::EndSync {
    //                     done_receiving = true;
    //                 } else {
    //                     let ix = ix.unwrap_or_else(|| {
    //                         panic!(
    //                             "evaluator: message {} received without index in sync mode",
    //                             m
    //                         )
    //                     });
    //                     awaiting[ix as usize].push_back(bytes);
    //                 }
    //             }

    //             // answer requests if possible
    //             if let Some(ref requests) = *requests.read().unwrap() {
    //                 for (ix, reqs) in requests.iter().enumerate() {
    //                     if !awaiting[ix].is_empty() {
    //                         if let Ok(sender) = reqs.pop() {
    //                             sender.send(awaiting[ix].pop_front().unwrap()).unwrap();
    //                         }
    //                     }
    //                 }
    //             }
    //         }
    //     });
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
    ) -> Result<Wire, EvaluatorError> {
        self.recv_wire(ix, q)
    }
    #[inline]
    fn evaluator_input(&self, ix: Option<SyncIndex>, q: u16) -> Result<Wire, EvaluatorError> {
        self.recv_wire(ix, q)
    }
    #[inline]
    fn constant(&self, ix: Option<SyncIndex>, _: u16, q: u16) -> Result<Wire, EvaluatorError> {
        self.recv_wire(ix, q)
    }
    #[inline]
    fn add(&self, x: &Wire, y: &Wire) -> Result<Wire, EvaluatorError> {
        if x.modulus() != y.modulus() {
            return Err(EvaluatorError::FancyError(FancyError::UnequalModuli));
        }
        Ok(x.plus(y))
    }
    #[inline]
    fn sub(&self, x: &Wire, y: &Wire) -> Result<Wire, EvaluatorError> {
        if x.modulus() != y.modulus() {
            return Err(EvaluatorError::FancyError(FancyError::UnequalModuli));
        }
        Ok(x.minus(y))
    }
    #[inline]
    fn cmul(&self, x: &Wire, c: u16) -> Result<Wire, EvaluatorError> {
        Ok(x.cmul(c))
    }
    #[inline]
    fn mul(&self, ix: Option<SyncIndex>, A: &Wire, B: &Wire) -> Result<Wire, EvaluatorError> {
        if A.modulus() < A.modulus() {
            return self.mul(ix, B, A);
        }
        let q = A.modulus();
        let qb = B.modulus();
        let gate = self.recv_gate(ix, q as usize + qb as usize - 2)?;
        let gate_num = self.current_gate(ix);
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
        let new_b_color = if A.modulus() != B.modulus() {
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
    fn proj(
        &self,
        ix: Option<SyncIndex>,
        x: &Wire,
        q: u16,
        _tt: Option<Vec<u16>>,
    ) -> Result<Wire, EvaluatorError> {
        let ngates = (x.modulus() - 1) as usize;
        let gate = self.recv_gate(ix, ngates)?;
        let gate_num = self.current_gate(ix);
        if x.color() == 0 {
            Ok(x.hashback(gate_num as u128, q))
        } else {
            let ct = gate[x.color() as usize - 1];
            Ok(Wire::from_block(ct ^ x.hash(gate_num as u128), q))
        }
    }
    #[inline]
    fn output(&self, ix: Option<SyncIndex>, x: &Wire) -> Result<(), EvaluatorError> {
        let noutputs = x.modulus() as usize;
        let c = self.recv_outputs(ix, noutputs)?;
        self.output_cts.lock().unwrap().push(c);
        self.output_wires.lock().unwrap().push(x.clone());
        Ok(())
    }
    #[inline]
    fn begin_sync(&self, num_indices: SyncIndex) -> Result<(), EvaluatorError> {
        self.internal_begin_sync(num_indices)
    }
    #[inline]
    fn finish_index(&self, index: SyncIndex) -> Result<(), EvaluatorError> {
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
        c: &Circuit,
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
        let eval = Evaluator::new(move |_| Ok((None, msgs.next().unwrap())));
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
    pub fn new(outputs: Vec<Vec<Block>>) -> Self {
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
                if h == Block::from(self.outputs[i][k as usize]) {
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
        check_send(Evaluator::new(|_| unimplemented!()));
        check_sync(Evaluator::new(|_| unimplemented!()));
    }
}
