use crate::circuit::{Circuit, Gate};
use crate::fancy::{Fancy, HasModulus};
use crate::util::{tweak2, output_tweak};
use crate::wire::Wire;
use itertools::Itertools;
use serde_derive::{Serialize, Deserialize};
use std::collections::HashMap;
use std::ops::DerefMut;
use std::sync::{Arc, RwLock, Mutex};
use super::{Message, GarbledGate, OutputCiphertext, GateType};
use crossbeam::queue::MsQueue;
use std::sync::mpsc::{channel, Sender, Receiver};
use std::thread::{self, JoinHandle};

/// Streaming evaluator using a callback to receive ciphertexts as needed.
///
/// Evaluates a garbled circuit on the fly, using messages containing ciphertexts and
/// wires. Parallelizable.
pub struct Evaluator {
    recv_function:  Arc<Mutex<FnMut(GateType) -> Message + Send>>,
    constants:      Arc<RwLock<HashMap<(u16,u16), Wire>>>,
    current_gate:   Arc<Mutex<usize>>,
    output_cts:     Arc<Mutex<Vec<OutputCiphertext>>>,
    output_wires:   Arc<Mutex<Vec<Wire>>>,

    sync_info:      Arc<RwLock<Option<SyncInfo>>>,
    msg_queues:     Arc<RwLock<Vec<MsQueue<(GateType, Sender<Message>)>>>>,
    index_done:     Arc<RwLock<Option<Vec<bool>>>>,
    id_for_index:   Arc<RwLock<Vec<Mutex<usize>>>>,
    postman_handle: Arc<Mutex<Option<JoinHandle<()>>>>,
    postman_notify: Arc<Mutex<Option<Sender<()>>>>,
}

struct SyncInfo {
    begin_index: usize,
    starting_gate_id: usize,
}

impl Evaluator {
    /// Create a new Evaluator.
    ///
    /// `recv_function` enables streaming by producing messages during the `Fancy`
    /// computation, which contain ciphertexts and wirelabels.
    pub fn new<F>(recv_function: F) -> Evaluator
      where F: FnMut(GateType) -> Message + Send + 'static
    {
        Evaluator {
            recv_function:  Arc::new(Mutex::new(recv_function)),
            constants:      Arc::new(RwLock::new(HashMap::new())),
            current_gate:   Arc::new(Mutex::new(0)),
            output_cts:     Arc::new(Mutex::new(Vec::new())),
            output_wires:   Arc::new(Mutex::new(Vec::new())),

            sync_info:      Arc::new(RwLock::new(None)),
            msg_queues:     Arc::new(RwLock::new(Vec::new())),
            index_done:     Arc::new(RwLock::new(None)),
            id_for_index:   Arc::new(RwLock::new(Vec::new())),
            postman_handle: Arc::new(Mutex::new(None)),
            postman_notify: Arc::new(Mutex::new(None)),
        }
    }

    /// Decode the output received during the Fancy computation.
    pub fn decode_output(&self) -> Vec<u16> {
        let cts  = self.output_cts.lock().unwrap();
        let outs = self.output_wires.lock().unwrap();
        Decoder::new(cts.clone()).decode(&outs)
    }

    /// Receive the next message.
    fn recv(&self, sync_index: Option<usize>, ty: GateType) -> Message {
        if self.in_sync() {
            let ix = sync_index.expect("synchronization requires a sync index");
            let (tx, rx) = channel();
            self.msg_queues.read().unwrap()[ix - self.starting_index()].push((ty,tx));
            self.notify_postman();
            rx.recv().unwrap()
        } else {
            self.internal_recv(ty)
        }
    }

    fn internal_recv(&self, ty: GateType) -> Message {
        (self.recv_function.lock().unwrap().deref_mut())(ty)
    }

    fn internal_begin_sync(&self, begin_index: usize, end_index: usize) {
        let n = end_index - begin_index;

        assert_eq!(self.in_sync(), false,
            "evaluator: begin sync called while already in sync mode!");

        *self.sync_info.write().unwrap() = Some(SyncInfo {
            begin_index,
            starting_gate_id: *self.current_gate.lock().unwrap()
        });

        *self.msg_queues.write().unwrap()   = (0..n).map(|_| MsQueue::new()).collect_vec();
        *self.index_done.write().unwrap()   = Some(vec![false; n]);
        *self.id_for_index.write().unwrap() = (begin_index..end_index).map(|_| Mutex::new(0)).collect_vec();

        // set up postman
        let p_index_done = self.index_done.clone();
        let p_msg_queues = self.msg_queues.clone();
        let p_recv = self.recv_function.clone();
        let (tx,rx) = channel();

        // start postman
        let h = thread::spawn(move || {
            postman(begin_index, end_index, p_index_done, p_msg_queues, p_recv, rx);
        });

        *self.postman_handle.lock().unwrap() = Some(h);
        *self.postman_notify.lock().unwrap() = Some(tx);
    }

    fn internal_finish_index(&self, index: usize) {
        let mut done = false;
        {
            let mut opt_index_done = self.index_done.write().unwrap();
            if let Some(ref mut index_done) = *opt_index_done {
                index_done[index - self.starting_index()] = true;
                if index_done.iter().all(|&x| x) {
                    // end sync
                    done = true;
                    *opt_index_done = None;
                    *self.sync_info.write().unwrap()    = None;
                    *self.msg_queues.write().unwrap()   = Vec::new();
                    *self.current_gate.lock().unwrap() += 1;
                }
            } else {
                panic!("garbler: finish_index called without starting a sync!");
            }
            // unlock index_done for postman
        }
        self.notify_postman();
        if done {
            self.postman_handle.lock().unwrap().take().unwrap().join().unwrap();
            *self.postman_notify.lock().unwrap() = None;
        }
    }

    // starting index of the current sync computation
    fn starting_index(&self) -> usize {
        self.sync_info.read().unwrap().as_ref().unwrap().begin_index
    }

    fn in_sync(&self) -> bool {
        self.sync_info.read().unwrap().is_some()
    }

    fn notify_postman(&self) {
        self.postman_notify.lock().unwrap().as_ref().unwrap().send(()).unwrap();
    }

    /// The current non-free gate index of the garbling computation.
    fn current_gate(&self, sync_index: Option<usize>) -> usize {
        if let Some(ref info) = *self.sync_info.read().unwrap() {
            let ix = sync_index.expect("syncronization requires a sync index");
            let ids = self.id_for_index.read().unwrap();
            let mut id_mutex = ids[ix - info.begin_index].lock().unwrap();
            let id = *id_mutex;
            *id_mutex += 1;
            // 48 bits for gate index, 16 for id
            info.starting_gate_id + ix + (id << 48)
        } else {
            let mut c = self.current_gate.lock().unwrap();
            let old = *c;
            *c += 1;
            old
        }
    }
}

fn postman(
    start_index: usize,
    end_index: usize,
    index_done: Arc<RwLock<Option<Vec<bool>>>>,
    msg_queues: Arc<RwLock<Vec<MsQueue<(GateType, Sender<Message>)>>>>,
    recv: Arc<Mutex<FnMut(GateType) -> Message + Send>>,
    notify: Receiver<()>,
){
    let mut ix = start_index;
    while ix < end_index {
        // wait for notification
        notify.recv().unwrap();

        // check if this index is done yet
        if let Some(ref index_done) = *index_done.read().unwrap() {
            if index_done[ix] {
                ix += 1;
            }
        } else {
            // sync has been cancelled
            break;
        }

        // check if there is a message to receive for this index
        if let Some((ty, tx)) = msg_queues.read().unwrap()[ix].try_pop() {
            // receive message
            let m = (recv.lock().unwrap().deref_mut())(ty);
            // return the message to the original caller
            tx.send(m).unwrap();
        }
    }
}

impl Fancy for Evaluator {
    type Item = Wire;

    fn garbler_input(&self, ix: Option<usize>, q: u16) -> Wire {
        match self.recv(ix, GateType::Other) {
            Message::GarblerInput(w) => {
                assert_eq!(w.modulus(), q);
                w
            }
            m => panic!("Expected message GarblerInput but got {}", m),
        }
    }

    fn evaluator_input(&self, ix: Option<usize>, q: u16) -> Wire {
        match self.recv(ix, GateType::EvaluatorInput { modulus: q }) {
            Message::EvaluatorInput(w) => {
                assert_eq!(w.modulus(), q);
                w
            }
            m => panic!("Expected message EvaluatorInput but got {}", m),
        }
    }

    fn constant(&self, ix: Option<usize>, x: u16, q: u16) -> Wire {
        match self.constants.read().unwrap().get(&(x,q)) {
            Some(c) => return c.clone(),
            None => (),
        }
        let mut constants = self.constants.write().unwrap();
        match constants.get(&(x,q)) {
            Some(c) => return c.clone(),
            None => (),
        }
        let w = match self.recv(ix, GateType::Other) {
            Message::Constant { wire, .. } => wire,
            m => panic!("Expected message Constant but got {}", m),
        };
        constants.insert((x,q),w.clone());
        w
    }

    fn add(&self, x: &Wire, y: &Wire) -> Wire {
        x.plus(y)
    }

    fn sub(&self, x: &Wire, y: &Wire) -> Wire {
        x.minus(y)
    }

    fn cmul(&self, x: &Wire, c: u16) -> Wire {
        x.cmul(c)
    }

    fn mul(&self, ix: Option<usize>, A: &Wire, B: &Wire) -> Wire {
        if A.modulus() < A.modulus() {
            return self.mul(ix,B,A);
        }

        let gate = match self.recv(ix, GateType::Other) {
            Message::GarbledGate(g) => g,
            m => panic!("Expected message GarbledGate but got {}", m),
        };
        let gate_num = self.current_gate(ix);
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

    fn proj(&self, ix: Option<usize>, x: &Wire, q: u16, _tt: &[u16]) -> Wire {
        let gate = match self.recv(ix, GateType::Other) {
            Message::GarbledGate(g) => g,
            m => panic!("Expected message GarbledGate but got {}", m),
        };
        assert!(gate.len() as u16 == x.modulus() - 1,
            "evaluator proj: garbled gate length does not equal q-1, sync issue?");
        let gate_num = self.current_gate(ix);
        let w = if x.color() == 0 {
            x.hashback(gate_num as u128, q)
        } else {
            let ct = gate[x.color() as usize - 1];
            Wire::from_u128(ct ^ x.hash(gate_num as u128), q)
        };
        w
    }

    fn output(&self, ix: Option<usize>, x: &Wire) {
        match self.recv(ix, GateType::Other) {
            Message::OutputCiphertext(c) => {
                assert_eq!(c.len() as u16, x.modulus());
                self.output_cts.lock().unwrap().push(c);
            }
            m => panic!("Expected message OutputCiphertext but got {}", m),
        }
        self.output_wires.lock().unwrap().push(x.clone());
    }

    fn begin_sync(&self, begin_index: usize, end_index: usize) {
        self.internal_begin_sync(begin_index, end_index);
    }

    fn finish_index(&self, index: usize) {
        self.internal_finish_index(index);
    }
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

        let eval = Evaluator::new(move |_| msgs.next().unwrap());

        let mut wires: Vec<Wire> = Vec::new();
        for (i,gate) in c.gates.iter().enumerate() {
            let q = c.modulus(i);
            let w = match *gate {
                Gate::GarblerInput { .. }    => eval.garbler_input(None, q),
                Gate::EvaluatorInput { .. }  => eval.evaluator_input(None, q),
                Gate::Constant { val }       => eval.constant(None, val, q),
                Gate::Add { xref, yref }     => wires[xref.ix].plus(&wires[yref.ix]),
                Gate::Sub { xref, yref }     => wires[xref.ix].minus(&wires[yref.ix]),
                Gate::Cmul { xref, c }       => wires[xref.ix].cmul(c),
                Gate::Proj { xref, .. }      => eval.proj(None, &wires[xref.ix], q, &[]),
                Gate::Mul { xref, yref, .. } => eval.mul(None, &wires[xref.ix], &wires[yref.ix]),
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
        debug_assert_eq!(ws.len(), self.outputs.len(),
            "got {} wires, but have {} output ciphertexts",
            ws.len(), self.outputs.len());

        let mut outs = Vec::new();
        for i in 0..ws.len() {
            let q = ws[i].modulus();
            debug_assert_eq!(q as usize, self.outputs[i].len());
            for k in 0..q {
                let h = ws[i].hash(output_tweak(i,k));
                if h == self.outputs[i][k as usize] {
                    outs.push(k);
                    break;
                }
            }
        }
        debug_assert_eq!(ws.len(), outs.len(),
            "decoding failed! decoded {} out of {} wires",
            outs.len(), ws.len());
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

////////////////////////////////////////////////////////////////////////////////
// tests

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn evaluator_has_send_and_sync() {
        fn check_send(_: impl Send) { }
        fn check_sync(_: impl Sync) { }
        check_send(Evaluator::new(|_| unimplemented!()));
        check_sync(Evaluator::new(|_| unimplemented!()));
    }
}
