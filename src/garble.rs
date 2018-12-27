//! Structs and functions for creating, streaming, and evaluating garbled circuits.

use crate::circuit::{Circuit, Gate};
use crate::fancy::{Fancy, HasModulus};
use crate::util::RngExt;
use crate::wire::Wire;
use itertools::Itertools;
use rand::rngs::ThreadRng;
use serde_derive::{Serialize, Deserialize};
use std::collections::HashMap;

/// The ciphertext created by a garbled gate.
pub type GarbledGate = Vec<u128>;

/// Ciphertext created by the garbler for output gates.
pub type OutputCiphertext = Vec<u128>;

/// The outputs that can be emitted during streaming of a garbling.
pub enum Message {
    /// Zero wire for one of the garbler's inputs.
    GarblerInput(Wire),

    /// Zero wire for one of the evaluator's inputs.
    EvaluatorInput(Wire),

    /// Constant wire carrying the value.
    Constant(u16,Wire),

    /// Garbled gate emitted by a projection or multiplication.
    GarbledGate(GarbledGate),

    /// Output decoding information.
    OutputCiphertext(OutputCiphertext),
}

impl std::fmt::Display for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(match self {
            Message::GarblerInput(_)     => "GarblerInput",
            Message::EvaluatorInput(_)   => "EvaluatorInput",
            Message::Constant(_,_)       => "Constant",
            Message::GarbledGate(_)      => "GarbledGate",
            Message::OutputCiphertext(_) => "OutputCiphertext",
        })
    }
}

////////////////////////////////////////////////////////////////////////////////
// Garbler

/// Streams garbled circuit ciphertexts through a callback.
pub struct Garbler<'a> {
    rng: ThreadRng,
    send_function: &'a mut FnMut(Message),
    constants: HashMap<(u16,u16),Wire>,
    deltas: HashMap<u16, Wire>,
    current_output: usize,
    current_gate: usize,
}

impl <'a> Fancy for Garbler<'a> {
    type Wire = Wire;

    fn garbler_input(&mut self, q: u16) -> Wire { // {{{
        let w = Wire::rand(&mut self.rng, q);
        self.send(Message::GarblerInput(w.clone()));
        w
    }
    //}}}
    fn evaluator_input(&mut self, q: u16) -> Wire { // {{{
        let w = Wire::rand(&mut self.rng, q);
        self.send(Message::EvaluatorInput(w.clone()));
        w
    }
    //}}}
    fn constant(&mut self, x: u16, q: u16) -> Wire { // {{{
        if self.constants.contains_key(&(x,q)) {
            return self.constants[&(x,q)].clone();
        }
        let zero = Wire::rand(&mut self.rng, q);
        let wire = zero.plus(&self.delta(q).cmul(x));
        self.constants.insert((x,q), wire.clone());
        self.send(Message::Constant(x, wire.clone()));
        zero
    }
    //}}}
    fn add(&mut self, x: &Wire, y: &Wire) -> Wire { // {{{
        x.plus(y)
    }
    //}}}
    fn sub(&mut self, x: &Wire, y: &Wire) -> Wire { // {{{
        x.minus(y)
    }
    //}}}
    fn cmul(&mut self, x: &Wire, c: u16)  -> Wire { // {{{
        x.cmul(c)
    }
    //}}}
    fn mul(&mut self, A: &Wire, B: &Wire) -> Wire { // {{{
        let q = A.modulus();
        let qb = B.modulus();
        let gate_num = self.current_gate();

        debug_assert!(q >= qb); // XXX: for now

        let D = self.delta(q);
        let Db = self.delta(qb);

        let r;
        let mut gate = vec![None; q as usize + qb as usize - 2];

        // hack for unequal moduli
        if q != qb {
            // would need to pack minitable into more than one u128 to support qb > 8
            debug_assert!(qb <= 8, "qb capped at 8 for now, for assymmetric moduli");

            r = self.rng.gen_u16() % q;
            let t = tweak2(gate_num as u64, 1);

            let mut minitable = vec![None; qb as usize];
            let mut B_ = B.clone();
            for b in 0..qb {
                if b > 0 {
                    B_.plus_eq(&Db);
                }
                let new_color = (r+b) % q;
                let ct = (B_.hash(t) & 0xFFFF) ^ new_color as u128;
                minitable[B_.color() as usize] = Some(ct);
            }

            let mut packed = 0;
            for i in 0..qb as usize {
                packed += minitable[i].unwrap() << (16 * i);
            }
            gate.push(Some(packed));

        } else {
            r = B.color(); // secret value known only to the garbler (ev knows r+b)
        }

        let g = tweak2(gate_num as u64, 0);

        // X = H(A+aD) + arD such that a + A.color == 0
        let alpha = (q - A.color()) % q; // alpha = -A.color
        let X = A.plus(&D.cmul(alpha))
                .hashback(g,q)
                .plus(&D.cmul((alpha * r) % q));

        // Y = H(B + bD) + (b + r)A such that b + B.color == 0
        let beta = (qb - B.color()) % qb;
        let Y = B.plus(&Db.cmul(beta))
                .hashback(g,q)
                .plus(&A.cmul((beta + r) % q));

        // precompute a lookup table of X.minus(&D_cmul[(a * r % q) as usize]).as_u128();
        //                            = X.plus(&D_cmul[((q - (a * r % q)) % q) as usize]).as_u128();
        let X_cmul = {
            let mut X_ = X.clone();
            (0..q).map(|x| {
                if x > 0 {
                    X_.plus_eq(&D);
                }
                X_.as_u128()
            }).collect_vec()
        };

        let mut A_ = A.clone();
        for a in 0..q {
            if a > 0 {
                A_.plus_eq(&D);
            }
            // garbler's half-gate: outputs X-arD
            // G = H(A+aD) ^ X+a(-r)D = H(A+aD) ^ X-arD
            if A_.color() != 0 {
                // let G = A_.hash(g) ^ X.minus(&D_cmul[(a * r % q) as usize]).as_u128();
                let G = A_.hash(g) ^ X_cmul[((q - (a * r % q)) % q) as usize];
                gate[A_.color() as usize - 1] = Some(G);
            }
        }

        // precompute a lookup table of Y.minus(&A_cmul[((b+r) % q) as usize]).as_u128();
        //                            = Y.plus(&A_cmul[((q - ((b+r) % q)) % q) as usize]).as_u128();
        let Y_cmul = {
            let mut Y_ = Y.clone();
            (0..q).map(|x| {
                if x > 0 {
                    Y_.plus_eq(&A);
                }
                Y_.as_u128()
            }).collect_vec()
        };

        let mut B_ = B.clone();
        for b in 0..qb {
            if b > 0 {
                B_.plus_eq(&Db)
            }
            // evaluator's half-gate: outputs Y-(b+r)D
            // G = H(B+bD) + Y-(b+r)A
            if B_.color() != 0 {
                // let G = B_.hash(g) ^ Y.minus(&A_cmul[((b+r) % q) as usize]).as_u128();
                let G = B_.hash(g) ^ Y_cmul[((q - ((b+r) % q)) % q) as usize];
                gate[q as usize - 1 + B_.color() as usize - 1] = Some(G);
            }
        }

        let gate = gate.into_iter().map(Option::unwrap).collect();
        self.send(Message::GarbledGate(gate));

        X.plus(&Y)
    }
    // }}}
    fn proj(&mut self, A: &Wire, q_out: u16, tt: &[u16]) -> Wire { // {{{
        let q_in = A.modulus();
        // we have to fill in the vector in an unkonwn order because of the color bits.
        // Since some of the values in gate will be void temporarily, we use Vec<Option<..>>
        let mut gate = vec![None; q_in as usize - 1];

        let tao = A.color();        // input zero-wire
        let g = tweak(self.current_gate());    // gate tweak

        let Din  = self.delta(q_in);
        let Dout = self.delta(q_out);

        // output zero-wire
        // W_g^0 <- -H(g, W_{a_1}^0 - \tao\Delta_m) - \phi(-\tao)\Delta_n
        // let C = A.minus(&Din.cmul(tao))
        //             .hashback(g, q_out)
        //             .minus(&Dout.cmul(tt[((q_in - tao) % q_in) as usize]));
        let mut C = A.clone();
        C.plus_eq(&Din.cmul((q_in-tao) % q_in));
        C = C.hashback(g, q_out);
        C.plus_eq(&Dout.cmul((q_out - tt[((q_in - tao) % q_in) as usize]) % q_out));

        // precompute `let C_ = C.plus(&Dout.cmul(tt[x as usize]))`
        let C_precomputed = {
            let mut C_ = C.clone();
            (0..q_out).map(|x| {
                if x > 0 {
                    C_.plus_eq(&Dout);
                }
                C_.as_u128()
            }).collect_vec()
        };

        let mut A_ = A.clone();
        for x in 0..q_in {
            if x > 0 {
                A_.plus_eq(&Din); // avoiding expensive cmul for `A_ = A.plus(&Din.cmul(x))`
            }

            let ix = (tao as usize + x as usize) % q_in as usize;
            if ix == 0 { continue }

            let ct = A_.hash(g) ^ C_precomputed[tt[x as usize] as usize];
            gate[ix - 1] = Some(ct);
        }

        // unwrap the Option elems inside the Vec
        let gate = gate.into_iter().map(Option::unwrap).collect();
        self.send(Message::GarbledGate(gate));

        C
    }
    // }}}
    fn output(&mut self, X: &Wire) { // {{{
        let mut cts = Vec::new();
        let q = X.modulus();
        let i = self.current_output();
        let D = self.delta(q);
        for k in 0..q {
            let t = output_tweak(i, k);
            cts.push(X.plus(&D.cmul(k)).hash(t));
        }
        self.send(Message::OutputCiphertext(cts));
    }
    // }}}
}

impl <'a> Garbler<'a> {
    /// Create a new garbler.
    ///
    /// `send_func` is a callback that enables streaming. It gets called as the garbler
    /// generates ciphertext information such as garbled gates or input wirelabels.
    pub fn new(send_func: &mut FnMut(Message)) -> Garbler {
        Garbler {
            rng: rand::thread_rng(),
            send_function: send_func,
            constants: HashMap::new(),
            deltas: HashMap::new(),
            current_gate: 0,
            current_output: 0,
        }
    }

    /// Output some information from the garbling.
    fn send(&mut self, m: Message) {
        (self.send_function)(m);
    }

    /// Create a delta if it has not been created yet for this modulus, otherwise just
    /// return the existing one.
    fn delta(&mut self, q: u16) -> Wire {
        if self.deltas.contains_key(&q) {
            return self.deltas[&q].clone();
        }
        let w = Wire::rand_delta(&mut self.rng, q);
        self.deltas.insert(q,w.clone());
        w
    }

    /// The current nonfree gate index of the garbling computation.
    fn current_gate(&mut self) -> usize {
        let c = self.current_gate;
        self.current_gate += 1;
        c
    }

    /// The current output index of the garbling computation.
    fn current_output(&mut self) -> usize {
        let c = self.current_output;
        self.current_output += 1;
        c
    }

}

/// Garble circuit without streaming.
pub fn garble(c: &Circuit) -> (Encoder, Decoder, Evaluator) {
    let mut garbler_inputs   = Vec::new();
    let mut evaluator_inputs = Vec::new();
    let mut garbled_gates    = Vec::new();
    let mut constants        = HashMap::new();
    let mut garbled_outputs  = Vec::new();
    let deltas;

    let mut send_func = |m| {
        match m {
            Message::GarblerInput(w)     => garbler_inputs.push(w),
            Message::EvaluatorInput(w)   => evaluator_inputs.push(w),
            Message::GarbledGate(w)      => garbled_gates.push(w),
            Message::OutputCiphertext(c) => garbled_outputs.push(c),
            Message::Constant(val,wire)  => {
                let q = wire.modulus();
                constants.insert((val,q), wire);
            }
        }
    };

    {
        let mut garbler = Garbler::new(&mut send_func);

        let mut wires = Vec::new();
        for (i, gate) in c.gates.iter().enumerate() {
            let q = c.modulus(i);
            let w = match gate {
                Gate::GarblerInput { .. }    => garbler.garbler_input(q),
                Gate::EvaluatorInput { .. }  => garbler.evaluator_input(q),
                Gate::Constant { val }       => garbler.constant(*val,q),
                Gate::Add { xref, yref }     => garbler.add(&wires[xref.ix], &wires[yref.ix]),
                Gate::Sub { xref, yref }     => garbler.sub(&wires[xref.ix], &wires[yref.ix]),
                Gate::Cmul { xref, c }       => garbler.cmul(&wires[xref.ix], *c),
                Gate::Mul { xref, yref, .. } => garbler.mul(&wires[xref.ix], &wires[yref.ix]),
                Gate::Proj { xref, tt, .. }  => garbler.proj(&wires[xref.ix], q, tt),
            };
            wires.push(w);
        }

        for r in c.output_refs.iter() {
            garbler.output(&wires[r.ix]);
        }

        deltas = garbler.deltas;
    }

    let en = Encoder::new(garbler_inputs, evaluator_inputs, deltas);
    let ev = Evaluator::new(garbled_gates, constants);
    let de = Decoder::new(garbled_outputs);
    (en, de, ev)
}

////////////////////////////////////////////////////////////////////////////////
// Encoder

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

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Decoder {
    outputs : Vec<Vec<u128>>
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

////////////////////////////////////////////////////////////////////////////////
// Evaluator

/// Streaming evaluator.
pub struct Eval<'a> {
    recv_function: &'a mut FnMut() -> Option<Message>,
    constants: HashMap<(u16,u16),Wire>,
    current_gate: usize,
    output_ciphertexts: Vec<OutputCiphertext>,
    output_wires: Vec<Wire>,
}

impl <'a> Eval<'a> {
    /// Create a new Evaluator.
    ///
    /// `recv_function` enables streaming by producing messages during the `Fancy`
    /// computation, which contain ciphertexts and wirelabels and constants and outputs.
    fn new(recv_function: &mut FnMut() -> Option<Message>) -> Eval {
        Eval {
            recv_function,
            constants: HashMap::new(),
            current_gate: 0,
            output_ciphertexts: Vec::new(),
            output_wires: Vec::new(),
        }
    }

    /// Recieve the next message.
    fn recv(&mut self) -> Message {
        match (self.recv_function)() {
            Some(m) => m,
            None => panic!("no more messages!"),
        }
    }

    /// The current nonfree gate index of the garbling computation.
    fn current_gate(&mut self) -> usize {
        let c = self.current_gate;
        self.current_gate += 1;
        c
    }
}

impl <'a> Fancy for Eval<'a> {
    type Wire = Wire;

    fn garbler_input(&mut self, _q: u16) -> Self::Wire {
        match self.recv() {
            Message::GarblerInput(w) => w,
            m => panic!("unexpected message: {}", m),
        }
    }

    fn evaluator_input(&mut self, _q: u16) -> Self::Wire {
        match self.recv() {
            Message::EvaluatorInput(w) => w,
            m => panic!("unexpected message: {}", m),
        }
    }

    fn constant(&mut self, x: u16, q: u16) -> Self::Wire {
        if self.constants.contains_key(&(x,q)) {
            return self.constants[&(x,q)].clone();
        }
        let w = match self.recv() {
            Message::Constant(_,w) => w,
            m => panic!("unexpected message: {}", m),
        };
        self.constants.insert((x,q),w.clone());
        w
    }

    fn add(&mut self, x: &Self::Wire, y: &Self::Wire) -> Self::Wire {
        x.plus(y)
    }

    fn sub(&mut self, x: &Self::Wire, y: &Self::Wire) -> Self::Wire {
        x.minus(y)
    }

    fn cmul(&mut self, x: &Self::Wire, c: u16) -> Self::Wire {
        x.cmul(c)
    }

    fn mul(&mut self, A: &Self::Wire, B: &Self::Wire) -> Self::Wire {
        let gate = match self.recv() {
            Message::GarbledGate(g) => g,
            m => panic!("unexpected message: {}", m),
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

    fn proj(&mut self, x: &Self::Wire, q: u16, _tt: &[u16]) -> Self::Wire {
        let gate = match self.recv() {
            Message::GarbledGate(g) => g,
            m => panic!("unexpected message: {}", m),
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

    fn output(&mut self, x: &Self::Wire) {
        match self.recv() {
            Message::OutputCiphertext(c) => self.output_ciphertexts.push(c),
            m => panic!("unexpected message: {}", m),
        }
        self.output_wires.push(x.clone());
    }
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Evaluator {
    gates  : Vec<GarbledGate>,
    consts : HashMap<(u16,u16),Wire>,
}

impl Evaluator {
    pub fn new(gates: Vec<GarbledGate>, consts: HashMap<(u16,u16),Wire>) -> Self {
        Evaluator { gates, consts }
    }

    pub fn size(&self) -> usize {
        let mut c = self.consts.len();
        for g in self.gates.iter() {
            c += g.len();
        }
        c
    }

    pub fn eval(&self, c: &Circuit, garbler_inputs: &[Wire], evaluator_inputs: &[Wire]) -> Vec<Wire> {
        // create list of messages
        let mut msgs = c.gates.iter().enumerate().filter_map(|(i,gate)| {
            let q = c.modulus(i);
            match *gate {
                Gate::GarblerInput { id }   => Some(Message::GarblerInput(garbler_inputs[id].clone())),
                Gate::EvaluatorInput { id } => Some(Message::EvaluatorInput(evaluator_inputs[id].clone())),
                Gate::Constant { val }      => Some(Message::Constant(val, self.consts[&(val,q)].clone())),
                Gate::Mul { id, .. }        => Some(Message::GarbledGate(self.gates[id].clone())),
                Gate::Proj { id, .. }       => Some(Message::GarbledGate(self.gates[id].clone())),
                _ => None,
            }
        });

        let mut recv_function = || msgs.next();

        let mut e = Eval::new(&mut recv_function);

        let mut wires: Vec<Wire> = Vec::new();
        for (i,gate) in c.gates.iter().enumerate() {
            let q = c.modulus(i);
            let w = match *gate {
                Gate::GarblerInput { .. }    => e.garbler_input(q),
                Gate::EvaluatorInput { .. }  => e.evaluator_input(q),
                Gate::Constant { val }       => e.constant(val, q),
                Gate::Add { xref, yref }     => wires[xref.ix].plus(&wires[yref.ix]),
                Gate::Sub { xref, yref }     => wires[xref.ix].minus(&wires[yref.ix]),
                Gate::Cmul { xref, c }       => wires[xref.ix].cmul(c),
                Gate::Proj { xref, .. }      => e.proj(&wires[xref.ix], q, &[]),
                Gate::Mul { xref, yref, .. } => e.mul(&wires[xref.ix], &wires[yref.ix]),
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
// helper tweak functions

fn tweak(i: usize) -> u128 {
    i as u128
}

fn tweak2(i: u64, j: u64) -> u128 {
    ((i as u128) << 64) + j as u128
}

fn output_tweak(i: usize, k: u16) -> u128 {
    let (left, _) = (i as u128).overflowing_shl(64);
    left + k as u128
}


////////////////////////////////////////////////////////////////////////////////
// tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::{Circuit, Builder};
    use crate::fancy::{Fancy, BundleGadgets};
    use crate::util::{self, RngExt};
    use itertools::Itertools;
    use rand::thread_rng;

    // helper {{{
    fn garble_test_helper<F>(f: F)
        where F: Fn(u16) -> Circuit
    {
        let mut rng = thread_rng();
        for _ in 0..16 {
            let q = rng.gen_prime();
            let c = &f(q);
            let (en, de, ev) = garble(c);
            println!("number of ciphertexts for mod {}: {}", q, ev.size());
            for _ in 0..16 {
                let inps = (0..c.num_evaluator_inputs()).map(|i| { rng.gen_u16() % c.evaluator_input_mod(i) }).collect_vec();
                let xs = &en.encode_evaluator_inputs(&inps);
                let ys = &ev.eval(c, &[], xs);
                let decoded = de.decode(ys)[0];
                let should_be = c.eval(&[], &inps)[0];
                if decoded != should_be {
                    println!("inp={:?} q={} got={} should_be={}", inps, q, decoded, should_be);
                    panic!("failed test!");
                }
            }
        }
    }
//}}}
    #[test] // add {{{
    fn add() {
        garble_test_helper(|q| {
            let mut b = Builder::new();
            let x = b.evaluator_input(q);
            let y = b.evaluator_input(q);
            let z = b.add(&x,&y);
            b.output(&z);
            b.finish()
        });
    }
//}}}
    #[test] // add_many {{{
    fn add_many() {
        garble_test_helper(|q| {
            let mut b = Builder::new();
            let xs = b.evaluator_inputs(q,16);
            let z = b.add_many(&xs);
            b.output(&z);
            b.finish()
        });
    }
//}}}
    #[test] // or_many {{{
    fn or_many() {
        garble_test_helper(|_| {
            let mut b = Builder::new();
            let xs = b.evaluator_inputs(2,16);
            let z = b.or_many(&xs);
            b.output(&z);
            b.finish()
        });
    }
//}}}
    #[test] // sub {{{
    fn sub() {
        garble_test_helper(|q| {
            let mut b = Builder::new();
            let x = b.evaluator_input(q);
            let y = b.evaluator_input(q);
            let z = b.sub(&x,&y);
            b.output(&z);
            b.finish()
        });
    }
//}}}
    #[test] // cmul {{{
    fn cmul() {
        garble_test_helper(|q| {
            let mut b = Builder::new();
            let x = b.evaluator_input(q);
            let _ = b.evaluator_input(q);
            let z;
            if q > 2 {
                z = b.cmul(&x, 2);
            } else {
                z = b.cmul(&x, 1);
            }
            b.output(&z);
            b.finish()
        });
    }
//}}}
    #[test] // proj_cycle {{{
    fn proj_cycle() {
        garble_test_helper(|q| {
            let mut tab = Vec::new();
            for i in 0..q {
                tab.push((i + 1) % q);
            }
            let mut b = Builder::new();
            let x = b.evaluator_input(q);
            let _ = b.evaluator_input(q);
            let z = b.proj(&x, q, &tab);
            b.output(&z);
            b.finish()
        });
    }
//}}}
    #[test] // proj_rand {{{
    fn proj_rand() {
        garble_test_helper(|q| {
            let mut rng = thread_rng();
            let mut tab = Vec::new();
            for _ in 0..q {
                tab.push(rng.gen_u16() % q);
            }
            let mut b = Builder::new();
            let x = b.evaluator_input(q);
            let _ = b.evaluator_input(q);
            let z = b.proj(&x, q, &tab);
            b.output(&z);
            b.finish()
        });
    }
//}}}
    #[test] // mod_change {{{
    fn mod_change() {
        garble_test_helper(|q| {
            let mut b = Builder::new();
            let x = b.evaluator_input(q);
            let z = b.mod_change(&x,q*2);
            b.output(&z);
            b.finish()
        });
    }
//}}}
    #[test] // half_gate {{{
    fn half_gate() {
        garble_test_helper(|q| {
            let mut b = Builder::new();
            let x = b.evaluator_input(q);
            let y = b.evaluator_input(q);
            let z = b.mul(&x,&y);
            b.output(&z);
            b.finish()
        });
    }
//}}}
    #[test] // half_gate_unequal_mods {{{
    fn half_gate_unequal_mods() {
        for q in 3..16 {
            let ymod = 2 + thread_rng().gen_u16() % 6; // lower mod is capped at 8 for now
            println!("\nTESTING MOD q={} ymod={}", q, ymod);

            let mut b = Builder::new();
            let x = b.evaluator_input(q);
            let y = b.evaluator_input(ymod);
            let z = b.mul(&x,&y);
            b.output(&z);
            let c = b.finish();

            let (en, de, ev) = garble(&c);

            let mut fail = false;
            for x in 0..q {
                for y in 0..ymod {
                    println!("TEST x={} y={}", x,y);
                    let xs = &en.encode_evaluator_inputs(&[x,y]);
                    let ys = &ev.eval(&c, &[], xs);
                    let decoded = de.decode(ys)[0];
                    let should_be = c.eval(&[], &[x,y])[0];
                    if decoded != should_be {
                        println!("FAILED inp={:?} q={} got={} should_be={}", [x,y], q, decoded, should_be);
                        fail = true;
                    } else {
                        // println!("SUCCEEDED inp={:?} q={} got={} should_be={}", [x,y], q, decoded, should_be);
                    }
                }
            }
            if fail {
                panic!("failed!")
            }
        }
    }
//}}}
    #[test] // mixed_radix_addition {{{
    fn mixed_radix_addition() {
        let mut rng = thread_rng();

        let nargs = 2 + rng.gen_usize() % 100;
        // let mods = (0..7).map(|_| rng.gen_modulus()).collect_vec(); // slow
        let mods = [3,7,10,2,13]; // fast

        let mut b = Builder::new();
        let xs = b.evaluator_input_bundles(&mods, nargs);
        let z = b.mixed_radix_addition(&xs);
        b.output_bundle(&z);
        let circ = b.finish();

        let (en, de, ev) = garble(&circ);
        println!("mods={:?} nargs={} size={}", mods, nargs, ev.size());

        let Q: u128 = mods.iter().map(|&q| q as u128).product();

        // test random values
        for _ in 0..16 {
            let mut should_be = 0;
            let mut ds = Vec::new();
            for _ in 0..nargs {
                let x = rng.gen_u128() % Q;
                should_be = (should_be + x) % Q;
                ds.extend(util::as_mixed_radix(x, &mods).iter());
            }
            let X = en.encode_evaluator_inputs(&ds);
            let Y = ev.eval(&circ, &[], &X);
            let res = de.decode(&Y);
            assert_eq!(util::from_mixed_radix(&res,&mods), should_be);
        }
    }
//}}}
    #[test] // basic constants {{{
    fn basic_constant() {
        let mut b = Builder::new();
        let mut rng = thread_rng();

        let q = rng.gen_modulus();
        let c = rng.gen_u16() % q;

        let y = b.constant(c,q);
        b.output(&y);

        let circ = b.finish();
        let (_, de, ev) = garble(&circ);

        for _ in 0..64 {
            assert_eq!(circ.eval(&[],&[])[0], c, "plaintext eval failed");
            let Y = ev.eval(&circ, &[], &[]);
            assert_eq!(de.decode(&Y)[0], c, "garbled eval failed");
        }
    }
//}}}
    #[test] // constants {{{
    fn constants() {
        let mut b = Builder::new();
        let mut rng = thread_rng();

        let q = rng.gen_modulus();
        let c = rng.gen_u16() % q;

        let x = b.evaluator_input(q);
        let y = b.constant(c,q);
        let z = b.add(&x,&y);
        b.output(&z);

        let circ = b.finish();
        let (en, de, ev) = garble(&circ);

        for _ in 0..64 {
            let x = rng.gen_u16() % q;

            assert_eq!(circ.eval(&[],&[x])[0], (x+c)%q, "plaintext");

            let X = en.encode_evaluator_inputs(&[x]);
            let Y = ev.eval(&circ, &[], &X);
            assert_eq!(de.decode(&Y)[0], (x+c)%q, "garbled");
        }
    }
//}}}
    #[test] // serialization {{{
    fn serialization() {
        let mut rng = thread_rng();

        let nargs = 2 + rng.gen_usize() % 10;
        let mods = (0..7).map(|_| rng.gen_modulus()).collect_vec();

        let mut b = Builder::new();
        let xs = b.evaluator_input_bundles(&mods, nargs);
        let z = b.mixed_radix_addition(&xs);
        b.output_bundle(&z);
        let circ = b.finish();

        let (en, de, ev) = garble(&circ);

        assert_eq!(ev, Evaluator::from_bytes(&ev.to_bytes()).unwrap());
        assert_eq!(en, Encoder::from_bytes(&en.to_bytes()).unwrap());
        assert_eq!(de, Decoder::from_bytes(&de.to_bytes()).unwrap());
    }
//}}}
}
