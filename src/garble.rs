//! Structs and functions for creating, and evaluating garbled circuits.

use crate::circuit::{Circuit, Gate};
use crate::wire::Wire;
use itertools::Itertools;
use rand::rngs::ThreadRng;
use serde_derive::{Serialize, Deserialize};
use std::collections::HashMap;
use crate::fancy::KnowsModulus;

pub mod operations;

/// The ciphertext created by a garbled gate.
pub type GarbledGate = Vec<u128>;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Encoder {
    inputs : Vec<Wire>,
    deltas : HashMap<u16,Wire>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Decoder {
    outputs : Vec<Vec<u128>>
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Evaluator {
    gates  : Vec<GarbledGate>,
    consts : Vec<Wire>,
}

/// Garbler is an iterator for streaming `GarbledGate`s, and producing constant wires,
/// `Encoder` and `Decoder`. It is intended to be used via its `Iterator` instance, during
/// which it produces wirelabels for all internal wires while creating `GarbledGate` for
/// each gate which requires ciphertexts.
pub struct Garbler<'a> {
    circuit: &'a Circuit,
    wires: Vec<Wire>,
    inputs: Vec<Wire>,
    consts: Vec<Wire>,
    deltas: HashMap<u16, Wire>,
    current_wire: usize,
    rng: ThreadRng,
}

/// Convenience function to garble directly with no streaming.
pub fn garble(c: &Circuit) -> (Encoder, Decoder, Evaluator) {
    let mut garbler = Garbler::new(c);
    let en     = garbler.encoder();
    let gates  = garbler.by_ref().collect();
    let ev     = Evaluator::new(gates, garbler.consts());
    let de     = garbler.decoder().unwrap();
    (en, de, ev)
}

impl <'a> Garbler<'a> {
    pub fn new(circuit: &'a Circuit) -> Garbler {
        let mut rng = rand::thread_rng();

        let mut deltas  = HashMap::new();
        let mut inputs  = Vec::new();
        let mut consts  = Vec::new();

        // initialize deltas
        for &m in circuit.gate_moduli.iter().unique() {
            let w = Wire::rand_delta(&mut rng, m);
            deltas.insert(m, w);
        }

        // initialize inputs
        for &i in circuit.input_refs.iter() {
            let q = i.modulus();
            let w = Wire::rand(&mut rng, q);
            inputs.push(w);
        }

        // initialize consts
        for &i in circuit.const_refs.iter() {
            let q = i.modulus();
            let w = Wire::rand(&mut rng, q);
            consts.push(w);
        }

        let wires = Vec::with_capacity(circuit.gates.len());

        Garbler { circuit, wires, inputs, consts, deltas, current_wire: 0, rng }
    }

    /// Extract the const wires from the `Garbler`.
    pub fn consts(&self) -> Vec<Wire> {
        let cs = self.circuit.const_vals.as_ref().expect("constants needed!");
        operations::encode_consts(cs, &self.consts, &self.deltas)
    }

    /// Extract an `Encoder` from the `Garbler`.
    pub fn encoder(&self) -> Encoder {
        Encoder::new(self.inputs.clone(), self.deltas.clone())
    }

    /// Extract a `Decoder` from the `Garbler`. Fails if called before all wires have been
    /// generated using the iterator interface.
    pub fn decoder(&self) -> Result<Decoder, failure::Error> {
        if self.current_wire < self.circuit.gates.len() {
            return Err(failure::err_msg("Garbler::decoder called before all wires were generated"));
        }
        let outs = self.circuit.output_refs.iter().enumerate().map(|(i, &r)| {
            operations::garble_output(&self.wires[r.ix], i, &self.deltas)
        }).collect();
        Ok(Decoder::new(outs))
    }
}

impl <'a> Iterator for Garbler<'a> {
    type Item = GarbledGate;

    fn next(&mut self) -> Option<GarbledGate> {
        if self.current_wire >= self.circuit.gates.len() {
            return None;
        }

        let mut gate = None;

        while gate.is_none() {
            if self.current_wire >= self.circuit.gates.len() {
                return None;
            }

            let q = self.circuit.modulus(self.current_wire);

            let (w,g) = match self.circuit.gates[self.current_wire] {
                Gate::Input { id } => (self.inputs[id].clone(), None),
                Gate::Const { id } => (self.consts[id].clone(), None),

                Gate::Add { xref, yref } => (self.wires[xref.ix].plus(&self.wires[yref.ix]),  None),
                Gate::Sub { xref, yref } => (self.wires[xref.ix].minus(&self.wires[yref.ix]), None),
                Gate::Cmul { xref, c }   => (self.wires[xref.ix].cmul(c),                  None),

                Gate::Proj { xref, ref tt, .. } =>
                    operations::garble_projection(&self.wires[xref.ix], q, tt, self.current_wire, &self.deltas),

                Gate::HalfGate { xref, yref, .. } =>
                    operations::garble_half_gate(&self.wires[xref.ix], &self.wires[yref.ix], self.current_wire, &self.deltas, &mut self.rng),
            };

            self.wires.push(w);
            gate = g;
            self.current_wire += 1;
        }

        gate
    }
}

impl Encoder {
    pub fn new(inputs: Vec<Wire>, deltas: HashMap<u16,Wire>) -> Self {
        Encoder { inputs, deltas }
    }

    pub fn ninputs(&self) -> usize {
        self.inputs.len()
    }

    pub fn encode_input(&self, x: u16, id: usize) -> Wire {
        let X = &self.inputs[id];
        let q = X.modulus();
        X.plus(&self.deltas[&q].cmul(x))
    }

    pub fn encode(&self, inputs: &[u16]) -> Vec<Wire> {
        debug_assert_eq!(inputs.len(), self.inputs.len());
        (0..inputs.len()).zip(inputs.iter()).map(|(id,&x)| {
            self.encode_input(x,id)
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
                let h = ws[i].hash(operations::output_tweak(i,k));
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

impl Evaluator {
    pub fn new(gates: Vec<GarbledGate>, consts: Vec<Wire>) -> Self {
        Evaluator { gates, consts }
    }

    pub fn size(&self) -> usize {
        let mut c = self.consts.len();
        for g in self.gates.iter() {
            c += g.len();
        }
        c
    }

    pub fn eval(&self, c: &Circuit, inputs: &[Wire]) -> Vec<Wire> {
        let mut wires: Vec<Wire> = Vec::new();
        for i in 0..c.gates.len() {
            let q = c.modulus(i);
            let w = match c.gates[i] {

                Gate::Input { id }       => inputs[id].clone(),
                Gate::Const { id, .. }   => self.consts[id].clone(),
                Gate::Add { xref, yref } => wires[xref.ix].plus(&wires[yref.ix]),
                Gate::Sub { xref, yref } => wires[xref.ix].minus(&wires[yref.ix]),
                Gate::Cmul { xref, c }   => wires[xref.ix].cmul(c),

                Gate::Proj { xref, id, .. } => {
                    let x = &wires[xref.ix];
                    if x.color() == 0 {
                        x.hashback(i as u128, q)
                    } else {
                        let ct = self.gates[id][x.color() as usize - 1];
                        Wire::from_u128(ct ^ x.hash(i as u128), q)
                    }
                }

                Gate::HalfGate { xref, yref, id } => {
                    let g = operations::tweak2(i as u64, 0);

                    // garbler's half gate
                    let A = &wires[xref.ix];
                    let L = if A.color() == 0 {
                        A.hashback(g,q)
                    } else {
                        let ct_left = self.gates[id][A.color() as usize - 1];
                        Wire::from_u128(ct_left ^ A.hash(g), q)
                    };

                    // evaluator's half gate
                    let B = &wires[yref.ix];
                    let R = if B.color() == 0 {
                        B.hashback(g,q)
                    } else {
                        let ct_right = self.gates[id][(q + B.color()) as usize - 2];
                        Wire::from_u128(ct_right ^ B.hash(g), q)
                    };

                    // hack for unequal mods
                    let new_b_color = if xref.modulus() != yref.modulus() {
                        let minitable = *self.gates[id].last().unwrap();
                        let ct = minitable >> (B.color() * 16);
                        let pt = B.hash(operations::tweak2(i as u64, 1)) ^ ct;
                        pt as u16
                    } else {
                        B.color()
                    };

                    L.plus(&R.plus(&A.cmul(new_b_color)))
                }
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


#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::{Circuit, Builder};
    use crate::fancy::Fancy;
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
                let inps = (0..c.ninputs()).map(|i| { rng.gen_u16() % c.input_mod(i) }).collect_vec();
                let xs = &en.encode(&inps);
                let ys = &ev.eval(c, xs);
                let decoded = de.decode(ys)[0];
                let should_be = c.eval(&inps)[0];
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
            let x = b.input(q);
            let y = b.input(q);
            let z = b.add(x,y);
            b.output(z);
            b.finish()
        });
    }
//}}}
    #[test] // add_many {{{
    fn add_many() {
        garble_test_helper(|q| {
            let mut b = Builder::new();
            let xs = b.inputs(16, q);
            let z = b.add_many(&xs);
            b.output(z);
            b.finish()
        });
    }
//}}}
    #[test] // or_many {{{
    fn or_many() {
        garble_test_helper(|_| {
            let mut b = Builder::new();
            let xs = b.inputs(16, 2);
            let z = b.or_many(&xs);
            b.output(z);
            b.finish()
        });
    }
//}}}
    #[test] // sub {{{
    fn sub() {
        garble_test_helper(|q| {
            let mut b = Builder::new();
            let x = b.input(q);
            let y = b.input(q);
            let z = b.sub(x,y);
            b.output(z);
            b.finish()
        });
    }
//}}}
    #[test] // cmul {{{
    fn cmul() {
        garble_test_helper(|q| {
            let mut b = Builder::new();
            let x = b.input(q);
            let _ = b.input(q);
            let z;
            if q > 2 {
                z = b.cmul(x, 2);
            } else {
                z = b.cmul(x, 1);
            }
            b.output(z);
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
            let x = b.input(q);
            let _ = b.input(q);
            let z = b.proj(x, q, tab);
            b.output(z);
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
            let x = b.input(q);
            let _ = b.input(q);
            let z = b.proj(x, q, tab);
            b.output(z);
            b.finish()
        });
    }
//}}}
    #[test] // mod_change {{{
    fn mod_change() {
        garble_test_helper(|q| {
            let mut b = Builder::new();
            let x = b.input(q);
            let z = b.mod_change(&x,q*2);
            b.output(z);
            b.finish()
        });
    }
//}}}
    #[test] // half_gate {{{
    fn half_gate() {
        garble_test_helper(|q| {
            let mut b = Builder::new();
            let x = b.input(q);
            let y = b.input(q);
            let z = b.half_gate(x,y);
            b.output(z);
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
            let x = b.input(q);
            let y = b.input(ymod);
            let z = b.half_gate(x,y);
            b.output(z);
            let c = b.finish();

            let (en, de, ev) = garble(&c);

            let mut fail = false;
            for x in 0..q {
                for y in 0..ymod {
                    println!("TEST x={} y={}", x,y);
                    let xs = &en.encode(&[x,y]);
                    let ys = &ev.eval(&c, xs);
                    let decoded = de.decode(ys)[0];
                    let should_be = c.eval(&[x,y])[0];
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
        let mods = (0..7).map(|_| rng.gen_modulus()).collect_vec();
        // let nargs = 97;
        // let mods = [37,10,10,54,100,51,17];

        let mut b = Builder::new();
        let xs = (0..nargs).map(|_| {
            mods.iter().map(|&q| b.input(q)).collect_vec()
        }).collect_vec();
        let zs = b.mixed_radix_addition(&xs);
        b.outputs(&zs);
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
            let X = en.encode(&ds);
            let Y = ev.eval(&circ, &X);
            let res = de.decode(&Y);
            assert_eq!(util::from_mixed_radix(&res,&mods), should_be);
        }
    }
//}}}
    #[test] // constants {{{
    fn constants() {
        let mut b = Builder::new();
        let mut rng = thread_rng();

        let q = rng.gen_modulus();
        let c = rng.gen_u16() % q;

        let x = b.input(q);
        let y = b.constant(c,q);
        let z = b.add(x,y);
        b.output(z);

        let circ = b.finish();
        let (en, de, ev) = garble(&circ);

        for _ in 0..64 {
            let x = rng.gen_u16() % q;

            assert_eq!(circ.eval(&[x])[0], (x+c)%q, "plaintext");

            let X = en.encode(&[x]);
            let Y = ev.eval(&circ, &X);
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
        let xs = (0..nargs).map(|_| {
            mods.iter().map(|&q| b.input(q)).collect_vec()
        }).collect_vec();
        let zs = b.mixed_radix_addition(&xs);
        b.outputs(&zs);
        let circ = b.finish();

        let (en, de, ev) = garble(&circ);

        assert_eq!(ev, Evaluator::from_bytes(&ev.to_bytes()).unwrap());
        assert_eq!(en, Encoder::from_bytes(&en.to_bytes()).unwrap());
        assert_eq!(de, Decoder::from_bytes(&de.to_bytes()).unwrap());
    }
//}}}
}
