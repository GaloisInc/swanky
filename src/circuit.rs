//! DSL for creating circuits compatible with fancy-garbling.

pub mod crt;

use itertools::Itertools;
use serde_derive::{Serialize, Deserialize};
use std::collections::HashMap;
use crate::fancy::Fancy;

/// The index of a `Gate` in a `Circuit`.
pub type Ref = usize;

/// The index of an input, const, or garbled gate.
pub type Id = usize;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Circuit {
    pub gates: Vec<Gate>,
    pub gate_moduli: Vec<u16>,
    pub input_refs: Vec<Ref>,
    pub const_refs: Vec<Ref>,
    pub output_refs: Vec<Ref>,
    pub const_vals: Option<Vec<u16>>,
    pub num_nonfree_gates: usize,
}

/// the lowest-level circuit description in Fancy Garbling
/// consists of 6 gate types:
/// * input
/// * addition
/// * subtraction
/// * scalar multiplication
/// * projection gates
/// * generalized half-gate multiplication
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum Gate {
    Input { id: Id },                                           // id is the input id
    Const { id: Id },                                           // id is the const id
    Add { xref: Ref, yref: Ref },
    Sub { xref: Ref, yref: Ref },
    Cmul { xref: Ref, c: u16 },
    Proj { xref: Ref, tt: Vec<u16>, id: Id },                   // id is the gate number
    HalfGate { xref: Ref, yref: Ref, id: Id },                  // id is the gate number
}

impl Circuit {
    pub fn eval(&self, inputs: &[u16]) -> Vec<u16> {
        assert_eq!(inputs.len(), self.ninputs(),
            "[circuit.eval] needed {} inputs but got {}!",
            self.ninputs(), inputs.len()
        );

        let mut cache = vec![0;self.gates.len()];
        for zref in 0..self.gates.len() {
            let q = self.gate_moduli[zref];
            let val = match self.gates[zref] {

                Gate::Input { id } => inputs[id],

                Gate::Const { id } => {
                    assert!(id < self.const_vals.as_ref().map_or(0, |cs| cs.len()),
                            "[eval_full] not enough constants provided");
                    self.const_vals.as_ref().expect("no consts provided")[id]
                }

                Gate::Add { xref, yref } => (cache[xref] + cache[yref]) % q,
                Gate::Sub { xref, yref } => (cache[xref] + q - cache[yref]) % q,

                Gate::Cmul { xref, c } => cache[xref] * c % q,

                Gate::Proj { xref, ref tt, .. } => tt[cache[xref] as usize],

                Gate::HalfGate { xref, yref, .. } =>
                    (cache[xref] * cache[yref] % q),
            };
            cache[zref] = val;
        }
        self.output_refs.iter().map(|outref| cache[*outref]).collect()
    }

    pub fn ninputs(&self) -> usize { self.input_refs.len() }
    pub fn noutputs(&self) -> usize { self.output_refs.len() }
    pub fn modulus(&self, x: Ref) -> u16 { self.gate_moduli[x] }

    pub fn input_mod(&self, id: Id) -> u16 {
        let r = self.input_refs[id];
        self.gate_moduli[r]
    }

    pub fn clear_consts(&mut self) {
        self.const_vals = None;
    }

    pub fn print_info(&self) {
        let mut nconst = 0;
        let mut nadd = 0;
        let mut nsub = 0;
        let mut ncmul = 0;
        let mut nproj = 0;
        let mut nhalfgate = 0;

        for g in self.gates.iter() {
            match g {
                Gate::Input    { .. } => (),
                Gate::Const    { .. } => nconst    += 1,
                Gate::Add      { .. } => nadd      += 1,
                Gate::Sub      { .. } => nsub      += 1,
                Gate::Cmul     { .. } => ncmul     += 1,
                Gate::Proj     { .. } => nproj     += 1,
                Gate::HalfGate { .. } => nhalfgate += 1,
            }
        }

        println!("circuit info:");
        println!("  ninputs:      {}", self.ninputs());
        println!("  noutputs:     {}", self.noutputs());
        println!("  nconsts:      {}", nconst);
        println!("");
        println!("  additions:    {}", nadd);
        println!("  subtractions: {}", nsub);
        println!("  cmuls:        {}", ncmul);
        println!("  projections:  {}", nproj);
        println!("  halfgates:    {}", nhalfgate);
        println!("");
        println!("  total non-free gates: {}", self.num_nonfree_gates);
        println!("");
    }

    pub  fn to_file(&self, filename: &str) -> Result<(), failure::Error> {
        let f = std::fs::File::create(filename)?;
        serde_json::to_writer(f, self)
            .map_err(|_| failure::err_msg("error writing json into file"))
    }

    pub fn from_file(filename: &str) -> Result<Circuit, failure::Error> {
        let f = std::fs::File::open(filename)?;
        serde_json::from_reader(f).map_err(|why| {
            failure::format_err!("failed to parse json: line {} column {}", why.line(), why.column())
        })
    }

    pub fn to_string(&self) -> String {
        serde_json::to_string(self).expect("couldn't serialize circuit")
    }

    pub fn from_str(s: &str) -> Result<Circuit, failure::Error> {
        serde_json::from_str(s).map_err(|why| {
            failure::format_err!("failed to parse json: line {} column {}", why.line(), why.column())
        })
    }
}

/// The `Builder` is a DSL to conveniently make a `Circuit`.
pub struct Builder {
    next_ref: Ref,
    next_input_id: Id,
    const_map: HashMap<(u16,u16), Ref>,
    pub circ: Circuit,
}

impl Builder {
    pub fn new() -> Self {
        let c = Circuit {
            gates: Vec::new(),
            input_refs: Vec::new(),
            const_refs: Vec::new(),
            output_refs: Vec::new(),
            gate_moduli: Vec::new(),
            const_vals: Some(Vec::new()),
            num_nonfree_gates: 0,
        };
        Builder {
            next_ref: 0,
            next_input_id: 0,
            const_map: HashMap::new(),
            circ: c
        }
    }

    pub fn finish(self) -> Circuit {
        self.circ
    }

    pub fn borrow_circ(&self) -> &Circuit {
        &self.circ
    }

    pub fn modulus(&self, x:Ref) -> u16 {
        self.circ.modulus(x)
    }

    fn get_next_input_id(&mut self) -> Id {
        let id = self.next_input_id;
        self.next_input_id += 1;
        id
    }

    fn get_next_ciphertext_id(&mut self) -> Id {
        let id = self.circ.num_nonfree_gates;
        self.circ.num_nonfree_gates += 1;
        id
    }

    fn get_next_ref(&mut self) -> Ref {
        let x = self.next_ref;
        self.next_ref += 1;
        x
    }

    fn gate(&mut self, gate: Gate, modulus: u16) -> Ref {
        self.circ.gates.push(gate);
        self.circ.gate_moduli.push(modulus);
        self.get_next_ref()
    }

    pub fn input(&mut self, modulus: u16) -> Ref {
        let gate = Gate::Input { id: self.get_next_input_id() };
        let r = self.gate(gate, modulus);
        self.circ.input_refs.push(r);
        r
    }

    pub fn inputs(&mut self, n: usize, modulus: u16) -> Vec<Ref> {
        (0..n).map(|_| self.input(modulus)).collect()
    }

    /// creates a new, secret, constant for each call
    pub fn secret_constant(&mut self, val: u16, modulus: u16) -> Ref {
        let id = self.circ.const_vals.as_ref().map_or(0, |cs| cs.len());
        if let Some(cs) = self.circ.const_vals.as_mut() { cs.push(val) }
        let gate = Gate::Const { id };
        let r = self.gate(gate, modulus);
        self.circ.const_refs.push(r);
        r
    }

    /// reuses constants if they already exist in the circuit
    pub fn constant(&mut self, val: u16, modulus: u16) -> Ref {
        match self.const_map.get(&(val, modulus)) {
            Some(&r) => r,
            None => {
                let id = self.circ.const_vals.as_ref().map_or(0, |cs| cs.len());
                if let Some(cs) = self.circ.const_vals.as_mut() { cs.push(val) }
                let gate = Gate::Const { id };
                let r = self.gate(gate, modulus);
                self.const_map.insert((val,modulus), r);
                self.circ.const_refs.push(r);
                r
            }
        }
    }

    pub fn output(&mut self, xref: Ref) {
        self.circ.output_refs.push(xref);
    }

    pub fn outputs(&mut self, xs: &[Ref]) {
        for &x in xs.iter() {
            self.output(x);
        }
    }

    pub fn add(&mut self, xref: Ref, yref: Ref) -> Ref {
        assert!(xref < self.next_ref);
        assert!(yref < self.next_ref);
        let xmod = self.circ.gate_moduli[xref];
        let ymod = self.circ.gate_moduli[yref];
        assert!(xmod == ymod, "xmod={} ymod={}", xmod, ymod);
        let gate = Gate::Add { xref, yref };
        self.gate(gate, xmod)
    }

    pub fn sub(&mut self, xref: Ref, yref: Ref) -> Ref {
        assert!(xref < self.next_ref);
        assert!(yref < self.next_ref);
        let xmod = self.circ.gate_moduli[xref];
        let ymod = self.circ.gate_moduli[yref];
        assert!(xmod == ymod);
        let gate = Gate::Sub { xref, yref };
        self.gate(gate, xmod)
    }

    pub fn cmul(&mut self, xref: Ref, c: u16) -> Ref {
        let q = self.modulus(xref);
        self.gate(Gate::Cmul { xref, c }, q)
    }

    pub fn proj(&mut self, xref: Ref, output_modulus: u16, tt: Vec<u16>) -> Ref {
        assert_eq!(tt.len(), self.circ.gate_moduli[xref] as usize);
        assert!(tt.iter().all(|&x| x < output_modulus),
            "not all xs were less than the output modulus! circuit.proj: tt={:?},
            output_modulus={}", tt, output_modulus);
        let q = output_modulus;
        let gate = Gate::Proj { xref, tt, id: self.get_next_ciphertext_id() };
        self.gate(gate, q)
    }

    pub fn half_gate(&mut self, xref: Ref, yref: Ref) -> Ref {
        if self.modulus(xref) < self.modulus(yref) {
            return self.half_gate(yref, xref);
        }

        let gate = Gate::HalfGate {
            xref,
            yref,
            id: self.get_next_ciphertext_id(),
        };

        let q = self.modulus(xref);
        self.gate(gate, q)
    }

}

impl Fancy for Builder {
    type Item = Ref;

    fn constant(&mut self, id: usize, val_and_mod: Option<(u16,u16)>) -> Ref {
        unimplemented!()
    }

    fn add(&mut self, x: &Ref, y: &Ref) -> Ref { self.add(*x, *y) }
    fn sub(&mut self, x: &Ref, y: &Ref) -> Ref { self.sub(*x, *y) }
    fn mul(&mut self, x: &Ref, y: &Ref) -> Ref { self.half_gate(*x, *y) }
    fn cmul(&mut self, x: &Ref, c: u16) -> Ref { self.cmul(*x, c) }
    fn proj(&mut self, x: &Ref, q: u16, tt: Vec<u16>) -> Ref { self.proj(*x, q, tt) }

    fn modulus(&self, x: &Ref) -> u16 { self.modulus(*x) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{self, RngExt};
    use rand;
    use itertools::Itertools;

    #[test] // {{{ and_gate_fan_n
    fn and_gate_fan_n() {
        let mut rng = rand::thread_rng();
        let mut b = Builder::new();
        let mut inps = Vec::new();
        let n = 2 + (rng.gen_usize() % 200);
        for _ in 0..n {
            inps.push(b.input(2));
        }
        let z = b.and_many(&inps);
        b.output(z);
        let c = b.finish();

        for _ in 0..16 {
            let mut inps: Vec<u16> = Vec::new();
            for _ in 0..n {
                inps.push(rng.gen_bool() as u16);
            }
            let res = inps.iter().fold(1, |acc, &x| x & acc);
            assert_eq!(c.eval(&inps)[0], res);
        }
    }
//}}}
    #[test] // {{{ or_gate_fan_n
    fn or_gate_fan_n() {
        let mut rng = rand::thread_rng();
        let mut b = Builder::new();
        let mut inps = Vec::new();
        let n = 2 + (rng.gen_usize() % 200);
        for _ in 0..n {
            inps.push(b.input(2));
        }
        let z = b.or_many(&inps);
        b.output(z);
        let c = b.finish();

        for _ in 0..16 {
            let mut inps: Vec<u16> = Vec::new();
            for _ in 0..n {
                inps.push(rng.gen_bool() as u16);
            }
            let res = inps.iter().fold(0, |acc, &x| x | acc);
            let out = c.eval(&inps)[0];
            if !(out == res) {
                println!("{:?} {} {}", inps, out, res);
                panic!();
            }
        }
    }
//}}}
    #[test] // {{{ half_gate
    fn half_gate() {
        let mut rng = rand::thread_rng();
        let mut b = Builder::new();
        let q = rng.gen_prime();
        let x = b.input(q);
        let y = b.input(q);
        let z = b.half_gate(x,y);
        b.output(z);
        let c = b.finish();
        for _ in 0..16 {
            let x = rng.gen_u16() % q;
            let y = rng.gen_u16() % q;
            assert_eq!(c.eval(&vec![x,y])[0], x * y % q);
        }
    }
//}}}
    #[test] // mod_change {{{
    fn mod_change() {
        let mut rng = rand::thread_rng();
        let mut b = Builder::new();
        let p = rng.gen_prime();
        let q = rng.gen_prime();
        let x = b.input(p);
        let y = b.mod_change(x, q);
        let z = b.mod_change(y, p);
        b.output(z);
        let c = b.finish();
        for _ in 0..16 {
            let x = rng.gen_u16() % p;
            assert_eq!(c.eval(&vec![x])[0], x % q);
        }
    }
//}}}
    #[test] // binary_addition {{{
    fn binary_addition() {
        let mut b = Builder::new();
        let xs = b.inputs(128, 2);
        let ys = b.inputs(128, 2);
        let (zs, c) = b.addition(&xs, &ys);
        b.outputs(&zs);
        b.output(c);
        let c = b.finish();
        let mut rng = rand::thread_rng();
        for _ in 0..16 {
            let x = rng.gen_u128();
            let y = rng.gen_u128();
            let mut bits = util::u128_to_bits(x, 128);
            bits.extend(util::u128_to_bits(y, 128).iter());
            let res = c.eval(&bits);
            let (z, carry) = x.overflowing_add(y);
            assert_eq!(util::u128_from_bits(&res[0..128]), z);
            assert_eq!(res[128], carry as u16);
        }
    }
//}}}
    #[test] // binary_addition_no_carry {{{
    fn binary_addition_no_carry() {
        let mut b = Builder::new();
        let xs = b.inputs(128, 2);
        let ys = b.inputs(128, 2);
        let zs = b.addition_no_carry(&xs, &ys);
        b.outputs(&zs);
        let c = b.finish();
        let mut rng = rand::thread_rng();
        for _ in 0..16 {
            let x = rng.gen_u128();
            let y = rng.gen_u128();
            let mut bits = util::u128_to_bits(x, 128);
            bits.extend(util::u128_to_bits(y, 128).iter());
            let res = c.eval(&bits);
            let (z, _carry) = x.overflowing_add(y);
            assert_eq!(util::u128_from_bits(&res[0..128]), z);
        }
    }

//}}}
    #[test] // binary_subtraction {{{
    fn binary_subtraction() {
        let mut b = Builder::new();
        let xs = b.inputs(128, 2);
        let ys = b.inputs(128, 2);
        let (zs, c) = b.binary_subtraction(&xs, &ys);
        b.outputs(&zs);
        b.output(c);
        let circ = b.finish();
        let mut rng = rand::thread_rng();
        for _ in 0..16 {
            let x = rng.gen_u128();
            let y = rng.gen_u128();
            let mut bits = util::u128_to_bits(x, 128);
            bits.extend(util::u128_to_bits(y, 128).iter());
            let res = circ.eval(&bits);
            let (z, carry) = x.overflowing_sub(y);
            assert_eq!(util::u128_from_bits(&res[0..128]), z);
            assert_eq!(res[128], carry as u16);
        }
    }
//}}}
    #[test] // add_many_mod_change {{{
    fn add_many_mod_change() {
        let mut b = Builder::new();
        let n = 113;
        let args = b.inputs(n, 2);
        let wires: Vec<_> = args.iter().map(|&x| {
            b.mod_change(x, n as u16 + 1)
        }).collect();
        let s = b.add_many(&wires);
        b.output(s);
        let c = &b.finish();

        let mut rng = rand::thread_rng();
        for _ in 0..64 {
            let inps: Vec<u16> = (0..c.ninputs()).map(|i| {
                rng.gen_u16() % c.input_mod(i)
            }).collect();
            let s: u16 = inps.iter().sum();
            println!("{:?}, sum={}", inps, s);
            assert_eq!(c.eval(&inps)[0], s);
        }
    }
// }}}
    #[test] // base_4_addition_no_carry {{{
    fn base_q_addition_no_carry() {
        let mut b = Builder::new();
        let mut rng = rand::thread_rng();

        let q = rng.gen_modulus();
        let n = 16;
        let xs = b.inputs(n,q);
        let ys = b.inputs(n,q);
        let zs = b.addition_no_carry(&xs, &ys);
        b.outputs(&zs);
        let c = b.finish();

        // test maximum overflow
        let Q = (q as u128).pow(n as u32);
        let x = Q - 1;
        let y = Q - 1;
        let mut ds = util::as_base_q(x,q,n);
        ds.extend(util::as_base_q(y,q,n).iter());
        let res = c.eval(&ds);
        let (z, _carry) = x.overflowing_add(y);
        assert_eq!(util::from_base_q(&res, q), z % Q);

        // test random values
        for _ in 0..64 {
            let Q = (q as u128).pow(n as u32);
            let x = rng.gen_u128() % Q;
            let y = rng.gen_u128() % Q;
            let mut ds = util::as_base_q(x,q,n);
            ds.extend(util::as_base_q(y,q,n).iter());
            let res = c.eval(&ds);
            let (z, _carry) = x.overflowing_add(y);
            assert_eq!(util::from_base_q(&res, q), z % Q);
        }
    }
//}}}
    #[test] // fancy_addition {{{
    fn fancy_addition() {
        let mut rng = rand::thread_rng();

        let nargs = 2 + rng.gen_usize() % 100;
        let mods = (0..7).map(|_| rng.gen_modulus()).collect_vec();

        let mut b = Builder::new();
        let xs = (0..nargs).map(|_| {
            mods.iter().map(|&q| b.input(q)).collect_vec()
        }).collect_vec();
        let zs = b.fancy_addition(&xs);
        b.outputs(&zs);
        let circ = b.finish();

        let Q: u128 = mods.iter().map(|&q| q as u128).product();

        // test maximum overflow
        let mut ds = Vec::new();
        for _ in 0..nargs {
            ds.extend(util::as_mixed_radix(Q-1, &mods).iter());
        }
        let res = circ.eval(&ds);
        assert_eq!(util::from_mixed_radix(&res,&mods), (Q-1)*(nargs as u128) % Q);

        // test random values
        for _ in 0..64 {
            let mut should_be = 0;
            let mut ds = Vec::new();
            for _ in 0..nargs {
                let x = rng.gen_u128() % Q;
                should_be = (should_be + x) % Q;
                ds.extend(util::as_mixed_radix(x, &mods).iter());
            }
            let res = circ.eval(&ds);
            assert_eq!(util::from_mixed_radix(&res,&mods), should_be);
        }
    }
//}}}
    #[test] // constants {{{
    fn constants() {
        let mut b = Builder::new();
        let mut rng = rand::thread_rng();

        let q = rng.gen_modulus();
        let c = rng.gen_u16() % q;

        let x = b.input(q);
        let y = b.constant(c,q);
        let z = b.add(x,y);
        b.output(z);

        let circ = b.finish();

        for _ in 0..64 {
            let x = rng.gen_u16() % q;
            let z = circ.eval(&[x]);
            assert_eq!(z[0], (x+c)%q);
        }
    }
//}}}
    #[test] // serialization {{{
    fn serialization() {
        let mut rng = rand::thread_rng();

        let nargs = 2 + rng.gen_usize() % 100;
        let mods = (0..7).map(|_| rng.gen_modulus()).collect_vec();

        let mut b = Builder::new();
        let xs = (0..nargs).map(|_| {
            mods.iter().map(|&q| b.input(q)).collect_vec()
        }).collect_vec();
        let zs = b.fancy_addition(&xs);
        b.outputs(&zs);
        let circ = b.finish();

        println!("{}", circ.to_string());

        assert_eq!(circ, Circuit::from_str(&circ.to_string()).unwrap());
    }
//}}}

}
