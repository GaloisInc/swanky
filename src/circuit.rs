//! DSL for creating circuits compatible with fancy-garbling in the old-fashioned way,
//! where you create a circuit for a computation then garble it.

use serde_derive::{Serialize, Deserialize};
use std::collections::HashMap;
use crate::fancy::{Fancy, BundleGadgets, HasModulus, Bundle};

/// The index and modulus of a `Gate` in a `Circuit`.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct Ref {
    pub ix: usize,
    modulus: u16,
}

impl HasModulus for Ref {
    fn modulus(&self) -> u16 { self.modulus }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Circuit {
    pub gates: Vec<Gate>,
    pub gate_moduli: Vec<u16>,
    pub garbler_input_refs: Vec<Ref>,
    pub evaluator_input_refs: Vec<Ref>,
    pub const_refs: Vec<Ref>,
    pub output_refs: Vec<Ref>,
    pub const_vals: Vec<u16>,
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
    GarblerInput { id: usize },
    EvaluatorInput { id: usize },
    Const { id: usize },
    Add { xref: Ref, yref: Ref },
    Sub { xref: Ref, yref: Ref },
    Cmul { xref: Ref, c: u16 },
    Proj { xref: Ref, tt: Vec<u16>, id: usize },  // id is the gate number
    HalfGate { xref: Ref, yref: Ref, id: usize }, // id is the gate number
}

impl Circuit {
    pub fn eval(&self, garbler_inputs: &[u16], evaluator_inputs: &[u16]) -> Vec<u16> {
        assert_eq!(garbler_inputs.len(), self.num_garbler_inputs(),
            "[circuit.eval] needed {} garbler inputs but got {}!",
            self.num_garbler_inputs(), garbler_inputs.len()
        );

        assert_eq!(evaluator_inputs.len(), self.num_evaluator_inputs(),
            "[circuit.eval] needed {} garbler inputs but got {}!",
            self.num_evaluator_inputs(), evaluator_inputs.len()
        );

        let mut cache = vec![0;self.gates.len()];
        for zref in 0..self.gates.len() {
            let q = self.gate_moduli[zref];
            let val = match self.gates[zref] {

                Gate::GarblerInput   { id } => garbler_inputs[id],
                Gate::EvaluatorInput { id } => evaluator_inputs[id],

                Gate::Const { id } => self.const_vals[id],

                Gate::Add { xref, yref } => (cache[xref.ix] + cache[yref.ix]) % q,
                Gate::Sub { xref, yref } => (cache[xref.ix] + q - cache[yref.ix]) % q,

                Gate::Cmul { xref, c } => cache[xref.ix] * c % q,

                Gate::Proj { xref, ref tt, .. } => tt[cache[xref.ix] as usize],

                Gate::HalfGate { xref, yref, .. } =>
                    (cache[xref.ix] * cache[yref.ix] % q),
            };
            cache[zref] = val;
        }
        self.output_refs.iter().map(|outref| cache[outref.ix]).collect()
    }

    pub fn num_garbler_inputs(&self) -> usize { self.garbler_input_refs.len() }

    pub fn num_evaluator_inputs(&self) -> usize { self.evaluator_input_refs.len() }

    pub fn noutputs(&self) -> usize { self.output_refs.len() }

    pub fn modulus(&self, gate_num: usize) -> u16 {
        self.gate_moduli[gate_num]
    }

    pub fn garbler_input_mod(&self, id: usize) -> u16 {
        let r = self.garbler_input_refs[id];
        r.modulus()
    }

    pub fn evaluator_input_mod(&self, id: usize) -> u16 {
        let r = self.evaluator_input_refs[id];
        r.modulus()
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
                Gate::GarblerInput   { .. } => (),
                Gate::EvaluatorInput { .. } => (),
                Gate::Const          { .. } => nconst    += 1,
                Gate::Add            { .. } => nadd      += 1,
                Gate::Sub            { .. } => nsub      += 1,
                Gate::Cmul           { .. } => ncmul     += 1,
                Gate::Proj           { .. } => nproj     += 1,
                Gate::HalfGate       { .. } => nhalfgate += 1,
            }
        }

        println!("circuit info:");
        println!("  garbler inputs:   {}", self.num_garbler_inputs());
        println!("  evaluator inputs: {}", self.num_evaluator_inputs());
        println!("  noutputs:         {}", self.noutputs());
        println!("  nconsts:          {}", nconst);
        println!("");
        println!("  additions:        {}", nadd);
        println!("  subtractions:     {}", nsub);
        println!("  cmuls:            {}", ncmul);
        println!("  projections:      {}", nproj);
        println!("  halfgates:        {}", nhalfgate);
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

/// The `Builder` struct is used to make a `Circuit`.
pub struct Builder {
    next_ref_ix: usize,
    next_garbler_input_id: usize,
    next_evaluator_input_id: usize,
    const_map: HashMap<(u16,u16), Ref>,
    pub circ: Circuit,
}

impl Fancy for Builder {
    type Wire = Ref;

    fn garbler_input(&mut self, modulus: u16) -> Ref {
        let gate = Gate::GarblerInput { id: self.get_next_garbler_input_id() };
        let r = self.gate(gate, modulus);
        self.circ.garbler_input_refs.push(r);
        r
    }

    fn evaluator_input(&mut self, modulus: u16) -> Ref {
        let gate = Gate::EvaluatorInput { id: self.get_next_evaluator_input_id() };
        let r = self.gate(gate, modulus);
        self.circ.evaluator_input_refs.push(r);
        r
    }

    fn constant(&mut self, val: u16, modulus: u16) -> Ref {
        match self.const_map.get(&(val, modulus)) {
            Some(&r) => r,
            None => {
                let id = self.circ.const_vals.len();
                self.circ.const_vals.push(val);
                let gate = Gate::Const { id };
                let r = self.gate(gate, modulus);
                self.const_map.insert((val,modulus), r);
                self.circ.const_refs.push(r);
                r
            }
        }
    }

    fn add(&mut self, xref: &Ref, yref: &Ref) -> Ref {
        assert!(xref.modulus() == yref.modulus(), "xmod={} ymod={}", xref.modulus(), yref.modulus());
        let gate = Gate::Add { xref: *xref, yref: *yref };
        self.gate(gate, xref.modulus())
    }

    fn sub(&mut self, xref: &Ref, yref: &Ref) -> Ref {
        assert!(xref.modulus() == yref.modulus(), "xmod={} ymod={}", xref.modulus(), yref.modulus());
        let gate = Gate::Sub { xref: *xref, yref: *yref };
        self.gate(gate, xref.modulus())
    }

    fn cmul(&mut self, xref: &Ref, c: u16) -> Ref {
        self.gate(Gate::Cmul { xref: *xref, c }, xref.modulus())
    }

    fn proj(&mut self, xref: &Ref, output_modulus: u16, tt: Vec<u16>) -> Ref {
        assert_eq!(tt.len(), xref.modulus() as usize);
        assert!(tt.iter().all(|&x| x < output_modulus),
            "not all xs were less than the output modulus! circuit.proj: tt={:?},
            output_modulus={}", tt, output_modulus);
        let gate = Gate::Proj { xref: *xref, tt, id: self.get_next_ciphertext_id() };
        self.gate(gate, output_modulus)
    }

    fn mul(&mut self, xref: &Ref, yref: &Ref) -> Ref {
        if xref.modulus() < yref.modulus() {
            return self.mul(yref, xref);
        }

        let gate = Gate::HalfGate {
            xref: *xref,
            yref: *yref,
            id: self.get_next_ciphertext_id(),
        };

        self.gate(gate, xref.modulus())
    }

}

impl BundleGadgets for Builder { }

impl Builder {
    pub fn new() -> Self {
        let c = Circuit {
            gates: Vec::new(),
            garbler_input_refs: Vec::new(),
            evaluator_input_refs: Vec::new(),
            const_refs: Vec::new(),
            output_refs: Vec::new(),
            gate_moduli: Vec::new(),
            const_vals: Vec::new(),
            num_nonfree_gates: 0,
        };
        Builder {
            next_ref_ix: 0,
            next_garbler_input_id: 0,
            next_evaluator_input_id: 0,
            const_map: HashMap::new(),
            circ: c
        }
    }

    pub fn modulus(&self, x: Ref) -> u16 {
        x.modulus()
    }

    pub fn finish(self) -> Circuit {
        self.circ
    }

    pub fn borrow_circ(&self) -> &Circuit {
        &self.circ
    }

    fn get_next_garbler_input_id(&mut self) -> usize {
        let id = self.next_garbler_input_id;
        self.next_garbler_input_id += 1;
        id
    }

    fn get_next_evaluator_input_id(&mut self) -> usize {
        let id = self.next_evaluator_input_id;
        self.next_evaluator_input_id += 1;
        id
    }

    fn get_next_ciphertext_id(&mut self) -> usize {
        let id = self.circ.num_nonfree_gates;
        self.circ.num_nonfree_gates += 1;
        id
    }

    fn get_next_ref_ix(&mut self) -> usize {
        let x = self.next_ref_ix;
        self.next_ref_ix += 1;
        x
    }

    fn gate(&mut self, gate: Gate, modulus: u16) -> Ref {
        self.circ.gates.push(gate);
        self.circ.gate_moduli.push(modulus);
        let ix = self.get_next_ref_ix();
        Ref { ix, modulus }
    }

    /// Mark `xref` as an output of the circuit.
    pub fn output(&mut self, xref: Ref) {
        self.circ.output_refs.push(xref);
    }

    /// Mark each `Ref` in `xs` as an output of the circuit.
    pub fn outputs(&mut self, xs: &[Ref]) {
        for &x in xs.iter() {
            self.output(x);
        }
    }

    pub fn output_bundle(&mut self, x: &Bundle<Ref>) {
        for &w in x.wires() {
            self.output(w);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{self, RngExt, crt_factor, crt_inv_factor};
    use itertools::Itertools;
    use rand::thread_rng;

    #[test] // {{{ and_gate_fan_n
    fn and_gate_fan_n() {
        let mut rng = thread_rng();
        let mut b = Builder::new();
        let n = 2 + (rng.gen_usize() % 200);
        let inps = b.evaluator_inputs(2,n);
        let z = b.and_many(&inps);
        b.output(z);
        let c = b.finish();

        for _ in 0..16 {
            let mut inps: Vec<u16> = Vec::new();
            for _ in 0..n {
                inps.push(rng.gen_bool() as u16);
            }
            let res = inps.iter().fold(0, |acc, &x| x & acc);
            let out = c.eval(&[],&inps)[0];
            if !(out == res) {
                println!("{:?} {} {}", inps, out, res);
                panic!();
            }
        }
    }
//}}}
    #[test] // {{{ or_gate_fan_n
    fn or_gate_fan_n() {
        let mut rng = thread_rng();
        let mut b = Builder::new();
        let n = 2 + (rng.gen_usize() % 200);
        let inps = b.evaluator_inputs(2,n);
        let z = b.or_many(&inps);
        b.output(z);
        let c = b.finish();

        for _ in 0..16 {
            let mut inps: Vec<u16> = Vec::new();
            for _ in 0..n {
                inps.push(rng.gen_bool() as u16);
            }
            let res = inps.iter().fold(0, |acc, &x| x | acc);
            let out = c.eval(&[],&inps)[0];
            if !(out == res) {
                println!("{:?} {} {}", inps, out, res);
                panic!();
            }
        }
    }
//}}}
    #[test] // {{{ half_gate
    fn half_gate() {
        let mut rng = thread_rng();
        let mut b = Builder::new();
        let q = rng.gen_prime();
        let x = b.garbler_input(q);
        let y = b.evaluator_input(q);
        let z = b.mul(&x,&y);
        b.output(z);
        let c = b.finish();
        for _ in 0..16 {
            let x = rng.gen_u16() % q;
            let y = rng.gen_u16() % q;
            assert_eq!(c.eval(&[x],&[y])[0], x * y % q);
        }
    }
//}}}
    #[test] // mod_change {{{
    fn mod_change() {
        let mut rng = thread_rng();
        let mut b = Builder::new();
        let p = rng.gen_prime();
        let q = rng.gen_prime();
        let x = b.garbler_input(p);
        let y = b.mod_change(&x, q);
        let z = b.mod_change(&y, p);
        b.output(z);
        let c = b.finish();
        for _ in 0..16 {
            let x = rng.gen_u16() % p;
            assert_eq!(c.eval(&[x],&[])[0], x % q);
        }
    }
//}}}
    #[test] // add_many_mod_change {{{
    fn add_many_mod_change() {
        let mut b = Builder::new();
        let n = 113;
        let args = b.garbler_inputs(2,n);
        let wires = args.iter().map(|x| b.mod_change(x, n as u16 + 1)).collect_vec();
        let s = b.add_many(&wires);
        b.output(s);
        let c = b.finish();

        let mut rng = thread_rng();
        for _ in 0..64 {
            let inps = (0..c.num_garbler_inputs()).map(|i| {
                rng.gen_u16() % c.garbler_input_mod(i)
            }).collect_vec();
            let s: u16 = inps.iter().sum();
            println!("{:?}, sum={}", inps, s);
            assert_eq!(c.eval(&inps, &[])[0], s);
        }
    }
// }}}
    #[test] // constants {{{
    fn constants() {
        let mut b = Builder::new();
        let mut rng = thread_rng();

        let q = rng.gen_modulus();
        let c = rng.gen_u16() % q;

        let x = b.evaluator_input(q);
        let y = b.constant(c,q);
        let z = b.add(&x,&y);
        b.output(z);

        let circ = b.finish();

        for _ in 0..64 {
            let x = rng.gen_u16() % q;
            let z = circ.eval(&[],&[x]);
            assert_eq!(z[0], (x+c)%q);
        }
    }
//}}}
    #[test] // serialization {{{
    fn serialization() {
        let mut rng = thread_rng();

        let nargs = 2 + rng.gen_usize() % 100;
        let mods = (0..7).map(|_| rng.gen_modulus()).collect_vec();

        let mut b = Builder::new();
        let xs = b.evaluator_input_bundles(&mods, nargs);
        let z = b.mixed_radix_addition(&xs);
        b.output_bundle(&z);
        let circ = b.finish();

        println!("{}", circ.to_string());

        assert_eq!(circ, Circuit::from_str(&circ.to_string()).unwrap());
    }
//}}}
    #[test] // bundle addition {{{
    fn bundle_addition() {
        let mut rng = thread_rng();
        let q = rng.gen_usable_composite_modulus();

        let mut b = Builder::new();
        let x = b.garbler_input_bundle_crt(q);
        let y = b.evaluator_input_bundle_crt(q);
        let z = b.add_bundles(&x,&y);
        b.output_bundle(&z);
        let c = b.finish();

        for _ in 0..16 {
            let x = rng.gen_u128() % q;
            let y = rng.gen_u128() % q;
            let res = c.eval(&crt_factor(x,q),&crt_factor(y,q));
            let z = crt_inv_factor(&res, q);
            assert_eq!(z, (x+y)%q);
        }
    }
    //}}}
    #[test] // bundle subtraction {{{
    fn bundle_subtraction() {
        let mut rng = thread_rng();
        let q = rng.gen_usable_composite_modulus();

        let mut b = Builder::new();
        let x = b.garbler_input_bundle_crt(q);
        let y = b.evaluator_input_bundle_crt(q);
        let z = b.sub_bundles(&x,&y);
        b.output_bundle(&z);
        let c = b.finish();

        for _ in 0..16 {
            let x = rng.gen_u128() % q;
            let y = rng.gen_u128() % q;
            let res = c.eval(&crt_factor(x,q),&crt_factor(y,q));
            let z = crt_inv_factor(&res, q);
            assert_eq!(z, (x+q-y)%q);
        }
    }
    //}}}
    #[test] // bundle cmul {{{
    fn bundle_cmul() {
        let mut rng = thread_rng();
        let q = util::modulus_with_width(16);

        let mut b = Builder::new();
        let x = b.garbler_input_bundle_crt(q);
        let y = rng.gen_u128() % q;
        let z = b.cmul_bundle(&x,y);
        b.output_bundle(&z);
        let c = b.finish();

        for _ in 0..16 {
            let x = rng.gen_u128() % q;
            let res = c.eval(&crt_factor(x,q),&[]);
            let z = crt_inv_factor(&res, q);
            assert_eq!(z, (x*y)%q);
        }
    }
    //}}}
    #[test] // bundle multiplication {{{
    fn bundle_multiplication() {
        let mut rng = thread_rng();
        let q = rng.gen_usable_composite_modulus();

        let mut b = Builder::new();
        let x = b.garbler_input_bundle_crt(q);
        let y = b.evaluator_input_bundle_crt(q);
        let z = b.mul_bundles(&x,&y);
        b.output_bundle(&z);
        let c = b.finish();

        for _ in 0..16 {
            let x = rng.gen_u64() as u128 % q;
            let y = rng.gen_u64() as u128 % q;
            let res = c.eval(&crt_factor(x,q),&crt_factor(y,q));
            let z = crt_inv_factor(&res, q);
            assert_eq!(z, (x*y)%q);
        }
    }
    //}}}
    #[test] // bundle cdiv {{{
    fn bundle_cdiv() {
        let mut rng = thread_rng();
        let q = util::modulus_with_width_skip2(32);

        let mut b = Builder::new();
        let x = b.garbler_input_bundle_crt(q);
        let z = b.cdiv_bundle(&x,2);
        b.output_bundle(&z);
        let c = b.finish();

        for _ in 0..64 {
            let mut pt = rng.gen_u128() % (q/2);
            pt += pt % 2;
            let res = c.eval(&crt_factor(pt,q),&[]);
            let z = crt_inv_factor(&res, q);
            assert_eq!(z, pt/2);
        }
    }
    //}}}
    #[test] // bundle cexp {{{
    fn bundle_cexp() {
        let mut rng = thread_rng();
        let q = util::modulus_with_width(10);
        let y = rng.gen_u16() % 10;

        let mut b = Builder::new();
        let x = b.garbler_input_bundle_crt(q);
        let z = b.cexp_bundle(&x,y);
        b.output_bundle(&z);
        let c = b.finish();

        for _ in 0..64 {
            let x = rng.gen_u16() as u128 % q;
            let should_be = x.pow(y as u32) % q;
            let res = c.eval(&crt_factor(x,q),&[]);
            let z = crt_inv_factor(&res, q);
            assert_eq!(z, should_be);
        }
    }
    // }}}
    #[test] // bundle remainder {{{
    fn bundle_remainder() {
        let mut rng = thread_rng();
        let ps = rng.gen_usable_factors();
        let q = ps.iter().fold(1, |acc, &x| (x as u128) * acc);
        let p = ps[rng.gen_u16() as usize % ps.len()];

        let mut b = Builder::new();
        let x = b.garbler_input_bundle_crt(q);
        let z = b.rem_bundle(&x,p);
        b.output_bundle(&z);
        let c = b.finish();

        for _ in 0..64 {
            let x = rng.gen_u128() % q;
            let should_be = x % p as u128;
            let res = c.eval(&crt_factor(x,q),&[]);
            let z = crt_inv_factor(&res, q);
            assert_eq!(z, should_be);
        }
    }
    //}}}
    #[test] // bundle equality {{{
    fn bundle_equality() {
        let mut rng = thread_rng();
        let q = rng.gen_usable_composite_modulus();

        let mut b = Builder::new();
        let x = b.garbler_input_bundle_crt(q);
        let y = b.evaluator_input_bundle_crt(q);
        let z = b.eq_bundles(&x,&y);
        b.output(z);
        let c = b.finish();

        // lets have at least one test where they are surely equal
        let x = rng.gen_u128() % q;
        let res = c.eval(&crt_factor(x,q),&crt_factor(x,q));
        assert_eq!(res, &[(x==x) as u16]);

        for _ in 0..64 {
            let x = rng.gen_u128() % q;
            let y = rng.gen_u128() % q;
            let res = c.eval(&crt_factor(x,q),&crt_factor(y,q));
            assert_eq!(res, &[(x==y) as u16]);
        }
    }
    //}}}
    #[test] // mixed_radix_addition {{{
    fn mixed_radix_addition() {
        let mut rng = thread_rng();

        let nargs = 2 + rng.gen_usize() % 100;
        let mods = (0..7).map(|_| rng.gen_modulus()).collect_vec();

        let mut b = Builder::new();
        let xs = b.evaluator_input_bundles(&mods, nargs);
        let z = b.mixed_radix_addition(&xs);
        b.output_bundle(&z);
        let circ = b.finish();

        let Q: u128 = mods.iter().map(|&q| q as u128).product();

        // test maximum overflow
        let mut ds = Vec::new();
        for _ in 0..nargs {
            ds.extend(util::as_mixed_radix(Q-1, &mods).iter());
        }
        let res = circ.eval(&[], &ds);
        assert_eq!(util::from_mixed_radix(&res,&mods), (Q-1)*(nargs as u128) % Q);

        // test random values
        for _ in 0..4 {
            let mut should_be = 0;
            let mut ds = Vec::new();
            for _ in 0..nargs {
                let x = rng.gen_u128() % Q;
                should_be = (should_be + x) % Q;
                ds.extend(util::as_mixed_radix(x, &mods).iter());
            }
            let res = circ.eval(&[],&ds);
            assert_eq!(util::from_mixed_radix(&res,&mods), should_be);
        }
    }
//}}}
    #[test] // relu {{{
    fn test_relu() {
        let mut rng = thread_rng();
        let q = util::modulus_with_width(10);
        println!("q={}", q);

        let mut b = Builder::new();
        let x = b.garbler_input_bundle_crt(q);
        let z = b.exact_relu(&x);
        b.output_bundle(&z);
        let c = b.finish();

        for _ in 0..128 {
            let pt = rng.gen_u128() % q;
            let should_be = if pt < q/2 { pt } else { 0 };
            let res = c.eval(&crt_factor(pt,q),&[]);
            let z = crt_inv_factor(&res, q);
            assert_eq!(z, should_be);
        }
    }
    //}}}

}
