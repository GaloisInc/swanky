//! DSL for creating circuits compatible with fancy-garbling in the old-fashioned way,
//! where you create a circuit for a computation then garble it.

use serde_derive::{Serialize, Deserialize};

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::fancy::{Fancy, HasModulus, SyncIndex};

/// The index and modulus of a gate in a circuit.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct CircuitRef {
    pub ix: usize,
    modulus: u16,
}

impl HasModulus for CircuitRef {
    fn modulus(&self) -> u16 { self.modulus }
}

/// Static representation of the type of computation supported by fancy garbling.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Circuit {
    pub gates: Vec<Gate>,
    pub gate_moduli: Vec<u16>,
    pub garbler_input_refs: Vec<CircuitRef>,
    pub evaluator_input_refs: Vec<CircuitRef>,
    pub const_refs: Vec<CircuitRef>,
    pub output_refs: Vec<CircuitRef>,
    pub num_nonfree_gates: usize,
}

/// The most basic types of computation supported by fancy garbling.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum Gate {
    GarblerInput { id: usize },
    EvaluatorInput { id: usize },
    Constant { val: u16 },
    Add { xref: CircuitRef, yref: CircuitRef },
    Sub { xref: CircuitRef, yref: CircuitRef },
    Cmul { xref: CircuitRef, c: u16 },
    Mul { xref: CircuitRef, yref: CircuitRef, id: usize }, // id is the gate number
    Proj { xref: CircuitRef, tt: Vec<u16>, id: usize },  // id is the gate number
}

impl Circuit {
    fn new() -> Circuit {
        Circuit {
            gates: Vec::new(),
            garbler_input_refs: Vec::new(),
            evaluator_input_refs: Vec::new(),
            const_refs: Vec::new(),
            output_refs: Vec::new(),
            gate_moduli: Vec::new(),
            num_nonfree_gates: 0,
        }
    }

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

                Gate::Constant { val } => val,

                Gate::Add { xref, yref } => (cache[xref.ix] + cache[yref.ix]) % q,
                Gate::Sub { xref, yref } => (cache[xref.ix] + q - cache[yref.ix]) % q,

                Gate::Cmul { xref, c } => cache[xref.ix] * c % q,

                Gate::Proj { xref, ref tt, .. } => tt[cache[xref.ix] as usize],

                Gate::Mul { xref, yref, .. } => (cache[xref.ix] * cache[yref.ix] % q),
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
                Gate::Constant       { .. } => nconst    += 1,
                Gate::Add            { .. } => nadd      += 1,
                Gate::Sub            { .. } => nsub      += 1,
                Gate::Cmul           { .. } => ncmul     += 1,
                Gate::Proj           { .. } => nproj     += 1,
                Gate::Mul            { .. } => nhalfgate += 1,
            }
        }

        println!("circuit info:");
        println!("  garbler inputs:   {}", self.num_garbler_inputs());
        println!("  evaluator inputs: {}", self.num_evaluator_inputs());
        println!("  noutputs:         {}", self.noutputs());
        println!("  nconsts:          {}", nconst);
        println!();
        println!("  additions:        {}", nadd);
        println!("  subtractions:     {}", nsub);
        println!("  cmuls:            {}", ncmul);
        println!("  projections:      {}", nproj);
        println!("  halfgates:        {}", nhalfgate);
        println!();
        println!("  total non-free gates: {}", self.num_nonfree_gates);
        println!();
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

    pub fn from_string(s: &str) -> Result<Circuit, failure::Error> {
        serde_json::from_str(s).map_err(|why| {
            failure::format_err!("failed to parse json: line {} column {}", why.line(), why.column())
        })
    }
}

/// CircuitBuilder is used to build circuits.
pub struct CircuitBuilder {
    next_ref_ix:             Arc<AtomicUsize>,
    next_garbler_input_id:   Arc<AtomicUsize>,
    next_evaluator_input_id: Arc<AtomicUsize>,
    const_map:               Arc<Mutex<HashMap<(u16,u16), CircuitRef>>>,
    circ:                    Arc<Mutex<Circuit>>,
}

impl Fancy for CircuitBuilder {
    type Item = CircuitRef;

    fn garbler_input(&self, _ix: Option<SyncIndex>, modulus: u16) -> CircuitRef {
        let gate = Gate::GarblerInput { id: self.get_next_garbler_input_id() };
        let r = self.gate(gate, modulus);
        self.circ.lock().unwrap().garbler_input_refs.push(r);
        r
    }

    fn evaluator_input(&self, _ix: Option<SyncIndex>, modulus: u16) -> CircuitRef {
        let gate = Gate::EvaluatorInput { id: self.get_next_evaluator_input_id() };
        let r = self.gate(gate, modulus);
        self.circ.lock().unwrap().evaluator_input_refs.push(r);
        r
    }

    fn constant(&self, _ix: Option<SyncIndex>, val: u16, modulus: u16) -> CircuitRef {
        let mut map = self.const_map.lock().unwrap();
        match map.get(&(val, modulus)) {
            Some(&r) => r,
            None => {
                let gate = Gate::Constant { val };
                let r = self.gate(gate, modulus);
                map.insert((val,modulus), r);
                self.circ.lock().unwrap().const_refs.push(r);
                r
            }
        }
    }

    fn add(&self, xref: &CircuitRef, yref: &CircuitRef) -> CircuitRef {
        assert!(xref.modulus() == yref.modulus(), "xmod={} ymod={}", xref.modulus(), yref.modulus());
        let gate = Gate::Add { xref: *xref, yref: *yref };
        self.gate(gate, xref.modulus())
    }

    fn sub(&self, xref: &CircuitRef, yref: &CircuitRef) -> CircuitRef {
        assert!(xref.modulus() == yref.modulus(), "xmod={} ymod={}", xref.modulus(), yref.modulus());
        let gate = Gate::Sub { xref: *xref, yref: *yref };
        self.gate(gate, xref.modulus())
    }

    fn cmul(&self, xref: &CircuitRef, c: u16) -> CircuitRef {
        self.gate(Gate::Cmul { xref: *xref, c }, xref.modulus())
    }

    fn proj(&self, _ix: Option<SyncIndex>, xref: &CircuitRef, output_modulus: u16, tt: Option<Vec<u16>>) -> CircuitRef {
        let tt = tt.expect("builder.proj requires truth table");
        assert_eq!(tt.len(), xref.modulus() as usize);
        assert!(tt.iter().all(|&x| x < output_modulus),
            "not all xs were less than the output modulus! circuit.proj: tt={:?},
            output_modulus={}", tt, output_modulus);
        let gate = Gate::Proj { xref: *xref, tt: tt.to_vec(), id: self.get_next_ciphertext_id() };
        self.gate(gate, output_modulus)
    }

    fn mul(&self, ix: Option<SyncIndex>, xref: &CircuitRef, yref: &CircuitRef) -> CircuitRef {
        if xref.modulus() < yref.modulus() {
            return self.mul(ix, yref, xref);
        }

        let gate = Gate::Mul {
            xref: *xref,
            yref: *yref,
            id: self.get_next_ciphertext_id(),
        };

        self.gate(gate, xref.modulus())
    }

    fn output(&self, _ix: Option<SyncIndex>, xref: &CircuitRef) {
        self.circ.lock().unwrap().output_refs.push(xref.clone());
    }
}

impl CircuitBuilder {
    pub fn new() -> Self {
        CircuitBuilder {
            next_ref_ix:             Arc::new(AtomicUsize::new(0)),
            next_garbler_input_id:   Arc::new(AtomicUsize::new(0)),
            next_evaluator_input_id: Arc::new(AtomicUsize::new(0)),
            const_map:               Arc::new(Mutex::new(HashMap::new())),
            circ:                    Arc::new(Mutex::new(Circuit::new())),
        }
    }

    pub fn finish(self) -> Circuit {
        Arc::try_unwrap(self.circ).unwrap().into_inner().unwrap()
    }

    fn get_next_garbler_input_id(&self) -> usize {
        self.next_garbler_input_id.fetch_add(1, Ordering::SeqCst)
    }

    fn get_next_evaluator_input_id(&self) -> usize {
        self.next_evaluator_input_id.fetch_add(1, Ordering::SeqCst)
    }

    fn get_next_ciphertext_id(&self) -> usize {
        let mut c = self.circ.lock().unwrap();
        let id = c.num_nonfree_gates;
        c.num_nonfree_gates += 1;
        id
    }

    fn get_next_ref_ix(&self) -> usize {
        self.next_ref_ix.fetch_add(1, Ordering::SeqCst)
    }

    fn gate(&self, gate: Gate, modulus: u16) -> CircuitRef {
        let mut c = self.circ.lock().unwrap();
        c.gates.push(gate);
        c.gate_moduli.push(modulus);
        let ix = self.get_next_ref_ix();
        CircuitRef { ix, modulus }
    }
}

#[cfg(test)]
mod basic {
    use super::*;
    use crate::util::RngExt;
    use itertools::Itertools;
    use rand::thread_rng;

    #[test] // {{{ and_gate_fan_n
    fn and_gate_fan_n() {
        let mut rng = thread_rng();

        let b = CircuitBuilder::new();
        let n = 2 + (rng.gen_usize() % 200);
        let inps = b.evaluator_inputs(None,2,n);
        let z = b.and_many(None,&inps);
        b.output(None,&z);
        let c = b.finish();

        for _ in 0..16 {
            let mut inps: Vec<u16> = Vec::new();
            for _ in 0..n {
                inps.push(rng.gen_bool() as u16);
            }
            let res = inps.iter().fold(1, |acc, &x| x & acc);
            let out = c.eval(&[],&inps)[0];
            if !(out == res) {
                println!("{:?} {} {}", inps, out, res);
                panic!("incorrect output n={}", n);
            }
        }
    }
//}}}
    #[test] // {{{ or_gate_fan_n
    fn or_gate_fan_n() {
        let mut rng = thread_rng();
        let b = CircuitBuilder::new();
        let n = 2 + (rng.gen_usize() % 200);
        let inps = b.evaluator_inputs(None,2,n);
        let z = b.or_many(None,&inps);
        b.output(None,&z);
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
        let b = CircuitBuilder::new();
        let q = rng.gen_prime();
        let x = b.garbler_input(None,q);
        let y = b.evaluator_input(None,q);
        let z = b.mul(None,&x,&y);
        b.output(None,&z);
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
        let b = CircuitBuilder::new();
        let p = rng.gen_prime();
        let q = rng.gen_prime();
        let x = b.garbler_input(None, p);
        let y = b.mod_change(None, &x, q);
        let z = b.mod_change(None, &y, p);
        b.output(None, &z);
        let c = b.finish();
        for _ in 0..16 {
            let x = rng.gen_u16() % p;
            assert_eq!(c.eval(&[x],&[])[0], x % q);
        }
    }
//}}}
    #[test] // add_many_mod_change {{{
    fn add_many_mod_change() {
        let b = CircuitBuilder::new();
        let n = 113;
        let args = b.garbler_inputs(None, 2, n);
        let wires = args.iter().map(|x| b.mod_change(None, x, n as u16 + 1)).collect_vec();
        let s = b.add_many(&wires);
        b.output(None, &s);
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
        let b = CircuitBuilder::new();
        let mut rng = thread_rng();

        let q = rng.gen_modulus();
        let c = rng.gen_u16() % q;

        let x = b.evaluator_input(None, q);
        let y = b.constant(None, c, q);
        let z = b.add(&x,&y);
        b.output(None, &z);

        let circ = b.finish();

        for _ in 0..64 {
            let x = rng.gen_u16() % q;
            let z = circ.eval(&[],&[x]);
            assert_eq!(z[0], (x+c)%q);
        }
    }
//}}}
}

#[cfg(test)]
mod bundle {
    use super::*;
    use crate::fancy::BundleGadgets;
    use crate::util::{self, RngExt, crt_factor, crt_inv_factor};
    use itertools::Itertools;
    use rand::thread_rng;

    #[test] // bundle addition {{{
    fn test_addition() {
        let mut rng = thread_rng();
        let q = rng.gen_usable_composite_modulus();

        let b = CircuitBuilder::new();
        let x = b.garbler_input_bundle_crt(None, q);
        let y = b.evaluator_input_bundle_crt(None, q);
        let z = b.add_bundles(&x,&y);
        b.output_bundle(None, &z);
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
    fn test_subtraction() {
        let mut rng = thread_rng();
        let q = rng.gen_usable_composite_modulus();

        let b = CircuitBuilder::new();
        let x = b.garbler_input_bundle_crt(None, q);
        let y = b.evaluator_input_bundle_crt(None, q);
        let z = b.sub_bundles(&x,&y);
        b.output_bundle(None, &z);
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
    fn test_cmul() {
        let mut rng = thread_rng();
        let q = util::modulus_with_width(16);

        let b = CircuitBuilder::new();
        let x = b.garbler_input_bundle_crt(None, q);
        let y = rng.gen_u128() % q;
        let z = b.cmul_bundle(&x,y);
        b.output_bundle(None, &z);
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
    fn test_multiplication() {
        let mut rng = thread_rng();
        let q = rng.gen_usable_composite_modulus();

        let b = CircuitBuilder::new();
        let x = b.garbler_input_bundle_crt(None, q);
        let y = b.evaluator_input_bundle_crt(None, q);
        let z = b.mul_bundles(None,&x,&y);
        b.output_bundle(None, &z);
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
    #[test] // bundle cexp {{{
    fn test_cexp() {
        let mut rng = thread_rng();
        let q = util::modulus_with_width(10);
        let y = rng.gen_u16() % 10;

        let b = CircuitBuilder::new();
        let x = b.garbler_input_bundle_crt(None, q);
        let z = b.cexp_bundle(None,&x,y);
        b.output_bundle(None, &z);
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
    fn test_remainder() {
        let mut rng = thread_rng();
        let ps = rng.gen_usable_factors();
        let q = ps.iter().fold(1, |acc, &x| (x as u128) * acc);
        let p = ps[rng.gen_u16() as usize % ps.len()];

        let b = CircuitBuilder::new();
        let x = b.garbler_input_bundle_crt(None, q);
        let z = b.rem_bundle(None,&x,p);
        b.output_bundle(None, &z);
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
    fn test_equality() {
        let mut rng = thread_rng();
        let q = rng.gen_usable_composite_modulus();

        let b = CircuitBuilder::new();
        let x = b.garbler_input_bundle_crt(None, q);
        let y = b.evaluator_input_bundle_crt(None, q);
        let z = b.eq_bundles(None,&x,&y);
        b.output(None,&z);
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
    #[test] // bundle mixed_radix_addition {{{
    fn test_mixed_radix_addition() {
        let mut rng = thread_rng();

        let nargs = 2 + rng.gen_usize() % 100;
        let mods = (0..7).map(|_| rng.gen_modulus()).collect_vec();

        let b = CircuitBuilder::new();
        let xs = b.evaluator_input_bundles(None, &mods, nargs);
        let z = b.mixed_radix_addition(None,&xs);
        b.output_bundle(None, &z);
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
    #[test] // bundle relu {{{
    fn test_relu() {
        let mut rng = thread_rng();
        let q = util::modulus_with_width(10);
        println!("q={}", q);

        let b = CircuitBuilder::new();
        let x = b.garbler_input_bundle_crt(None, q);
        let z = b.relu(None, &x, "100%");
        b.output_bundle(None, &z);
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
    #[test] // bundle sgn {{{
    fn test_sgn() {
        let mut rng = thread_rng();
        let q = util::modulus_with_width(10);
        println!("q={}", q);

        let b = CircuitBuilder::new();
        let x = b.garbler_input_bundle_crt(None, q);
        let z = b.sgn(None, &x, "100%");
        b.output_bundle(None, &z);
        let c = b.finish();

        for _ in 0..128 {
            let pt = rng.gen_u128() % q;
            let should_be = if pt < q/2 { 1 } else { q-1 };
            let res = c.eval(&crt_factor(pt,q),&[]);
            let z = crt_inv_factor(&res, q);
            assert_eq!(z, should_be);
        }
    }
    //}}}
    #[test] // bundle leq {{{
    fn test_leq() {
        let mut rng = thread_rng();
        let q = util::modulus_with_width(10);

        let b = CircuitBuilder::new();
        let x = b.garbler_input_bundle_crt(None, q);
        let y = b.evaluator_input_bundle_crt(None, q);
        let z = b.lt(None,&x,&y,"100%");
        b.output(None,&z);
        let c = b.finish();

        // lets have at least one test where they are surely equal
        let x = rng.gen_u128() % q/2;
        let res = c.eval(&crt_factor(x,q),&crt_factor(x,q));
        assert_eq!(res, &[(x<x) as u16], "x={}", x);

        for _ in 0..64 {
            let x = rng.gen_u128() % q/2;
            let y = rng.gen_u128() % q/2;
            let res = c.eval(&crt_factor(x,q),&crt_factor(y,q));
            assert_eq!(res, &[(x<y) as u16], "x={} y={}", x, y);
        }
    }
    //}}}
    #[test] // bundle max {{{
    fn test_max() {
        let mut rng = thread_rng();
        let q = util::modulus_with_width(10);
        let n = 10;
        println!("n={} q={}", n, q);

        let b = CircuitBuilder::new();
        let xs = b.garbler_input_bundles_crt(None,q,n);
        let z = b.max(None,&xs,"100%");
        b.output_bundle(None, &z);
        let c = b.finish();

        for _ in 0..16 {
            let inps = (0..n).map(|_| rng.gen_u128() % (q/2)).collect_vec();
            println!("{:?}", inps);
            let should_be = *inps.iter().max().unwrap();

            let enc_inps = inps.into_iter().flat_map(|x| crt_factor(x,q)).collect_vec();
            let res = c.eval(&enc_inps,&[]);
            let z = crt_inv_factor(&res, q);
            assert_eq!(z, should_be);
        }
    }
    //}}}
    #[test] // binary addition {{{
    fn test_binary_addition() {
        let mut rng = thread_rng();
        let n = 2 + (rng.gen_usize() % 10);
        let q = 2;
        let Q = util::product(&vec![q;n]);
        println!("n={} q={} Q={}", n, q, Q);

        let b = CircuitBuilder::new();
        let xs = b.garbler_input_bundle(None,&vec![q;n]);
        let ys = b.evaluator_input_bundle(None,&vec![q;n]);
        let (zs,carry) = b.binary_addition(None,&xs, &ys);
        b.output(None,&carry);
        b.output_bundle(None, &zs);
        let c = b.finish();

        for _ in 0..16 {
            let x = rng.gen_u128() % Q;
            let y = rng.gen_u128() % Q;
            println!("x={} y={}", x, y);
            let res_should_be = (x + y) % Q;
            let carry_should_be = (x + y >= Q) as u16;

            let res = c.eval(&util::u128_to_bits(x,n), &util::u128_to_bits(y,n));
            assert_eq!(util::u128_from_bits(&res[1..]), res_should_be);
            assert_eq!(res[0], carry_should_be);
        }
    }
    //}}}
    #[test] // serialization {{{
    fn test_serialization() {
        let mut rng = thread_rng();

        let nargs = 2 + rng.gen_usize() % 100;
        let mods = (0..7).map(|_| rng.gen_modulus()).collect_vec();

        let b = CircuitBuilder::new();
        let xs = b.evaluator_input_bundles(None,&mods, nargs);
        let z = b.mixed_radix_addition(None,&xs);
        b.output_bundle(None, &z);
        let circ = b.finish();

        println!("{}", circ.to_string());

        assert_eq!(circ, Circuit::from_string(&circ.to_string()).unwrap());
    }
//}}}
    #[test] // builder has send and sync {{{
    fn test_builder_has_send_and_sync() {
        fn check_send(_: impl Send) { }
        fn check_sync(_: impl Sync) { }
        check_send(CircuitBuilder::new());
        check_sync(CircuitBuilder::new());
    } // }}}
}
