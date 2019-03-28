//! DSL for creating circuits compatible with fancy-garbling in the old-fashioned way,
//! where you create a circuit for a computation then garble it.

use serde::{Deserialize, Serialize};

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::error::{CircuitBuilderError, DummyError, FancyError, InformerError};
use crate::fancy::{Fancy, HasModulus};

/// The index and modulus of a gate in a circuit.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct CircuitRef {
    pub ix: usize,
    pub(crate) modulus: u16,
}

impl std::fmt::Display for CircuitRef {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "[{} | {}]", self.ix, self.modulus)
    }
}

impl HasModulus for CircuitRef {
    fn modulus(&self) -> u16 {
        self.modulus
    }
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
    num_nonfree_gates: usize,
}

/// The most basic types of computation supported by fancy garbling.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum Gate {
    GarblerInput {
        id: usize,
    },
    EvaluatorInput {
        id: usize,
    },
    Constant {
        val: u16,
    },
    Add {
        xref: CircuitRef,
        yref: CircuitRef,
        out: Option<usize>,
    },
    Sub {
        xref: CircuitRef,
        yref: CircuitRef,
        out: Option<usize>,
    },
    Cmul {
        xref: CircuitRef,
        c: u16,
        out: Option<usize>,
    },
    Mul {
        xref: CircuitRef,
        yref: CircuitRef,
        id: usize,
        out: Option<usize>,
    }, // id is the gate number
    Proj {
        xref: CircuitRef,
        tt: Vec<u16>,
        id: usize,
        out: Option<usize>,
    }, // id is the gate number
}

impl std::fmt::Display for Gate {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Gate::GarblerInput { id } => write!(f, "GarblerInput {}", id),
            Gate::EvaluatorInput { id } => write!(f, "EvaluatorInput {}", id),
            Gate::Constant { val } => write!(f, "Constant {}", val),
            Gate::Add { xref, yref, out } => write!(f, "Add ( {}, {}, {:?} )", xref, yref, out),
            Gate::Sub { xref, yref, out } => write!(f, "Sub ( {}, {}, {:?} )", xref, yref, out),
            Gate::Cmul { xref, c, out } => write!(f, "Cmul ( {}, {}, {:?} )", xref, c, out),
            Gate::Mul {
                xref,
                yref,
                id,
                out,
            } => write!(f, "Mul ( {}, {}, {}, {:?} )", xref, yref, id, out),
            Gate::Proj { xref, tt, id, out } => {
                write!(f, "Proj ( {}, {:?}, {}, {:?} )", xref, tt, id, out)
            }
        }
    }
}

impl Circuit {
    pub fn new(ngates: Option<usize>) -> Circuit {
        let gates = Vec::with_capacity(ngates.unwrap_or(0));
        Circuit {
            gates,
            garbler_input_refs: Vec::new(),
            evaluator_input_refs: Vec::new(),
            const_refs: Vec::new(),
            output_refs: Vec::new(),
            gate_moduli: Vec::new(),
            num_nonfree_gates: 0,
        }
    }

    pub fn eval<F: Fancy>(&self, f: &F) -> Result<Vec<F::Item>, F::Error> {
        let mut cache: Vec<Option<F::Item>> = vec![None; self.gates.len()];
        for (i, gate) in self.gates.iter().enumerate() {
            let q = self.modulus(i);
            let (zref_, val) = match *gate {
                Gate::GarblerInput { .. } => (None, f.garbler_input(q, None)?),
                Gate::EvaluatorInput { .. } => (None, f.evaluator_input(q)?),
                Gate::Constant { val } => (None, f.constant(val, q)?),
                Gate::Add { xref, yref, out } => (
                    out,
                    f.add(
                        cache[xref.ix]
                            .as_ref()
                            .ok_or(F::Error::from(FancyError::UninitializedValue))?,
                        cache[yref.ix]
                            .as_ref()
                            .ok_or(F::Error::from(FancyError::UninitializedValue))?,
                    )?,
                ),
                Gate::Sub { xref, yref, out } => (
                    out,
                    f.sub(
                        cache[xref.ix]
                            .as_ref()
                            .ok_or(F::Error::from(FancyError::UninitializedValue))?,
                        cache[yref.ix]
                            .as_ref()
                            .ok_or(F::Error::from(FancyError::UninitializedValue))?,
                    )?,
                ),
                Gate::Cmul { xref, c, out } => (
                    out,
                    f.cmul(
                        cache[xref.ix]
                            .as_ref()
                            .ok_or(F::Error::from(FancyError::UninitializedValue))?,
                        c,
                    )?,
                ),
                Gate::Proj {
                    xref,
                    ref tt,
                    id: _,
                    out,
                } => (
                    out,
                    f.proj(
                        cache[xref.ix]
                            .as_ref()
                            .ok_or(F::Error::from(FancyError::UninitializedValue))?,
                        q,
                        Some(tt.to_vec()),
                    )?,
                ),
                Gate::Mul {
                    xref,
                    yref,
                    id: _,
                    out,
                } => (
                    out,
                    f.mul(
                        cache[xref.ix]
                            .as_ref()
                            .ok_or(F::Error::from(FancyError::UninitializedValue))?,
                        cache[yref.ix]
                            .as_ref()
                            .ok_or(F::Error::from(FancyError::UninitializedValue))?,
                    )?,
                ),
            };
            cache[zref_.unwrap_or(i)] = Some(val);
        }
        let mut outputs = Vec::with_capacity(self.output_refs.len());
        for r in self.output_refs.iter() {
            let out = cache[r.ix]
                .clone()
                .ok_or(F::Error::from(FancyError::UninitializedValue))?;
            outputs.push(out);
        }
        Ok(outputs)
    }

    pub fn process_outputs<F: Fancy>(&self, outputs: &[F::Item], f: &F) -> Result<(), F::Error> {
        for r in outputs.iter() {
            f.output(r)?;
        }
        Ok(())
    }

    /// Evaluate the circuit in plaintext.
    pub fn eval_plain(
        &self,
        garbler_inputs: &[u16],
        evaluator_inputs: &[u16],
    ) -> Result<Vec<u16>, DummyError> {
        let dummy = crate::dummy::Dummy::new(garbler_inputs, evaluator_inputs);
        let outputs = self.eval(&dummy)?;
        self.process_outputs(&outputs, &dummy)?;
        Ok(dummy.get_output())
    }

    /// Print circuit info.
    pub fn info(&self) -> Result<(), InformerError> {
        let informer = crate::informer::Informer::new();
        self.eval(&informer)?;
        Ok(())
    }
    #[inline]
    pub fn num_garbler_inputs(&self) -> usize {
        self.garbler_input_refs.len()
    }
    #[inline]
    pub fn num_evaluator_inputs(&self) -> usize {
        self.evaluator_input_refs.len()
    }
    #[inline]
    pub fn noutputs(&self) -> usize {
        self.output_refs.len()
    }
    #[inline]
    pub fn modulus(&self, gate_num: usize) -> u16 {
        self.gate_moduli[gate_num]
    }
    #[inline]
    pub fn garbler_input_mod(&self, id: usize) -> u16 {
        let r = self.garbler_input_refs[id];
        r.modulus()
    }
    #[inline]
    pub fn evaluator_input_mod(&self, id: usize) -> u16 {
        let r = self.evaluator_input_refs[id];
        r.modulus()
    }
}

/// CircuitBuilder is used to build circuits.
pub struct CircuitBuilder {
    next_ref_ix: Arc<AtomicUsize>,
    next_garbler_input_id: Arc<AtomicUsize>,
    next_evaluator_input_id: Arc<AtomicUsize>,
    const_map: Arc<Mutex<HashMap<(u16, u16), CircuitRef>>>,
    circ: Arc<Mutex<Circuit>>,
}

impl Fancy for CircuitBuilder {
    type Item = CircuitRef;
    type Error = CircuitBuilderError;

    fn garbler_input(&self, modulus: u16, _opt_x: Option<u16>) -> Result<CircuitRef, Self::Error> {
        let gate = Gate::GarblerInput {
            id: self.get_next_garbler_input_id(),
        };
        let r = self.gate(gate, modulus);
        self.circ.lock().unwrap().garbler_input_refs.push(r);
        Ok(r)
    }

    fn evaluator_input(&self, modulus: u16) -> Result<CircuitRef, Self::Error> {
        let gate = Gate::EvaluatorInput {
            id: self.get_next_evaluator_input_id(),
        };
        let r = self.gate(gate, modulus);
        self.circ.lock().unwrap().evaluator_input_refs.push(r);
        Ok(r)
    }

    fn constant(&self, val: u16, modulus: u16) -> Result<CircuitRef, Self::Error> {
        let mut map = self.const_map.lock().unwrap();
        match map.get(&(val, modulus)) {
            Some(&r) => Ok(r),
            None => {
                let gate = Gate::Constant { val };
                let r = self.gate(gate, modulus);
                map.insert((val, modulus), r);
                self.circ.lock().unwrap().const_refs.push(r);
                Ok(r)
            }
        }
    }

    fn add(&self, xref: &CircuitRef, yref: &CircuitRef) -> Result<CircuitRef, Self::Error> {
        if xref.modulus() != yref.modulus() {
            return Err(Self::Error::from(FancyError::UnequalModuli));
        }
        let gate = Gate::Add {
            xref: *xref,
            yref: *yref,
            out: None,
        };
        Ok(self.gate(gate, xref.modulus()))
    }

    fn sub(&self, xref: &CircuitRef, yref: &CircuitRef) -> Result<CircuitRef, Self::Error> {
        if xref.modulus() != yref.modulus() {
            return Err(Self::Error::from(FancyError::UnequalModuli));
        }
        let gate = Gate::Sub {
            xref: *xref,
            yref: *yref,
            out: None,
        };
        Ok(self.gate(gate, xref.modulus()))
    }

    fn cmul(&self, xref: &CircuitRef, c: u16) -> Result<CircuitRef, Self::Error> {
        Ok(self.gate(
            Gate::Cmul {
                xref: *xref,
                c,
                out: None,
            },
            xref.modulus(),
        ))
    }

    fn proj(
        &self,
        xref: &CircuitRef,
        output_modulus: u16,
        tt: Option<Vec<u16>>,
    ) -> Result<CircuitRef, Self::Error> {
        let tt = tt.ok_or(Self::Error::from(FancyError::NoTruthTable))?;
        if tt.len() < xref.modulus() as usize || !tt.iter().all(|&x| x < output_modulus) {
            return Err(Self::Error::from(FancyError::InvalidTruthTable));
        }
        let gate = Gate::Proj {
            xref: *xref,
            tt: tt.to_vec(),
            id: self.get_next_ciphertext_id(),
            out: None,
        };
        Ok(self.gate(gate, output_modulus))
    }

    fn mul(&self, xref: &CircuitRef, yref: &CircuitRef) -> Result<CircuitRef, Self::Error> {
        if xref.modulus() < yref.modulus() {
            return self.mul(yref, xref);
        }

        let gate = Gate::Mul {
            xref: *xref,
            yref: *yref,
            id: self.get_next_ciphertext_id(),
            out: None,
        };

        Ok(self.gate(gate, xref.modulus()))
    }

    fn output(&self, xref: &CircuitRef) -> Result<(), Self::Error> {
        self.circ.lock().unwrap().output_refs.push(xref.clone());
        Ok(())
    }
}

impl CircuitBuilder {
    pub fn new() -> Self {
        CircuitBuilder {
            next_ref_ix: Arc::new(AtomicUsize::new(0)),
            next_garbler_input_id: Arc::new(AtomicUsize::new(0)),
            next_evaluator_input_id: Arc::new(AtomicUsize::new(0)),
            const_map: Arc::new(Mutex::new(HashMap::new())),
            circ: Arc::new(Mutex::new(Circuit::new(None))),
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
        let inps = b.evaluator_inputs(&vec![2; n]).unwrap();
        let z = b.and_many(&inps).unwrap();
        b.output(&z).unwrap();
        let c = b.finish();

        for _ in 0..16 {
            let mut inps: Vec<u16> = Vec::new();
            for _ in 0..n {
                inps.push(rng.gen_bool() as u16);
            }
            let res = inps.iter().fold(1, |acc, &x| x & acc);
            let out = c.eval_plain(&[], &inps).unwrap()[0];
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
        let inps = b.evaluator_inputs(&vec![2; n]).unwrap();
        let z = b.or_many(&inps).unwrap();
        b.output(&z).unwrap();
        let c = b.finish();

        for _ in 0..16 {
            let mut inps: Vec<u16> = Vec::new();
            for _ in 0..n {
                inps.push(rng.gen_bool() as u16);
            }
            let res = inps.iter().fold(0, |acc, &x| x | acc);
            let out = c.eval_plain(&[], &inps).unwrap()[0];
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
        let x = b.garbler_input(q, None).unwrap();
        let y = b.evaluator_input(q).unwrap();
        let z = b.mul(&x, &y).unwrap();
        b.output(&z).unwrap();
        let c = b.finish();
        for _ in 0..16 {
            let x = rng.gen_u16() % q;
            let y = rng.gen_u16() % q;
            let out = c.eval_plain(&[x], &[y]).unwrap();
            assert_eq!(out[0], x * y % q);
        }
    }
    //}}}
    #[test] // mod_change {{{
    fn mod_change() {
        let mut rng = thread_rng();
        let b = CircuitBuilder::new();
        let p = rng.gen_prime();
        let q = rng.gen_prime();
        let x = b.garbler_input(p, None).unwrap();
        let y = b.mod_change(&x, q).unwrap();
        let z = b.mod_change(&y, p).unwrap();
        b.output(&z).unwrap();
        let c = b.finish();
        for _ in 0..16 {
            let x = rng.gen_u16() % p;
            let out = c.eval_plain(&[x], &[]).unwrap();
            assert_eq!(out[0], x % q);
        }
    }
    //}}}
    #[test] // add_many_mod_change {{{
    fn add_many_mod_change() {
        let b = CircuitBuilder::new();
        let n = 113;
        let args = b.garbler_inputs(&vec![2; n], None).unwrap();
        let wires = args
            .iter()
            .map(|x| b.mod_change(x, n as u16 + 1).unwrap())
            .collect_vec();
        let s = b.add_many(&wires).unwrap();
        b.output(&s).unwrap();
        let c = b.finish();

        let mut rng = thread_rng();
        for _ in 0..64 {
            let inps = (0..c.num_garbler_inputs())
                .map(|i| rng.gen_u16() % c.garbler_input_mod(i))
                .collect_vec();
            let s: u16 = inps.iter().sum();
            println!("{:?}, sum={}", inps, s);
            let out = c.eval_plain(&inps, &[]).unwrap();
            assert_eq!(out[0], s);
        }
    }
    // }}}
    #[test] // constants {{{
    fn constants() {
        let b = CircuitBuilder::new();
        let mut rng = thread_rng();

        let q = rng.gen_modulus();
        let c = rng.gen_u16() % q;

        let x = b.evaluator_input(q).unwrap();
        let y = b.constant(c, q).unwrap();
        let z = b.add(&x, &y).unwrap();
        b.output(&z).unwrap();

        let circ = b.finish();

        for _ in 0..64 {
            let x = rng.gen_u16() % q;
            let z = circ.eval_plain(&[], &[x]).unwrap();
            assert_eq!(z[0], (x + c) % q);
        }
    }
    //}}}
}

#[cfg(test)]
mod bundle {
    use super::*;
    use crate::fancy::BundleGadgets;
    use crate::util::{self, crt_factor, crt_inv_factor, RngExt};
    use itertools::Itertools;
    use rand::thread_rng;

    #[test] // bundle addition {{{
    fn test_addition() {
        let mut rng = thread_rng();
        let q = rng.gen_usable_composite_modulus();

        let b = CircuitBuilder::new();
        let x = b.garbler_input_bundle_crt(q, None).unwrap();
        let y = b.evaluator_input_bundle_crt(q).unwrap();
        let z = b.add_bundles(&x, &y).unwrap();
        b.output_bundle(&z).unwrap();
        let c = b.finish();

        for _ in 0..16 {
            let x = rng.gen_u128() % q;
            let y = rng.gen_u128() % q;
            let res = c.eval_plain(&crt_factor(x, q), &crt_factor(y, q)).unwrap();
            let z = crt_inv_factor(&res, q);
            assert_eq!(z, (x + y) % q);
        }
    }
    //}}}
    #[test] // bundle subtraction {{{
    fn test_subtraction() {
        let mut rng = thread_rng();
        let q = rng.gen_usable_composite_modulus();

        let b = CircuitBuilder::new();
        let x = b.garbler_input_bundle_crt(q, None).unwrap();
        let y = b.evaluator_input_bundle_crt(q).unwrap();
        let z = b.sub_bundles(&x, &y).unwrap();
        b.output_bundle(&z).unwrap();
        let c = b.finish();

        for _ in 0..16 {
            let x = rng.gen_u128() % q;
            let y = rng.gen_u128() % q;
            let res = c.eval_plain(&crt_factor(x, q), &crt_factor(y, q)).unwrap();
            let z = crt_inv_factor(&res, q);
            assert_eq!(z, (x + q - y) % q);
        }
    }
    //}}}
    #[test] // bundle cmul {{{
    fn test_cmul() {
        let mut rng = thread_rng();
        let q = util::modulus_with_width(16);

        let b = CircuitBuilder::new();
        let x = b.garbler_input_bundle_crt(q, None).unwrap();
        let y = rng.gen_u128() % q;
        let z = b.cmul_bundle(&x, y).unwrap();
        b.output_bundle(&z).unwrap();
        let c = b.finish();

        for _ in 0..16 {
            let x = rng.gen_u128() % q;
            let res = c.eval_plain(&crt_factor(x, q), &[]).unwrap();
            let z = crt_inv_factor(&res, q);
            assert_eq!(z, (x * y) % q);
        }
    }
    //}}}
    #[test] // bundle multiplication {{{
    fn test_multiplication() {
        let mut rng = thread_rng();
        let q = rng.gen_usable_composite_modulus();

        let b = CircuitBuilder::new();
        let x = b.garbler_input_bundle_crt(q, None).unwrap();
        let y = b.evaluator_input_bundle_crt(q).unwrap();
        let z = b.mul_bundles(&x, &y).unwrap();
        b.output_bundle(&z).unwrap();
        let c = b.finish();

        for _ in 0..16 {
            let x = rng.gen_u64() as u128 % q;
            let y = rng.gen_u64() as u128 % q;
            let res = c.eval_plain(&crt_factor(x, q), &crt_factor(y, q)).unwrap();
            let z = crt_inv_factor(&res, q);
            assert_eq!(z, (x * y) % q);
        }
    }
    // }}}
    #[test] // bundle cexp {{{
    fn test_cexp() {
        let mut rng = thread_rng();
        let q = util::modulus_with_width(10);
        let y = rng.gen_u16() % 10;

        let b = CircuitBuilder::new();
        let x = b.garbler_input_bundle_crt(q, None).unwrap();
        let z = b.cexp_bundle(&x, y).unwrap();
        b.output_bundle(&z).unwrap();
        let c = b.finish();

        for _ in 0..64 {
            let x = rng.gen_u16() as u128 % q;
            let should_be = x.pow(y as u32) % q;
            let res = c.eval_plain(&crt_factor(x, q), &[]).unwrap();
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
        let x = b.garbler_input_bundle_crt(q, None).unwrap();
        let z = b.rem_bundle(&x, p).unwrap();
        b.output_bundle(&z).unwrap();
        let c = b.finish();

        for _ in 0..64 {
            let x = rng.gen_u128() % q;
            let should_be = x % p as u128;
            let res = c.eval_plain(&crt_factor(x, q), &[]).unwrap();
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
        let x = b.garbler_input_bundle_crt(q, None).unwrap();
        let y = b.evaluator_input_bundle_crt(q).unwrap();
        let z = b.eq_bundles(&x, &y).unwrap();
        b.output(&z).unwrap();
        let c = b.finish();

        // lets have at least one test where they are surely equal
        let x = rng.gen_u128() % q;
        let res = c.eval_plain(&crt_factor(x, q), &crt_factor(x, q)).unwrap();
        assert_eq!(res, &[(x == x) as u16]);

        for _ in 0..64 {
            let x = rng.gen_u128() % q;
            let y = rng.gen_u128() % q;
            let res = c.eval_plain(&crt_factor(x, q), &crt_factor(y, q)).unwrap();
            assert_eq!(res, &[(x == y) as u16]);
        }
    }
    //}}}
    #[test] // bundle mixed_radix_addition {{{
    fn test_mixed_radix_addition() {
        let mut rng = thread_rng();

        let nargs = 2 + rng.gen_usize() % 100;
        let mods = (0..7).map(|_| rng.gen_modulus()).collect_vec();

        let b = CircuitBuilder::new();
        let xs = b.evaluator_input_bundles(&mods, nargs).unwrap();
        let z = b.mixed_radix_addition(&xs).unwrap();
        b.output_bundle(&z).unwrap();
        let circ = b.finish();

        let Q: u128 = mods.iter().map(|&q| q as u128).product();

        // test maximum overflow
        let mut ds = Vec::new();
        for _ in 0..nargs {
            ds.extend(util::as_mixed_radix(Q - 1, &mods).iter());
        }
        let res = circ.eval_plain(&[], &ds).unwrap();
        assert_eq!(
            util::from_mixed_radix(&res, &mods),
            (Q - 1) * (nargs as u128) % Q
        );

        // test random values
        for _ in 0..4 {
            let mut should_be = 0;
            let mut ds = Vec::new();
            for _ in 0..nargs {
                let x = rng.gen_u128() % Q;
                should_be = (should_be + x) % Q;
                ds.extend(util::as_mixed_radix(x, &mods).iter());
            }
            let res = circ.eval_plain(&[], &ds).unwrap();
            assert_eq!(util::from_mixed_radix(&res, &mods), should_be);
        }
    }
    //}}}
    #[test] // bundle relu {{{
    fn test_relu() {
        let mut rng = thread_rng();
        let q = util::modulus_with_width(10);
        println!("q={}", q);

        let b = CircuitBuilder::new();
        let x = b.garbler_input_bundle_crt(q, None).unwrap();
        let z = b.relu(&x, "100%", None).unwrap();
        b.output_bundle(&z).unwrap();
        let c = b.finish();

        for _ in 0..128 {
            let pt = rng.gen_u128() % q;
            let should_be = if pt < q / 2 { pt } else { 0 };
            let res = c.eval_plain(&crt_factor(pt, q), &[]).unwrap();
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
        let x = b.garbler_input_bundle_crt(q, None).unwrap();
        let z = b.sgn(&x, "100%", None).unwrap();
        b.output_bundle(&z).unwrap();
        let c = b.finish();

        for _ in 0..128 {
            let pt = rng.gen_u128() % q;
            let should_be = if pt < q / 2 { 1 } else { q - 1 };
            let res = c.eval_plain(&crt_factor(pt, q), &[]).unwrap();
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
        let x = b.garbler_input_bundle_crt(q, None).unwrap();
        let y = b.evaluator_input_bundle_crt(q).unwrap();
        let z = b.lt(&x, &y, "100%").unwrap();
        b.output(&z).unwrap();
        let c = b.finish();

        // lets have at least one test where they are surely equal
        let x = rng.gen_u128() % q / 2;
        let res = c.eval_plain(&crt_factor(x, q), &crt_factor(x, q)).unwrap();
        assert_eq!(res, &[(x < x) as u16], "x={}", x);

        for _ in 0..64 {
            let x = rng.gen_u128() % q / 2;
            let y = rng.gen_u128() % q / 2;
            let res = c.eval_plain(&crt_factor(x, q), &crt_factor(y, q)).unwrap();
            assert_eq!(res, &[(x < y) as u16], "x={} y={}", x, y);
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
        let xs = b.garbler_input_bundles_crt(q, n, None).unwrap();
        let z = b.max(&xs, "100%").unwrap();
        b.output_bundle(&z).unwrap();
        let c = b.finish();

        for _ in 0..16 {
            let inps = (0..n).map(|_| rng.gen_u128() % (q / 2)).collect_vec();
            println!("{:?}", inps);
            let should_be = *inps.iter().max().unwrap();

            let enc_inps = inps
                .into_iter()
                .flat_map(|x| crt_factor(x, q))
                .collect_vec();
            let res = c.eval_plain(&enc_inps, &[]).unwrap();
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
        let Q = util::product(&vec![q; n]);
        println!("n={} q={} Q={}", n, q, Q);

        let b = CircuitBuilder::new();
        let xs = b.garbler_input_bundle(&vec![q; n], None).unwrap();
        let ys = b.evaluator_input_bundle(&vec![q; n]).unwrap();
        let (zs, carry) = b.binary_addition(&xs, &ys).unwrap();
        b.output(&carry).unwrap();
        b.output_bundle(&zs).unwrap();
        let c = b.finish();

        for _ in 0..16 {
            let x = rng.gen_u128() % Q;
            let y = rng.gen_u128() % Q;
            println!("x={} y={}", x, y);
            let res_should_be = (x + y) % Q;
            let carry_should_be = (x + y >= Q) as u16;
            let res = c
                .eval_plain(&util::u128_to_bits(x, n), &util::u128_to_bits(y, n))
                .unwrap();
            assert_eq!(util::u128_from_bits(&res[1..]), res_should_be);
            assert_eq!(res[0], carry_should_be);
        }
    }
    //}}}
    #[test] // builder has send and sync {{{
    fn test_builder_has_send_and_sync() {
        fn check_send(_: impl Send) {}
        fn check_sync(_: impl Sync) {}
        check_send(CircuitBuilder::new());
        check_sync(CircuitBuilder::new());
    } // }}}
}
