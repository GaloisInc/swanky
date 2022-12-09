// -*- mode: rust; -*-
//
// This file is part of `fancy-garbling`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! DSL for creating circuits compatible with fancy-garbling in the old-fashioned way,
//! where you create a circuit for a computation then garble it.

use crate::{
    dummy::{Dummy, DummyVal},
    errors::{CircuitBuilderError, DummyError, FancyError},
    fancy::{BinaryBundle, CrtBundle, Fancy, FancyInput, HasModulus},
};
use core::hash::BuildHasher;
use itertools::Itertools;
use scuttlebutt::Block;
use std::collections::HashMap;

/// The index and modulus of a gate in a circuit.
#[derive(Default, Clone, Copy, Debug, PartialEq)]
#[cfg_attr(feature = "serde1", derive(serde::Serialize, serde::Deserialize))]
pub struct CircuitRef {
    pub(crate) ix: usize,
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
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde1", derive(serde::Serialize, serde::Deserialize))]
pub struct Circuit {
    pub(crate) gates: Vec<Gate>,
    pub(crate) gate_moduli: Vec<u16>,
    pub(crate) garbler_input_refs: Vec<CircuitRef>,
    pub(crate) evaluator_input_refs: Vec<CircuitRef>,
    pub(crate) const_refs: Vec<CircuitRef>,
    pub(crate) output_refs: Vec<CircuitRef>,
    pub(crate) num_nonfree_gates: usize,
}

/// The most basic types of computation supported by fancy garbling.
///
/// `id` represents the gate number. `out` gives the output wire index; if `out
/// = None`, then we use the gate index as the output wire index.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde1", derive(serde::Serialize, serde::Deserialize))]
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
    },
    Proj {
        xref: CircuitRef,
        tt: Vec<u16>,
        id: usize,
        out: Option<usize>,
    },
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

fn eval_prepare<F: Fancy>(
    f: &mut F,
    garbler_inputs: &[F::Item],
    evaluator_inputs: &[F::Item],
    gates: &[Gate],
    gate_moduli: &[u16],
) -> Result<Vec<Option<F::Item>>, F::Error> {
    let mut cache: Vec<Option<F::Item>> = vec![None; gates.len()];
    let mut temp_blocks = vec![Block::default(); 2];

    eval_prepare_with_prealloc(
        f,
        garbler_inputs,
        evaluator_inputs,
        gates,
        gate_moduli,
        &mut cache,
        &mut temp_blocks,
    )?;

    Ok(cache)
}

pub fn eval_prepare_with_prealloc<F: Fancy>(
    f: &mut F,
    garbler_inputs: &[F::Item],
    evaluator_inputs: &[F::Item],
    gates: &[Gate],
    gate_moduli: &[u16],
    cache: &mut Vec<Option<F::Item>>,
    temp_blocks: &mut Vec<Block>,
) -> Result<(), F::Error> {
    debug_assert_eq!(cache.len(), gates.len(), "cache is NOT the correct size!");
    for (i, gate) in gates.iter().enumerate() {
        let q = gate_moduli[i];
        let (zref_, val) = match *gate {
            Gate::GarblerInput { id } => (None, garbler_inputs[id].clone()),
            Gate::EvaluatorInput { id } => {
                assert!(
                    id < evaluator_inputs.len(),
                    "id={} ev_inps.len()={}",
                    id,
                    evaluator_inputs.len()
                );
                (None, evaluator_inputs[id].clone())
            }
            Gate::Constant { val } => (None, f.constant(val, q)?),
            Gate::Add { xref, yref, out } => (
                out,
                f.add(
                    cache[xref.ix]
                        .as_ref()
                        .ok_or_else(|| F::Error::from(FancyError::UninitializedValue))?,
                    cache[yref.ix]
                        .as_ref()
                        .ok_or_else(|| F::Error::from(FancyError::UninitializedValue))?,
                )?,
            ),
            Gate::Sub { xref, yref, out } => (
                out,
                f.sub(
                    cache[xref.ix]
                        .as_ref()
                        .ok_or_else(|| F::Error::from(FancyError::UninitializedValue))?,
                    cache[yref.ix]
                        .as_ref()
                        .ok_or_else(|| F::Error::from(FancyError::UninitializedValue))?,
                )?,
            ),
            Gate::Cmul { xref, c, out } => (
                out,
                f.cmul(
                    cache[xref.ix]
                        .as_ref()
                        .ok_or_else(|| F::Error::from(FancyError::UninitializedValue))?,
                    c,
                )?,
            ),
            Gate::Proj {
                xref, ref tt, out, ..
            } => (
                out,
                f.proj(
                    cache[xref.ix]
                        .as_ref()
                        .ok_or_else(|| F::Error::from(FancyError::UninitializedValue))?,
                    q,
                    Some(tt.to_vec()),
                )?,
            ),
            Gate::Mul {
                xref, yref, out, ..
            } => (
                out,
                f.mul_with_prealloc(
                    cache[xref.ix]
                        .as_ref()
                        .ok_or_else(|| F::Error::from(FancyError::UninitializedValue))?,
                    cache[yref.ix]
                        .as_ref()
                        .ok_or_else(|| F::Error::from(FancyError::UninitializedValue))?,
                    temp_blocks,
                )?,
            ),
        };
        cache[zref_.unwrap_or(i)] = Some(val);
    }

    Ok(())
}

fn eval_eval<F: Fancy>(
    cache: &[Option<F::Item>],
    f: &mut F,
    output_refs: &[CircuitRef],
) -> Result<Option<Vec<u16>>, F::Error> {
    let mut outputs = vec![None; output_refs.len()];
    let mut temp_blocks = vec![Block::default(); 2];
    let mut hashes_cache: HashMap<(F::Item, usize, u16), Block> = HashMap::new();
    eval_eval_with_prealloc(
        cache,
        f,
        output_refs,
        &mut outputs,
        &mut temp_blocks,
        &mut hashes_cache,
    )?;
    Ok(outputs.into_iter().collect())
}

pub fn eval_eval_with_prealloc<F: Fancy, H: BuildHasher>(
    cache: &[Option<F::Item>],
    f: &mut F,
    output_refs: &[CircuitRef],
    outputs: &mut Vec<Option<u16>>,
    temp_blocks: &mut Vec<Block>,
    hashes_cache: &mut HashMap<(F::Item, usize, u16), Block, H>,
) -> Result<(), F::Error> {
    debug_assert_eq!(output_refs.len(), outputs.len(), "outputs NOT init!");
    for (i, r) in output_refs.iter().enumerate() {
        // TODO(interstellar) debug_assert_eq!(cache[i], Some(r), "bad index!");
        let r = cache[r.ix]
            .as_ref()
            .ok_or_else(|| F::Error::from(FancyError::UninitializedValue))?;
        let out = f.output_with_prealloc(r, temp_blocks, hashes_cache)?;
        outputs[i] = out;
    }

    Ok(())
}

impl Circuit {
    /// Make a new `Circuit` object.
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

    /// Evaluate the circuit using fancy object `f`.
    pub fn eval<F: Fancy>(
        &self,
        f: &mut F,
        garbler_inputs: &[F::Item],
        evaluator_inputs: &[F::Item],
    ) -> Result<Option<Vec<u16>>, F::Error> {
        let cache = eval_prepare(
            f,
            garbler_inputs,
            evaluator_inputs,
            &self.gates,
            &self.gate_moduli,
        )?;

        eval_eval(&cache, f, &self.output_refs)
    }

    /// fn eval: version with preallocated outputs
    /// This is the client-side use case, where we call eval() inside a render loop
    pub fn eval_with_prealloc<F: Fancy, H: BuildHasher>(
        &self,
        f: &mut F,
        garbler_inputs: &[F::Item],
        evaluator_inputs: &[F::Item],
        outputs: &mut Vec<Option<u16>>,
        cache: &mut Vec<Option<F::Item>>,
        temp_blocks: &mut Vec<Block>,
        hashes_cache: &mut HashMap<(F::Item, usize, u16), Block, H>,
    ) -> Result<(), F::Error> {
        eval_prepare_with_prealloc(
            f,
            garbler_inputs,
            evaluator_inputs,
            &self.gates,
            &self.gate_moduli,
            cache,
            temp_blocks,
        )?;

        eval_eval_with_prealloc(
            cache,
            f,
            &self.output_refs,
            outputs,
            temp_blocks,
            hashes_cache,
        )
    }

    /// Evaluate the circuit in plaintext.
    pub fn eval_plain(
        &self,
        garbler_inputs: &[u16],
        evaluator_inputs: &[u16],
    ) -> Result<Vec<u16>, DummyError> {
        let mut dummy = crate::dummy::Dummy::new();

        if garbler_inputs.len() != self.garbler_input_refs.len() {
            return Err(DummyError::NotEnoughGarblerInputs);
        }

        if evaluator_inputs.len() != self.evaluator_input_refs.len() {
            return Err(DummyError::NotEnoughEvaluatorInputs);
        }

        // encode inputs as DummyVals
        let gb = garbler_inputs
            .iter()
            .zip(self.garbler_input_refs.iter())
            .map(|(x, r)| DummyVal::new(*x, r.modulus()))
            .collect_vec();
        let ev = evaluator_inputs
            .iter()
            .zip(self.evaluator_input_refs.iter())
            .map(|(x, r)| DummyVal::new(*x, r.modulus()))
            .collect_vec();

        let outputs = self.eval(&mut dummy, &gb, &ev)?;
        Ok(outputs.expect("dummy will always return Some(u16) output"))
    }

    /// Print circuit info.
    pub fn print_info(&self) -> Result<(), DummyError> {
        let mut informer = crate::informer::Informer::new(Dummy::new());

        // encode inputs as InformerVals
        let gb = self
            .garbler_input_refs
            .iter()
            .map(|r| informer.receive(r.modulus()))
            .collect::<Result<Vec<DummyVal>, DummyError>>()?;
        let ev = self
            .evaluator_input_refs
            .iter()
            .map(|r| informer.receive(r.modulus()))
            .collect::<Result<Vec<DummyVal>, DummyError>>()?;

        let _outputs = self.eval(&mut informer, &gb, &ev)?;
        println!("{}", informer.stats());
        Ok(())
    }

    /// Return the number of garbler inputs.
    #[inline]
    pub fn num_garbler_inputs(&self) -> usize {
        self.garbler_input_refs.len()
    }

    /// Return the number of evaluator inputs.
    #[inline]
    pub fn num_evaluator_inputs(&self) -> usize {
        self.evaluator_input_refs.len()
    }

    /// Return the number of outputs.
    #[inline]
    pub fn noutputs(&self) -> usize {
        self.output_refs.len()
    }

    /// Return the modulus of the gate indexed by `i`.
    #[inline]
    pub fn modulus(&self, i: usize) -> u16 {
        self.gate_moduli[i]
    }

    /// Return the modulus of the garbler input indexed by `i`.
    #[inline]
    pub fn garbler_input_mod(&self, i: usize) -> u16 {
        let r = self.garbler_input_refs[i];
        r.modulus()
    }

    /// Return the modulus of the evaluator input indexed by `i`.
    #[inline]
    pub fn evaluator_input_mod(&self, i: usize) -> u16 {
        let r = self.evaluator_input_refs[i];
        r.modulus()
    }
}

/// CircuitBuilder is used to build circuits.
pub struct CircuitBuilder {
    next_ref_ix: usize,
    next_garbler_input_id: usize,
    next_evaluator_input_id: usize,
    const_map: HashMap<(u16, u16), CircuitRef>,
    circ: Circuit,
}

impl Fancy for CircuitBuilder {
    type Item = CircuitRef;
    type Error = CircuitBuilderError;

    fn constant(&mut self, val: u16, modulus: u16) -> Result<CircuitRef, Self::Error> {
        match self.const_map.get(&(val, modulus)) {
            Some(&r) => Ok(r),
            None => {
                let gate = Gate::Constant { val };
                let r = self.gate(gate, modulus);
                self.const_map.insert((val, modulus), r);
                self.circ.const_refs.push(r);
                Ok(r)
            }
        }
    }

    fn add(&mut self, xref: &CircuitRef, yref: &CircuitRef) -> Result<CircuitRef, Self::Error> {
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

    fn sub(&mut self, xref: &CircuitRef, yref: &CircuitRef) -> Result<CircuitRef, Self::Error> {
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

    fn cmul(&mut self, xref: &CircuitRef, c: u16) -> Result<CircuitRef, Self::Error> {
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
        &mut self,
        xref: &CircuitRef,
        output_modulus: u16,
        tt: Option<Vec<u16>>,
    ) -> Result<CircuitRef, Self::Error> {
        let tt = tt.ok_or_else(|| Self::Error::from(FancyError::NoTruthTable))?;
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

    fn mul_with_prealloc(
        &mut self,
        xref: &CircuitRef,
        yref: &CircuitRef,
        temp_blocks: &mut Vec<Block>,
    ) -> Result<CircuitRef, Self::Error> {
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

    fn output(&mut self, xref: &CircuitRef) -> Result<Option<u16>, Self::Error> {
        // println!("output called");
        self.circ.output_refs.push(*xref);
        Ok(None)
    }

    fn output_with_prealloc<H: BuildHasher>(
        &mut self,
        xref: &Self::Item,
        temp_blocks: &mut Vec<Block>,
        hashes_cache: &mut HashMap<(Self::Item, usize, u16), Block, H>,
    ) -> Result<Option<u16>, Self::Error> {
        todo!()
    }
}

impl CircuitBuilder {
    /// Make a new `CircuitBuilder`.
    pub fn new() -> Self {
        CircuitBuilder {
            next_ref_ix: 0,
            next_garbler_input_id: 0,
            next_evaluator_input_id: 0,
            const_map: HashMap::new(),
            circ: Circuit::new(None),
        }
    }

    /// Finish circuit building, outputting the resulting circuit.
    pub fn finish(self) -> Circuit {
        self.circ
    }

    fn get_next_garbler_input_id(&mut self) -> usize {
        let current = self.next_garbler_input_id;
        self.next_garbler_input_id += 1;
        current
    }

    fn get_next_evaluator_input_id(&mut self) -> usize {
        let current = self.next_evaluator_input_id;
        self.next_evaluator_input_id += 1;
        current
    }

    fn get_next_ciphertext_id(&mut self) -> usize {
        let current = self.circ.num_nonfree_gates;
        self.circ.num_nonfree_gates += 1;
        current
    }

    fn get_next_ref_ix(&mut self) -> usize {
        let current = self.next_ref_ix;
        self.next_ref_ix += 1;
        current
    }

    fn gate(&mut self, gate: Gate, modulus: u16) -> CircuitRef {
        self.circ.gates.push(gate);
        self.circ.gate_moduli.push(modulus);
        let ix = self.get_next_ref_ix();
        CircuitRef { ix, modulus }
    }

    /// Get CircuitRef for a garbler input wire.
    pub fn garbler_input(&mut self, modulus: u16) -> CircuitRef {
        let id = self.get_next_garbler_input_id();
        let r = self.gate(Gate::GarblerInput { id }, modulus);
        self.circ.garbler_input_refs.push(r);
        r
    }

    /// Get CircuitRef for an evaluator input wire.
    pub fn evaluator_input(&mut self, modulus: u16) -> CircuitRef {
        let id = self.get_next_evaluator_input_id();
        let r = self.gate(Gate::EvaluatorInput { id }, modulus);
        self.circ.evaluator_input_refs.push(r);
        r
    }

    /// Get a vec of CircuitRefs for garbler inputs.
    pub fn garbler_inputs(&mut self, mods: &[u16]) -> Vec<CircuitRef> {
        mods.iter().map(|q| self.garbler_input(*q)).collect()
    }

    /// Get a vec of CircuitRefs for garbler inputs.
    pub fn evaluator_inputs(&mut self, mods: &[u16]) -> Vec<CircuitRef> {
        mods.iter().map(|q| self.evaluator_input(*q)).collect()
    }

    /// Get a CrtBundle for the garbler using composite modulus Q
    pub fn crt_garbler_input(&mut self, modulus: u128) -> CrtBundle<CircuitRef> {
        CrtBundle::new(self.garbler_inputs(&crate::util::factor(modulus)))
    }

    /// Get a CrtBundle for the evaluator using composite modulus Q
    pub fn crt_evaluator_input(&mut self, modulus: u128) -> CrtBundle<CircuitRef> {
        CrtBundle::new(self.evaluator_inputs(&crate::util::factor(modulus)))
    }

    /// Get a BinaryBundle for the garbler with n bits.
    pub fn bin_garbler_input(&mut self, nbits: usize) -> BinaryBundle<CircuitRef> {
        BinaryBundle::new(self.garbler_inputs(&vec![2; nbits]))
    }

    /// Get a BinaryBundle for the evaluator with n bits.
    pub fn bin_evaluator_input(&mut self, nbits: usize) -> BinaryBundle<CircuitRef> {
        BinaryBundle::new(self.evaluator_inputs(&vec![2; nbits]))
    }
}

#[cfg(test)]
mod plaintext {
    use super::*;
    use crate::util::RngExt;
    use itertools::Itertools;
    use rand::thread_rng;

    #[test] // {{{ and_gate_fan_n
    fn and_gate_fan_n() {
        let mut rng = thread_rng();

        let mut b = CircuitBuilder::new();
        let n = 2 + (rng.gen_usize() % 200);
        let inps = b.evaluator_inputs(&vec![2; n]);
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
        let mut b = CircuitBuilder::new();
        let n = 2 + (rng.gen_usize() % 200);
        let inps = b.evaluator_inputs(&vec![2; n]);
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
        let mut b = CircuitBuilder::new();
        let q = rng.gen_prime();
        let x = b.garbler_input(q);
        let y = b.evaluator_input(q);
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
        let mut b = CircuitBuilder::new();
        let p = rng.gen_prime();
        let q = rng.gen_prime();
        let x = b.garbler_input(p);
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
        let mut b = CircuitBuilder::new();
        let n = 113;
        let args = b.garbler_inputs(&vec![2; n]);
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
        let mut b = CircuitBuilder::new();
        let mut rng = thread_rng();

        let q = rng.gen_modulus();
        let c = rng.gen_u16() % q;

        let x = b.evaluator_input(q);
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
    use crate::{
        fancy::{BinaryGadgets, BundleGadgets, CrtGadgets},
        util::{self, crt_factor, crt_inv_factor, RngExt},
    };
    use itertools::Itertools;
    use rand::thread_rng;

    #[test] // bundle input and output {{{
    fn test_bundle_input_output() {
        let mut rng = thread_rng();
        let q = rng.gen_usable_composite_modulus();

        let mut b = CircuitBuilder::new();
        let x = b.crt_garbler_input(q);
        println!("{:?} wires", x.wires().len());
        b.output_bundle(&x).unwrap();
        let c = b.finish();

        println!("{:?}", c.output_refs);

        for _ in 0..16 {
            let x = rng.gen_u128() % q;
            let res = c.eval_plain(&crt_factor(x, q), &[]).unwrap();
            println!("{:?}", res);
            let z = crt_inv_factor(&res, q);
            assert_eq!(x, z);
        }
    }

    //}}}
    #[test] // bundle addition {{{
    fn test_addition() {
        let mut rng = thread_rng();
        let q = rng.gen_usable_composite_modulus();

        let mut b = CircuitBuilder::new();
        let x = b.crt_garbler_input(q);
        let y = b.crt_evaluator_input(q);
        let z = b.crt_add(&x, &y).unwrap();
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

        let mut b = CircuitBuilder::new();
        let x = b.crt_garbler_input(q);
        let y = b.crt_evaluator_input(q);
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

        let mut b = CircuitBuilder::new();
        let x = b.crt_garbler_input(q);
        let y = rng.gen_u128() % q;
        let z = b.crt_cmul(&x, y).unwrap();
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

        let mut b = CircuitBuilder::new();
        let x = b.crt_garbler_input(q);
        let y = b.crt_evaluator_input(q);
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

        let mut b = CircuitBuilder::new();
        let x = b.crt_garbler_input(q);
        let z = b.crt_cexp(&x, y).unwrap();
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

        let mut b = CircuitBuilder::new();
        let x = b.crt_garbler_input(q);
        let z = b.crt_rem(&x, p).unwrap();
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

        let mut b = CircuitBuilder::new();
        let x = b.crt_garbler_input(q);
        let y = b.crt_evaluator_input(q);
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

        let mut b = CircuitBuilder::new();
        let xs = (0..nargs)
            .map(|_| crate::fancy::Bundle::new(b.evaluator_inputs(&mods)))
            .collect_vec();
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

        let mut b = CircuitBuilder::new();
        let x = b.crt_garbler_input(q);
        let z = b.crt_relu(&x, "100%", None).unwrap();
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

        let mut b = CircuitBuilder::new();
        let x = b.crt_garbler_input(q);
        let z = b.crt_sgn(&x, "100%", None).unwrap();
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

        let mut b = CircuitBuilder::new();
        let x = b.crt_garbler_input(q);
        let y = b.crt_evaluator_input(q);
        let z = b.crt_lt(&x, &y, "100%").unwrap();
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

        let mut b = CircuitBuilder::new();
        let xs = (0..n).map(|_| b.crt_garbler_input(q)).collect_vec();
        let z = b.crt_max(&xs, "100%").unwrap();
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

        let mut b = CircuitBuilder::new();
        let x = b.bin_garbler_input(n);
        let y = b.bin_evaluator_input(n);
        let (zs, carry) = b.bin_addition(&x, &y).unwrap();
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
    #[test] // binary demux {{{
    fn test_bin_demux() {
        let mut rng = thread_rng();
        let nbits = 1 + (rng.gen_usize() % 7);
        let Q = 1 << nbits as u128;

        let mut b = CircuitBuilder::new();
        let x = b.bin_garbler_input(nbits);
        let d = b.bin_demux(&x).unwrap();
        b.outputs(&d).unwrap();
        let c = b.finish();

        for _ in 0..16 {
            let x = rng.gen_u128() % Q;
            println!("x={}", x);
            let mut should_be = vec![0; Q as usize];
            should_be[x as usize] = 1;

            let res = c.eval_plain(&util::u128_to_bits(x, nbits), &[]).unwrap();

            for (i, y) in res.into_iter().enumerate() {
                if i as u128 == x {
                    assert_eq!(y, 1);
                } else {
                    assert_eq!(y, 0);
                }
            }
        }
    }
    //}}}
}
