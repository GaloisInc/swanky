use std::collections::HashMap;

use mac_n_cheese_sieve_parser::TypeId;
use swanky_field::PrimeFiniteField;

use crate::circuit_ir::{FunStore, FunctionBody, GateM};

use super::DisjGate;

#[derive(Default)]
struct WireFrame {
    map: HashMap<mac_n_cheese_sieve_parser::WireId, super::WireId>,
    max: usize, // max cell number assigned in this scope
    off: usize, // offset for cell numbers in this scope
}

impl WireFrame {
    // translates a SIEVE wire id to a cell number
    fn translate(&mut self, org: mac_n_cheese_sieve_parser::WireId) -> super::WireId {
        match self.map.get(&org) {
            Some(r) => *r,
            None => {
                let idx = self.off + org as usize;
                self.max = std::cmp::max(self.max, idx);
                idx
            }
        }
    }

    // descend into a child scope (used with function calls)
    fn descend(&self, map: Vec<(mac_n_cheese_sieve_parser::WireId, super::WireId)>) -> Self {
        WireFrame {
            max: self.max,
            off: self.max + 1, // avoids reassigning cells from parent
            map: map.into_iter().collect(),
        }
    }
}

pub(crate) fn translate<F: PrimeFiniteField>(
    disj_gates: &mut Vec<DisjGate<F>>,
    fun_store: &FunStore,
    typ: TypeId,
    gates: impl Iterator<Item = GateM>,
) {
    translate_gates(disj_gates, fun_store, typ, gates, &mut WireFrame::default());
}

fn translate_gates<F: PrimeFiniteField>(
    disj_gates: &mut Vec<DisjGate<F>>,
    fun_store: &FunStore,
    typ: TypeId,
    gates: impl Iterator<Item = GateM>,
    alloc: &mut WireFrame,
) {
    for gate in gates {
        translate_gate(disj_gates, fun_store, typ, gate, alloc);
    }
}

// Translates `gate` to one or more `DisjGate`, pushing the result(s) to
// `disj_gates`. Checks that all gates are for `typ`.
fn translate_gate<F: PrimeFiniteField>(
    disj_gates: &mut Vec<DisjGate<F>>,
    fun_store: &FunStore,
    typ: TypeId,
    gate: GateM,
    alloc: &mut WireFrame,
) {
    match gate {
        GateM::Add(typ2, dst, lhs, rhs) => {
            assert_eq!(typ2, typ, "different types in disjunction");
            disj_gates.push(DisjGate::Add(
                alloc.translate(dst),
                alloc.translate(lhs),
                alloc.translate(rhs),
            ))
        }
        GateM::Sub(typ2, dst, lhs, rhs) => {
            assert_eq!(typ2, typ, "different types in disjunction");
            disj_gates.push(DisjGate::Sub(
                alloc.translate(dst),
                alloc.translate(lhs),
                alloc.translate(rhs),
            ))
        }
        GateM::Mul(typ2, dst, lhs, rhs) => {
            assert_eq!(typ2, typ, "different types in disjunction");
            disj_gates.push(DisjGate::Mul(
                alloc.translate(dst),
                alloc.translate(lhs),
                alloc.translate(rhs),
            ))
        }
        GateM::Copy(typ2, dst, src) => {
            assert_eq!(typ2, typ, "different types in disjunction");
            let mut curr_out = dst.0;
            for curr_input_range in *src {
                for curr_inp in curr_input_range.0..=curr_input_range.1 {
                    disj_gates.push(DisjGate::Copy(
                        alloc.translate(curr_out),
                        alloc.translate(curr_inp),
                    ));
                    curr_out += 1;
                }
            }
        }
        GateM::Witness(typ2, dst) => {
            assert_eq!(typ2, typ, "different types in disjunction");
            for curr_dst in dst.0..=dst.1 {
                disj_gates.push(DisjGate::Witness(alloc.translate(curr_dst)))
            }
        }
        GateM::Constant(typ2, dst, cnst) => {
            assert_eq!(typ2, typ, "different types in disjunction");
            let val = F::try_from_int(*cnst).unwrap();
            disj_gates.push(DisjGate::Constant(alloc.translate(dst), val))
        }
        GateM::AddConstant(typ2, dst, src, cnst) => {
            assert_eq!(typ2, typ, "different types in disjunction");
            let val = F::try_from_int(*cnst).unwrap();
            disj_gates.push(DisjGate::AddConstant(
                alloc.translate(dst),
                alloc.translate(src),
                val,
            ))
        }
        GateM::MulConstant(typ2, dst, src, cnst) => {
            assert_eq!(typ2, typ, "different types in disjunction");
            let val = F::try_from_int(*cnst).unwrap();
            disj_gates.push(DisjGate::MulConstant(
                alloc.translate(dst),
                alloc.translate(src),
                val,
            ))
        }
        GateM::AssertZero(typ2, src) => {
            assert_eq!(typ2, typ, "different types in disjunction");
            disj_gates.push(DisjGate::AssertZero(alloc.translate(src)))
        }
        GateM::Call(call_gate) => {
            // recall:
            // - the first arguments in the function call are outputs
            // - the last arguments in the function call are inputs
            let fun_id = call_gate.0;
            let dst_wires = &call_gate.1;
            let src_wires = &call_gate.2;

            // lookup function body
            let func = fun_store.get_func(fun_id).unwrap();

            // Map inputs/outputs to cells into the child scope
            // avoids needing to copy arguments and return values
            // to/from the parent scope
            //
            // Note: this relies on wires being single assignment in SIEVE-IR
            let mut w = 0;
            let mut alias = Vec::with_capacity(func.compiled_info.outputs_cnt as usize);
            for (start, end) in dst_wires.iter() {
                for dst in *start..=*end {
                    alias.push((w, alloc.translate(dst)));
                    w += 1;
                }
            }
            for (start, end) in src_wires.iter() {
                for src in *start..=*end {
                    alias.push((w, alloc.translate(src)));
                    w += 1;
                }
            }

            // check that the number of arguments is correct
            debug_assert_eq!(w, func.compiled_info.inputs_cnt);
            debug_assert_eq!(alias.len(), func.compiled_info.inputs_cnt as usize);

            // translate function body
            match func.body() {
                FunctionBody::Gates(body) => {
                    translate_gates(
                        disj_gates,
                        fun_store,
                        typ,
                        body.gates().iter().cloned(),
                        &mut alloc.descend(alias),
                    );
                }
                _ => panic!("unsupported function body"),
            }
        }

        GateM::New(_, _, _) | GateM::Comment(_) => {}
        _ => panic!("unsupported gate: {:?}", gate),
    }
}
