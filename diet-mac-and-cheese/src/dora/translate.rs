use crate::{
    circuit_ir::{self, FunStore, FunctionBody, GateM, TypeId},
    fields::SieveIrDeserialize,
};

use super::DisjGate;

#[derive(Default)]
struct WireFrame {
    // next available cell number
    next: usize,
    // maps SIEVE wire ids (index) to cell numbers
    alias: Vec<Option<super::WireId>>,
}

impl WireFrame {
    fn new(inputs: usize, outputs: usize) -> Self {
        WireFrame {
            next: inputs + outputs,
            alias: (0..inputs + outputs).map(Some).collect(),
        }
    }

    // translates a SIEVE wire id to a cell number
    fn translate(&mut self, org: circuit_ir::WireId) -> super::WireId {
        let idx = org as usize;
        if self.alias.len() <= idx {
            self.alias.resize(idx + 1, None);
        }

        match &mut self.alias[idx] {
            Some(cell) => *cell,
            tx => {
                let cell = self.next;
                self.next = cell + 1;
                *tx = Some(cell);
                cell
            }
        }
    }

    // descend into a child scope (used with function calls)
    fn descend(&self, map: Vec<(circuit_ir::WireId, super::WireId)>) -> Self {
        // create initial alias map
        let size = map
            .iter()
            .map(|(org, _)| (*org + 1) as usize)
            .max()
            .unwrap_or(0);

        let mut alias = vec![None; size];
        for (org, dst) in map {
            alias[org as usize] = Some(dst);
        }

        WireFrame {
            next: self.next,
            alias,
        }
    }
}

/// Translates a SIEVE-IR gate to a list of `DisjGate`
pub(crate) fn translate<F: SieveIrDeserialize>(
    inputs: usize,
    outputs: usize,
    disj_gates: &mut Vec<DisjGate<F>>,
    fun_store: &FunStore,
    typ: TypeId,
    gates: impl Iterator<Item = GateM>,
) {
    translate_gates(
        disj_gates,
        fun_store,
        typ,
        gates,
        &mut WireFrame::new(inputs, outputs),
    );
}

fn translate_gates<F: SieveIrDeserialize>(
    disj_gates: &mut Vec<DisjGate<F>>,
    fun_store: &FunStore,
    typ: TypeId,
    gates: impl Iterator<Item = GateM>,
    frame: &mut WireFrame,
) {
    for gate in gates {
        translate_gate(disj_gates, fun_store, typ, gate, frame);
    }
}

// Translates `gate` to one or more `DisjGate`, pushing the result(s) to
// `disj_gates`. Checks that all gates are for `typ`.
fn translate_gate<F: SieveIrDeserialize>(
    disj_gates: &mut Vec<DisjGate<F>>,
    fun_store: &FunStore,
    typ: TypeId,
    gate: GateM,
    frame: &mut WireFrame,
) {
    match gate {
        GateM::Add(typ2, dst, lhs, rhs) => {
            assert_eq!(typ2, typ, "different types in disjunction");
            disj_gates.push(DisjGate::Add(
                frame.translate(dst),
                frame.translate(lhs),
                frame.translate(rhs),
            ))
        }
        GateM::Sub(typ2, dst, lhs, rhs) => {
            assert_eq!(typ2, typ, "different types in disjunction");
            disj_gates.push(DisjGate::Sub(
                frame.translate(dst),
                frame.translate(lhs),
                frame.translate(rhs),
            ))
        }
        GateM::Mul(typ2, dst, lhs, rhs) => {
            assert_eq!(typ2, typ, "different types in disjunction");
            disj_gates.push(DisjGate::Mul(
                frame.translate(dst),
                frame.translate(lhs),
                frame.translate(rhs),
            ))
        }
        GateM::Copy(typ2, dst, src) => {
            assert_eq!(typ2, typ, "different types in disjunction");

            // flatten ranges
            let dsts = dst.0..=dst.1;
            let srcs = src.iter().cloned().flat_map(|(s, e)| s..=e);

            // translate each copy
            for (w_dst, w_src) in dsts.zip(srcs) {
                // explicit copy
                disj_gates.push(DisjGate::Copy(
                    frame.translate(w_dst),
                    frame.translate(w_src),
                ));
            }
        }
        GateM::Witness(typ2, dst) => {
            assert_eq!(typ2, typ, "different types in disjunction");
            for curr_dst in dst.0..=dst.1 {
                disj_gates.push(DisjGate::Witness(frame.translate(curr_dst)))
            }
        }
        GateM::Constant(typ2, dst, cnst) => {
            assert_eq!(typ2, typ, "different types in disjunction");
            let val = F::from_number(&cnst).unwrap();
            disj_gates.push(DisjGate::Constant(frame.translate(dst), val))
        }
        GateM::AddConstant(typ2, dst, src, cnst) => {
            assert_eq!(typ2, typ, "different types in disjunction");
            let val = F::from_number(&cnst).unwrap();
            disj_gates.push(DisjGate::AddConstant(
                frame.translate(dst),
                frame.translate(src),
                val,
            ))
        }
        GateM::MulConstant(typ2, dst, src, cnst) => {
            assert_eq!(typ2, typ, "different types in disjunction");
            let val = F::from_number(&cnst).unwrap();
            disj_gates.push(DisjGate::MulConstant(
                frame.translate(dst),
                frame.translate(src),
                val,
            ))
        }
        GateM::AssertZero(typ2, src) => {
            assert_eq!(typ2, typ, "different types in disjunction");
            disj_gates.push(DisjGate::AssertZero(frame.translate(src)))
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

            // check that the function has the correct type
            for typ2 in func.compiled_info.type_ids.iter() {
                assert_eq!(*typ2, typ, "different types in disjunction");
            }

            // Check that no output wires are used as input wires.
            // This way, the input cells does not change during the function call.
            //
            // This is enforced by the SIEVE-IR spec, because of single assignment:
            // otherwise it would require reassigning the input wires.
            // So this is a sanity check.
            #[cfg(debug_assertions)]
            {
                use std::collections::HashSet;

                let src_set: HashSet<u64> =
                    src_wires.iter().cloned().flat_map(|(s, e)| s..=e).collect();

                assert!(
                    !dst_wires
                        .iter()
                        .cloned()
                        .flat_map(|(s, e)| s..=e)
                        .any(|x| src_set.contains(&x)),
                    "output wires used as input wires"
                )
            }

            // Alias parent inputs/outputs cells into the child scope.
            //
            // Note:
            //
            // - the function call cannot assign to inputs
            // - the set of outputs is disjoint from the set of inputs
            //
            // Both follows from single assignment in SIEVE-IR.
            // Therefore we can safely alias the input/output
            // cells of the parent into the child scope.
            let mut wire = 0;
            let mut alias = Vec::with_capacity(func.compiled_info.outputs_cnt as usize);
            for (start, end) in dst_wires.iter() {
                for dst in *start..=*end {
                    alias.push((wire, frame.translate(dst)));
                    wire += 1;
                }
            }
            for (start, end) in src_wires.iter() {
                for src in *start..=*end {
                    alias.push((wire, frame.translate(src)));
                    wire += 1;
                }
            }

            // check that the number of arguments is correct
            debug_assert_eq!(wire, func.compiled_info.inputs_cnt);
            debug_assert_eq!(alias.len(), func.compiled_info.inputs_cnt as usize);

            // translate function body
            match func.body() {
                FunctionBody::Gates(body) => {
                    translate_gates(
                        disj_gates,
                        fun_store,
                        typ,
                        body.gates().iter().cloned(),
                        &mut frame.descend(alias),
                    );
                }
                _ => panic!("unsupported function body in disjunction (not gates)"),
            }

            // leaving the child scope
            // automatically garbage collects the
            // cells allocated in the child scope as "next" is reset.
        }

        GateM::New(_, _, _) | GateM::Comment(_) => {}
        _ => panic!("unsupported gate: {:?}", gate),
    }
}
