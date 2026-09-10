/*! Circuit validation.
 *
 * This is a circuit validator for a subset of SIEVE-IR.
 *
 * Property validated:
 * a) each wire is assigned at most once.
 * b) each wire has been assigned before read.
 */

use crate::circuit::Circuit;
use crate::circuit::GateM;
use std::collections::BTreeMap;
use swanky_error::{ErrorKind, bail};
use swanky_sieve_ir_parser::WireId;

#[derive(Default)]
struct ValidatorMemory {
    mem: BTreeMap<WireId, ()>,
}

impl ValidatorMemory {
    pub(crate) fn assign(&mut self, wid: WireId) -> swanky_error::Result<()> {
        if self.mem.contains_key(&wid) {
            bail!(ErrorKind::OtherError, "wire {wid} already assigned")
        }
        self.mem.insert(wid, ());
        Ok(())
    }

    pub(crate) fn check_free(&self, wid: &WireId) -> swanky_error::Result<()> {
        if self.mem.contains_key(wid) {
            bail!(ErrorKind::OtherError, "wire {wid} is not free")
        }
        Ok(())
    }

    pub(crate) fn check_assigned(&self, wid: &WireId) -> swanky_error::Result<()> {
        if !self.mem.contains_key(wid) {
            bail!(ErrorKind::OtherError, "wire {wid} not assigned")
        }
        Ok(())
    }
}

#[derive(Default)]
struct Validator {
    memory: ValidatorMemory,
}

impl Validator {
    fn validate(&mut self, circuit: &Circuit) -> swanky_error::Result<()> {
        for g in circuit.gates.iter().cloned() {
            match g {
                GateM::Add(_ty, dst, left, right) => {
                    self.memory.check_assigned(&left)?;
                    self.memory.check_assigned(&right)?;

                    self.memory.check_free(&dst)?;
                    self.memory.assign(dst)?;
                }
                GateM::Mul(_ty, dst, left, right) => {
                    self.memory.check_assigned(&left)?;
                    self.memory.check_assigned(&right)?;

                    self.memory.check_free(&dst)?;
                    self.memory.assign(dst)?;
                }
                GateM::AddConstant(_ty, dst, left, _right) => {
                    self.memory.check_assigned(&left)?;

                    self.memory.check_free(&dst)?;
                    self.memory.assign(dst)?;
                }
                GateM::Witness(_ty, dst) => {
                    for wid in dst.start..=dst.end {
                        self.memory.check_free(&wid)?;
                        self.memory.assign(wid)?;
                    }
                }
                _ => bail!(
                    ErrorKind::UnsupportedError,
                    "Invalid input: VOLE-in-the-head does not support gate {:?}",
                    g
                ),
            }
        }
        Ok(())
    }
}

/// Validate a circuit
pub fn validate_circuit(circuit: &Circuit) -> swanky_error::Result<()> {
    Validator::default().validate(circuit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use swanky_sieve_ir_parser::{TypeId, WireRange};

    const TY: TypeId = 0;

    #[test]
    fn property_allows_unique_assignments() {
        let circuit = Circuit {
            gates: vec![
                GateM::Witness(TY, WireRange { start: 0, end: 1 }),
                GateM::Add(TY, 2, 0, 1),
            ],
            private_inputs: vec![],
            max_wire_id: 2,
        };

        assert!(Validator::default().validate(&circuit).is_ok());
    }

    #[test]
    fn property_rejects_double_assignment() {
        let circuit = Circuit {
            gates: vec![
                GateM::Witness(TY, WireRange { start: 0, end: 1 }),
                GateM::Add(TY, 2, 0, 1),
                GateM::Mul(TY, 2, 0, 1),
            ],
            private_inputs: vec![],
            max_wire_id: 2,
        };

        let err = Validator::default()
            .validate(&circuit)
            .unwrap_err()
            .to_string();
        assert!(err.contains("not free"));
    }

    #[test]
    fn property_allows_read_after_assignment() {
        let circuit = Circuit {
            gates: vec![
                GateM::Witness(TY, WireRange { start: 0, end: 1 }),
                GateM::Mul(TY, 2, 0, 1),
            ],
            private_inputs: vec![],
            max_wire_id: 2,
        };

        assert!(Validator::default().validate(&circuit).is_ok());
    }

    #[test]
    fn property_rejects_read_before_assignment() {
        let circuit = Circuit {
            gates: vec![GateM::Add(TY, 2, 0, 1)],
            private_inputs: vec![],
            max_wire_id: 2,
        };

        let err = Validator::default()
            .validate(&circuit)
            .unwrap_err()
            .to_string();
        assert!(err.contains("not assigned"));
    }
}
