//! The functions that do the actual garbling, used by the `Garbler` iterator.

use crate::garble::GarbledGate;
use crate::wire::Wire;
use itertools::Itertools;
use rand::Rng;
use std::collections::HashMap;
use crate::fancy::HasModulus;

////////////////////////////////////////////////////////////////////////////////
// garbler helper functions

pub fn encode_consts(consts: &[u16], const_wires: &[Wire], deltas: &HashMap<u16,Wire>) -> Vec<Wire> {
    debug_assert_eq!(consts.len(), const_wires.len(), "[encode_consts] not enough consts!");
    let mut xs = Vec::new();
    for i in 0..consts.len() {
        let x = consts[i];
        let X = &const_wires[i];
        let D = &deltas[&X.modulus()];
        xs.push(X.plus(&D.cmul(x)));
    }
    xs
}

