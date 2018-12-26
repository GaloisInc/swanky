//! The functions that do the actual garbling, used by the `Garbler` iterator.

use crate::garble::GarbledGate;
use crate::wire::Wire;
use itertools::Itertools;
use rand::Rng;
use std::collections::HashMap;
use crate::fancy::HasModulus;

////////////////////////////////////////////////////////////////////////////////
// garbler helper functions

pub fn garble_half_gate<R: Rng>(A: &Wire, B: &Wire, gate_num: usize, deltas: &HashMap<u16,Wire>, rng: &mut R)
    -> (Wire, Option<GarbledGate>)
{
    let q = A.modulus();
    let qb = B.modulus();

    debug_assert!(q >= qb);

    let D = deltas[&q].clone();
    let Db = deltas[&qb].clone();

    let r;
    let mut gate = vec![None; q as usize + qb as usize - 2];

    // hack for unequal moduli
    if q != qb {
        // would need to pack minitable into more than one u128 to support qb > 8
        debug_assert!(qb <= 8, "qb capped at 8 for now!");

        r = rng.gen::<u16>() % q;
        let t = tweak2(gate_num as u64, 1);

        let mut minitable = vec![None; qb as usize];
        let mut B_ = B.clone();
        for b in 0..qb {
            if b > 0 {
                B_.plus_eq(&Db);
            }
            let new_color = (r+b) % q;
            let ct = (B_.hash(t) & 0xFFFF) ^ new_color as u128;
            minitable[B_.color() as usize] = Some(ct);
        }

        let mut packed = 0;
        for i in 0..qb as usize {
            packed += minitable[i].unwrap() << (16 * i);
        }
        gate.push(Some(packed));

    } else {
        r = B.color(); // secret value known only to the garbler (ev knows r+b)
    }

    let g = tweak2(gate_num as u64, 0);

    // X = H(A+aD) + arD such that a + A.color == 0
    let alpha = (q - A.color()) % q; // alpha = -A.color
    let X = A.plus(&D.cmul(alpha))
             .hashback(g,q)
             .plus(&D.cmul((alpha * r) % q));

    // Y = H(B + bD) + (b + r)A such that b + B.color == 0
    let beta = (qb - B.color()) % qb;
    let Y = B.plus(&Db.cmul(beta))
             .hashback(g,q)
             .plus(&A.cmul((beta + r) % q));

    // precompute a lookup table of X.minus(&D_cmul[(a * r % q) as usize]).as_u128();
    //                            = X.plus(&D_cmul[((q - (a * r % q)) % q) as usize]).as_u128();
    let X_cmul = {
        let mut X_ = X.clone();
        (0..q).map(|x| {
            if x > 0 {
                X_.plus_eq(&D);
            }
            X_.as_u128()
        }).collect_vec()
    };

    let mut A_ = A.clone();
    for a in 0..q {
        if a > 0 {
            A_.plus_eq(&D);
        }
        // garbler's half-gate: outputs X-arD
        // G = H(A+aD) ^ X+a(-r)D = H(A+aD) ^ X-arD
        if A_.color() != 0 {
            // let G = A_.hash(g) ^ X.minus(&D_cmul[(a * r % q) as usize]).as_u128();
            let G = A_.hash(g) ^ X_cmul[((q - (a * r % q)) % q) as usize];
            gate[A_.color() as usize - 1] = Some(G);
        }
    }

    // precompute a lookup table of Y.minus(&A_cmul[((b+r) % q) as usize]).as_u128();
    //                            = Y.plus(&A_cmul[((q - ((b+r) % q)) % q) as usize]).as_u128();
    let Y_cmul = {
        let mut Y_ = Y.clone();
        (0..q).map(|x| {
            if x > 0 {
                Y_.plus_eq(&A);
            }
            Y_.as_u128()
        }).collect_vec()
    };

    let mut B_ = B.clone();
    for b in 0..qb {
        if b > 0 {
            B_.plus_eq(&Db)
        }
        // evaluator's half-gate: outputs Y-(b+r)D
        // G = H(B+bD) + Y-(b+r)A
        if B_.color() != 0 {
            // let G = B_.hash(g) ^ Y.minus(&A_cmul[((b+r) % q) as usize]).as_u128();
            let G = B_.hash(g) ^ Y_cmul[((q - ((b+r) % q)) % q) as usize];
            gate[q as usize - 1 + B_.color() as usize - 1] = Some(G);
        }
    }

    let gate = gate.into_iter().map(Option::unwrap).collect();
    (X.plus(&Y), Some(gate)) // output zero wire
}

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

pub fn tweak2(i: u64, j: u64) -> u128 {
    ((i as u128) << 64) + j as u128
}

