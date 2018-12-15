//! The functions that do the actual garbling, used by the `Garbler` iterator.

use crate::garble::GarbledGate;
use crate::wire::Wire;
use itertools::Itertools;
use rand::Rng;
use std::collections::HashMap;

////////////////////////////////////////////////////////////////////////////////
// garbler helper functions

pub fn garble_output(X: &Wire, output_num: usize, deltas: &HashMap<u16,Wire>)
    -> Vec<u128>
{
    let mut cts = Vec::new();
    let q = X.modulus();
    let D = &deltas[&q];
    for k in 0..q {
        let t = output_tweak(output_num, k);
        cts.push(X.plus(&D.cmul(k)).hash(t));
    }
    cts
}

pub fn garble_projection(A: &Wire, q_out: u16, tt: &[u16], gate_num: usize, deltas: &HashMap<u16,Wire>)
    -> (Wire, Option<GarbledGate>)
{
    let q_in = A.modulus();
    // we have to fill in the vector in an unkonwn order because of the
    // color bits. Since some of the values in gate will be void
    // temporarily, we use Vec<Option<..>>
    let mut gate = vec![None; q_in as usize - 1];

    let tao = A.color();        // input zero-wire
    let g = tweak(gate_num);    // gate tweak

    let Din  = &deltas[&q_in];
    let Dout = &deltas[&q_out];

    // output zero-wire
    // W_g^0 <- -H(g, W_{a_1}^0 - \tao\Delta_m) - \phi(-\tao)\Delta_n
    // let C = A.minus(&Din.cmul(tao))
    //             .hashback(g, q_out)
    //             .minus(&Dout.cmul(tt[((q_in - tao) % q_in) as usize]));
    let mut C = A.clone();
    C.plus_eq(&Din.cmul((q_in-tao) % q_in));
    C = C.hashback(g, q_out);
    C.plus_eq(&Dout.cmul((q_out - tt[((q_in - tao) % q_in) as usize]) % q_out));

    // precompute `let C_ = C.plus(&Dout.cmul(tt[x as usize]))`
    let C_precomputed = {
        let mut C_ = C.clone();
        (0..q_out).map(|x| {
            if x > 0 {
                C_.plus_eq(&Dout);
            }
            C_.as_u128()
        }).collect_vec()
    };

    let mut A_ = A.clone();
    for x in 0..q_in {
        if x > 0 {
            A_.plus_eq(&Din); // avoiding expensive cmul for `A_ = A.plus(&Din.cmul(x))`
        }

        let ix = (tao as usize + x as usize) % q_in as usize;
        if ix == 0 { continue }

        let ct = A_.hash(g) ^ C_precomputed[tt[x as usize] as usize];
        gate[ix - 1] = Some(ct);
    }

    // unwrap the Option elems inside the Vec
    let gate = gate.into_iter().map(Option::unwrap).collect();
    (C, Some(gate))
}

pub fn garble_yao(A: &Wire, B: &Wire, q: u16, tt: &[Vec<u16>], gate_num: usize, deltas: &HashMap<u16,Wire>)
    -> (Wire, Option<GarbledGate>)
{
    let xmod = A.modulus() as usize;
    let ymod = B.modulus() as usize;
    let mut gate = vec![None; xmod * ymod - 1];

    // gate tweak
    let g = tweak(gate_num);

    // sigma is the output truth value of the 0,0-colored wirelabels
    let sigma = tt[((xmod - A.color() as usize) % xmod) as usize]
                  [((ymod - B.color() as usize) % ymod) as usize];

    // we use the row reduction trick here
    let B_delta = &deltas[&(ymod as u16)];
    let C = A.minus(&deltas[&(xmod as u16)].cmul(A.color()))
                .hashback2(&B.minus(&B_delta.cmul(B.color())), g, q)
                .minus(&deltas[&q].cmul(sigma));

    for x in 0..xmod {
        let A_ = A.plus(&deltas[&(xmod as u16)].cmul(x as u16));
        for y in 0..ymod {
            let ix = ((A.color() as usize + x) % xmod) * ymod +
                     ((B.color() as usize + y) % ymod);
            if ix == 0 { continue }
            debug_assert_eq!(gate[ix-1], None);
            let B_ = B.plus(&deltas[&(ymod as u16)].cmul(y as u16));
            let C_ = C.plus(&deltas[&q].cmul(tt[x][y]));
            let ct = A_.hash2(&B_,g) ^ C_.as_u128();
            gate[ix-1] = Some(ct);
        }
    }
    let gate = gate.into_iter().map(Option::unwrap).collect();
    (C, Some(gate))
}

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

pub fn tweak(i: usize) -> u128 {
    i as u128
}

pub fn tweak2(i: u64, j: u64) -> u128 {
    ((i as u128) << 64) + j as u128
}

pub fn output_tweak(i: usize, k: u16) -> u128 {
    let (left, _) = (i as u128).overflowing_shl(64);
    left + k as u128
}

