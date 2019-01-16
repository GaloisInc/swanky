use crate::fancy::{Fancy, HasModulus};
use crate::util::{RngExt, tweak, tweak2, output_tweak};
use crate::wire::Wire;
use itertools::Itertools;
use std::collections::HashMap;
use std::ops::DerefMut;
use std::sync::{Arc, RwLock, Mutex};

use super::Message;

/// Streams garbled circuit ciphertexts through a callback.
pub struct Garbler {
    send_function:  Arc<Mutex<FnMut(Message) + Send>>,
    constants:      Arc<RwLock<HashMap<(u16,u16),Wire>>>,
    deltas:         Arc<RwLock<HashMap<u16, Wire>>>,
    current_output: Arc<Mutex<usize>>,
    current_gate:   Arc<Mutex<usize>>,
}

impl Garbler {
    /// Create a new garbler.
    ///
    /// `send_func` is a callback that enables streaming. It gets called as the garbler
    /// generates ciphertext information such as garbled gates or input wirelabels.
    pub fn new<F>(send_func: F) -> Garbler
      where F: FnMut(Message) + Send + 'static
    {
        Garbler {
            send_function:  Arc::new(Mutex::new(send_func)),
            constants:      Arc::new(RwLock::new(HashMap::new())),
            deltas:         Arc::new(RwLock::new(HashMap::new())),
            current_gate:   Arc::new(Mutex::new(0)),
            current_output: Arc::new(Mutex::new(0)),
        }
    }

    /// Output some information from the garbling.
    fn send(&self, m: Message) {
        (self.send_function.lock().unwrap().deref_mut())(m);
    }

    /// Create a delta if it has not been created yet for this modulus, otherwise just
    /// return the existing one.
    fn delta(&self, q: u16) -> Wire {
        match self.deltas.read().unwrap().get(&q) {
            Some(delta) => return delta.clone(),
            None => (),
        }
        let mut deltas = self.deltas.write().unwrap();
        match deltas.get(&q) {
            Some(delta) => return delta.clone(),
            None => (),
        }
        let w = Wire::rand_delta(&mut rand::thread_rng(), q);
        deltas.insert(q,w.clone());
        w
    }

    /// The current non-free gate index of the garbling computation.
    fn current_gate(&self) -> usize {
        let mut c = self.current_gate.lock().unwrap();
        let old = *c;
        *c += 1;
        old
    }

    /// The current output index of the garbling computation.
    fn current_output(&self) -> usize {
        let mut c = self.current_output.lock().unwrap();
        let old = *c;
        *c += 1;
        old
    }

    /// Get the deltas, consuming the Garbler.
    pub fn get_deltas(self) -> HashMap<u16, Wire> {
        Arc::try_unwrap(self.deltas).unwrap().into_inner().unwrap()
    }
}

impl Fancy for Garbler {
    type Item = Wire;

    fn garbler_input(&self, q: u16) -> Wire {
        let w = Wire::rand(&mut rand::thread_rng(), q);
        let d = self.delta(q);
        self.send(Message::UnencodedGarblerInput {
            zero: w.clone(),
            delta: d,
        });
        w
    }

    fn evaluator_input(&self, q: u16) -> Wire {
        let w = Wire::rand(&mut rand::thread_rng(), q);
        let d = self.delta(q);
        self.send(Message::UnencodedEvaluatorInput {
            zero: w.clone(),
            delta: d,
        });
        w
    }

    fn constant(&self, x: u16, q: u16) -> Wire {
        match self.constants.read().unwrap().get(&(x,q)) {
            Some(c) => return c.clone(),
            None => (),
        }
        let mut constants = self.constants.write().unwrap();
        match constants.get(&(x,q)) {
            Some(c) => return c.clone(),
            None => (),
        }
        let zero = Wire::rand(&mut rand::thread_rng(), q);
        let wire = zero.plus(&self.delta(q).cmul(x));
        constants.insert((x,q), wire.clone());
        self.send(Message::Constant {
            value: x,
            wire: wire.clone()
        });
        zero
    }

    fn add(&self, x: &Wire, y: &Wire) -> Wire {
        x.plus(y)
    }

    fn sub(&self, x: &Wire, y: &Wire) -> Wire {
        x.minus(y)
    }

    fn cmul(&self, x: &Wire, c: u16)  -> Wire {
        x.cmul(c)
    }

    fn mul(&self, A: &Wire, B: &Wire) -> Wire {
        if A.modulus() < A.modulus() {
            return self.mul(B,A);
        }

        let q = A.modulus();
        let qb = B.modulus();
        let gate_num = self.current_gate();

        debug_assert!(q >= qb); // XXX: for now

        let D = self.delta(q);
        let Db = self.delta(qb);

        let r;
        let mut gate = vec![None; q as usize + qb as usize - 2];

        // hack for unequal moduli
        if q != qb {
            // would need to pack minitable into more than one u128 to support qb > 8
            debug_assert!(qb <= 8, "qb capped at 8 for now, for assymmetric moduli");

            r = rand::thread_rng().gen_u16() % q;
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
        self.send(Message::GarbledGate(gate));

        X.plus(&Y)
    }

    fn proj(&self, A: &Wire, q_out: u16, tt: &[u16]) -> Wire { //
        let q_in = A.modulus();
        // we have to fill in the vector in an unkonwn order because of the color bits.
        // Since some of the values in gate will be void temporarily, we use Vec<Option<..>>
        let mut gate = vec![None; q_in as usize - 1];

        let tao = A.color();        // input zero-wire
        let g = tweak(self.current_gate());    // gate tweak

        let Din  = self.delta(q_in);
        let Dout = self.delta(q_out);

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
        self.send(Message::GarbledGate(gate));

        C
    }

    fn output(&self, X: &Wire) {
        let mut cts = Vec::new();
        let q = X.modulus();
        let i = self.current_output();
        let D = self.delta(q);
        for k in 0..q {
            let t = output_tweak(i, k);
            cts.push(X.plus(&D.cmul(k)).hash(t));
        }
        self.send(Message::OutputCiphertext(cts));
    }

    fn begin_sync(&self, _begin_index: usize, _end_index: usize) { }

    fn finish_index(&self, _index: usize) { }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn garbler_has_send_and_sync() {
        fn check_send(_: impl Send) { }
        fn check_sync(_: impl Sync) { }
        check_send(Garbler::new(|_| ()));
        check_sync(Garbler::new(|_| ()));
    }
}
