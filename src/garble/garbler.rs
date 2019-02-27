use itertools::Itertools;

use std::collections::HashMap;
use std::ops::DerefMut;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use crate::fancy::{Fancy, HasModulus, SyncIndex};
use crate::util::{output_tweak, tweak, tweak2, RngExt};
use crate::wire::Wire;
use crate::error::{FancyError, GarblerError};

use super::{Message, SyncInfo};

/// Streams garbled circuit ciphertexts through a callback. Parallelizable.
pub struct Garbler {
    send_function: Arc<Mutex<FnMut(Option<SyncIndex>, Message) + Send>>,
    deltas: Arc<Mutex<HashMap<u16, Wire>>>,
    current_output: Arc<AtomicUsize>,
    current_gate: Arc<AtomicUsize>,
    sync_info: Arc<RwLock<Option<SyncInfo>>>,
}

impl Garbler {
    /// Create a new garbler.
    ///
    /// `send_func` is a callback that enables streaming. It gets called as the garbler
    /// generates ciphertext information such as garbled gates or input wirelabels.
    pub fn new<F>(send_func: F) -> Garbler
    where
        F: FnMut(Option<SyncIndex>, Message) + Send + 'static,
    {
        Garbler {
            send_function: Arc::new(Mutex::new(send_func)),
            deltas: Arc::new(Mutex::new(HashMap::new())),
            current_gate: Arc::new(AtomicUsize::new(0)),
            current_output: Arc::new(AtomicUsize::new(0)),
            sync_info: Arc::new(RwLock::new(None)),
        }
    }

    /// Output some information from the garbling.
    fn send(&self, ix: Option<SyncIndex>, m: Message) {
        (self.send_function.lock().unwrap().deref_mut())(ix, m);
    }

    fn internal_begin_sync(&self, num_indices: SyncIndex) {
        let mut opt_info = self.sync_info.write().unwrap();
        assert!(
            opt_info.is_none(),
            "garbler: begin_sync called before finishing previous sync!"
        );
        *opt_info = Some(SyncInfo::new(
            self.current_gate.load(Ordering::SeqCst),
            num_indices,
        ));
    }

    fn internal_finish_index(&self, index: SyncIndex) {
        let mut done = false;
        if let Some(ref info) = *self.sync_info.read().unwrap() {
            info.index_done[index as usize].store(true, Ordering::SeqCst);
            if info.index_done.iter().all(|x| x.load(Ordering::SeqCst)) {
                done = true;
            }
        } else {
            panic!("garbler: finish_index called out of sync mode");
        }
        if done {
            *self.sync_info.write().unwrap() = None;
            self.send(None, Message::EndSync);
            self.current_gate.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// The current non-free gate index of the garbling computation. Respects sync
    /// ordering. Must agree with Evaluator hence compute_gate_id is in the parent mod.
    fn current_gate(&self, sync_index: Option<SyncIndex>) -> usize {
        super::compute_gate_id(
            &self.current_gate,
            sync_index,
            &*self.sync_info.read().unwrap(),
        )
    }

    /// Create a delta if it has not been created yet for this modulus, otherwise just
    /// return the existing one.
    pub fn delta(&self, q: u16) -> Wire {
        let mut deltas = self.deltas.lock().unwrap();
        if let Some(delta) = deltas.get(&q) {
            return delta.clone();
        }
        let w = Wire::rand_delta(&mut rand::thread_rng(), q);
        deltas.insert(q, w.clone());
        w
    }

    /// The current output index of the garbling computation.
    fn current_output(&self) -> usize {
        self.current_output.fetch_add(1, Ordering::SeqCst)
    }

    /// Get the deltas, consuming the Garbler.
    pub(super) fn get_deltas(self) -> HashMap<u16, Wire> {
        Arc::try_unwrap(self.deltas).unwrap().into_inner().unwrap()
    }
}

impl Fancy for Garbler {
    type Item = Wire;
    type Error = GarblerError;

    fn garbler_input(&self, ix: Option<SyncIndex>, q: u16, opt_x: Option<u16>) -> Result<Wire, FancyError<GarblerError>> {
        let w = Wire::rand(&mut rand::thread_rng(), q);
        let d = self.delta(q);
        if let Some(x) = opt_x {
            let encoded_wire = w.plus(&d.cmul(x));
            self.send(ix, Message::GarblerInput(encoded_wire));
        } else {
            self.send(
                ix,
                Message::UnencodedGarblerInput {
                    zero: w.clone(),
                    delta: d,
                },
            );
        }
        w
    }

    fn evaluator_input(&self, ix: Option<SyncIndex>, q: u16) -> Result<Wire, FancyError<GarblerError>> {
        let w = Wire::rand(&mut rand::thread_rng(), q);
        let d = self.delta(q);
        self.send(
            ix,
            Message::UnencodedEvaluatorInput {
                zero: w.clone(),
                delta: d,
            },
        );
        w
    }

    fn constant(&self, ix: Option<SyncIndex>, x: u16, q: u16) -> Result<Wire, FancyError<GarblerError>> {
        let zero = Wire::rand(&mut rand::thread_rng(), q);
        let wire = zero.plus(&self.delta(q).cmul_eq(x));
        self.send(
            ix,
            Message::Constant {
                value: x,
                wire: wire,
            },
        );
        zero
    }

    fn add(&self, x: &Wire, y: &Wire) -> Result<Wire, FancyError<GarblerError>> {
        x.plus(y)
    }

    fn sub(&self, x: &Wire, y: &Wire) -> Result<Wire, FancyError<GarblerError>> {
        x.minus(y)
    }

    fn cmul(&self, x: &Wire, c: u16) -> Result<Wire, FancyError<GarblerError>> {
        x.cmul(c)
    }

    fn mul(&self, ix: Option<SyncIndex>, A: &Wire, B: &Wire) -> Result<Wire, FancyError<GarblerError>> {
        if A.modulus() < A.modulus() {
            return self.mul(ix, B, A);
        }

        let q = A.modulus();
        let qb = B.modulus();
        let gate_num = self.current_gate(ix);

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
                let new_color = (r + b) % q;
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
        let X = A
            .plus(&D.cmul(alpha))
            .hashback(g, q)
            .plus_mov(&D.cmul((alpha * r) % q));

        // Y = H(B + bD) + (b + r)A such that b + B.color == 0
        let beta = (qb - B.color()) % qb;
        let Y = B
            .plus(&Db.cmul(beta))
            .hashback(g, q)
            .plus_mov(&A.cmul((beta + r) % q));

        // precompute a lookup table of X.minus(&D_cmul[(a * r % q) as usize]).as_u128();
        //                            = X.plus(&D_cmul[((q - (a * r % q)) % q) as usize]).as_u128();
        let X_cmul = {
            let mut X_ = X.clone();
            (0..q)
                .map(|x| {
                    if x > 0 {
                        X_.plus_eq(&D);
                    }
                    X_.as_u128()
                })
                .collect_vec()
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
            (0..q)
                .map(|x| {
                    if x > 0 {
                        Y_.plus_eq(&A);
                    }
                    Y_.as_u128()
                })
                .collect_vec()
        };

        let mut B_ = B.clone();
        for b in 0..qb {
            if b > 0 {
                B_.plus_eq(&Db);
            }
            // evaluator's half-gate: outputs Y-(b+r)D
            // G = H(B+bD) + Y-(b+r)A
            if B_.color() != 0 {
                // let G = B_.hash(g) ^ Y.minus(&A_cmul[((b+r) % q) as usize]).as_u128();
                let G = B_.hash(g) ^ Y_cmul[((q - ((b + r) % q)) % q) as usize];
                gate[q as usize - 1 + B_.color() as usize - 1] = Some(G);
            }
        }

        let gate = gate.into_iter().map(Option::unwrap).collect();
        self.send(ix, Message::GarbledGate(gate));

        X.plus_mov(&Y)
    }

    fn proj(
        &self,
        ix: Option<SyncIndex>,
        A: &Wire,
        q_out: u16,
        tt: Option<Vec<u16>>,
    ) -> Result<Wire, FancyError<GarblerError>> {
        //
        let tt = tt.expect("garbler.proj requires truth table");

        let q_in = A.modulus();
        // we have to fill in the vector in an unkonwn order because of the color bits.
        // Since some of the values in gate will be void temporarily, we use Vec<Option<..>>
        let mut gate = vec![None; q_in as usize - 1];

        let tao = A.color();
        let g = tweak(self.current_gate(ix)); // gate tweak

        let Din = self.delta(q_in);
        let Dout = self.delta(q_out);

        // output zero-wire
        // W_g^0 <- -H(g, W_{a_1}^0 - \tao\Delta_m) - \phi(-\tao)\Delta_n
        // let C = A.minus(&Din.cmul(tao))
        //             .hashback(g, q_out)
        //             .minus(&Dout.cmul(tt[((q_in - tao) % q_in) as usize]));
        let C = A
            .plus(&Din.cmul((q_in - tao) % q_in))
            .hashback(g, q_out)
            .plus_mov(&Dout.cmul((q_out - tt[((q_in - tao) % q_in) as usize]) % q_out));

        // precompute `let C_ = C.plus(&Dout.cmul(tt[x as usize]))`
        let C_precomputed = {
            let mut C_ = C.clone();
            (0..q_out)
                .map(|x| {
                    if x > 0 {
                        C_.plus_eq(&Dout);
                    }
                    C_.as_u128()
                })
                .collect_vec()
        };

        let mut A_ = A.clone();
        for x in 0..q_in {
            if x > 0 {
                A_.plus_eq(&Din); // avoiding expensive cmul for `A_ = A.plus(&Din.cmul(x))`
            }

            let ix = (tao as usize + x as usize) % q_in as usize;
            if ix == 0 {
                continue;
            }

            let ct = A_.hash(g) ^ C_precomputed[tt[x as usize] as usize];
            gate[ix - 1] = Some(ct);
        }

        // unwrap the Option elems inside the Vec
        let gate = gate.into_iter().map(Option::unwrap).collect();
        self.send(ix, Message::GarbledGate(gate));

        C
    }

    fn output(&self, ix: Option<SyncIndex>, X: &Wire) -> Result<(), FancyError<GarblerError>> {
        let mut cts = Vec::new();
        let q = X.modulus();
        let i = self.current_output();
        let D = self.delta(q);
        for k in 0..q {
            let t = output_tweak(i, k);
            cts.push(X.plus(&D.cmul(k)).hash(t));
        }
        self.send(ix, Message::OutputCiphertext(cts));
    }

    fn begin_sync(&self, num_indices: SyncIndex) -> Result<(), FancyError<GarblerError>> {
        self.internal_begin_sync(num_indices);
    }

    fn finish_index(&self, index: SyncIndex) -> Result<(), FancyError<GarblerError>> {
        self.internal_finish_index(index);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn garbler_has_send_and_sync() {
        fn check_send(_: impl Send) {}
        fn check_sync(_: impl Sync) {}
        check_send(Garbler::new(|_, _| ()));
        check_sync(Garbler::new(|_, _| ()));
    }
}
