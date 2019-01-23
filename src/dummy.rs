//! Dummy implementation of Fancy.
//!
//! Useful for evaluating the circuits produced by Fancy without actually creating any
//! circuits.

use crate::fancy::{Fancy, HasModulus};
use crossbeam::queue::MsQueue;
use itertools::Itertools;
use std::sync::mpsc::{channel, Sender, Receiver};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::{self, JoinHandle};

/// Simple struct that performs the fancy computation over u16.
pub struct Dummy {
    outputs:          Arc<Mutex<Vec<u16>>>,
    garbler_inputs:   Arc<Mutex<Vec<u16>>>,
    evaluator_inputs: Arc<Mutex<Vec<u16>>>,

    // sync stuff to allow parallel inputs
    begin_index:      Arc<RwLock<Option<usize>>>,
    requests:         Arc<RwLock<Option<Vec<MsQueue<(Request, Sender<DummyVal>)>>>>>,
    index_done:       Arc<Mutex<Option<Vec<bool>>>>,
    postman_handle:   Arc<Mutex<Option<JoinHandle<()>>>>,
    postman_notify:   Arc<Mutex<Option<Sender<()>>>>,
}

enum Request {
    GarblerInput(u16),
    EvaluatorInput(u16),
}

/// Wrapper around u16.
#[derive(Clone, Default, Debug)]
pub struct DummyVal {
    val: u16,
    modulus: u16,
}

impl HasModulus for DummyVal {
    fn modulus(&self) -> u16 { self.modulus }
}

impl Dummy {
    /// Create a new Dummy.
    pub fn new(garbler_inputs: &[u16], evaluator_inputs: &[u16]) -> Dummy {
        Dummy {
            garbler_inputs:   Arc::new(Mutex::new(garbler_inputs.to_vec())),
            evaluator_inputs: Arc::new(Mutex::new(evaluator_inputs.to_vec())),
            outputs:          Arc::new(Mutex::new(Vec::new())),

            begin_index:      Arc::new(RwLock::new(None)),
            requests:         Arc::new(RwLock::new(None)),
            index_done:       Arc::new(Mutex::new(None)),
            postman_handle:   Arc::new(Mutex::new(None)),
            postman_notify:   Arc::new(Mutex::new(None)),
        }
    }

    /// Get the output from the fancy computation, consuming the Dummy.
    pub fn get_output(self) -> Vec<u16> {
        Arc::try_unwrap(self.outputs).unwrap().into_inner().unwrap()
    }

    fn in_sync(&self) -> bool {
        self.begin_index.read().unwrap().is_some()
    }

    fn starting_index(&self) -> usize {
        self.begin_index.read().unwrap().unwrap()
    }

    fn request(&self, ix: usize, m: Request) -> DummyVal {
        let (tx,rx) = channel();
        self.requests.read().unwrap().as_ref().unwrap()[ix].push((m,tx));
        self.postman_notify.lock().unwrap().as_ref().unwrap().send(()).unwrap();
        rx.recv().unwrap()
    }
}

impl Fancy for Dummy {
    type Item = DummyVal;

    fn garbler_input(&self, ix: Option<usize>, modulus: u16) -> DummyVal {
        if self.in_sync() {
            let ix = ix.expect("dummy: sync mode requires index");
            self.request(ix, Request::GarblerInput(modulus))
        } else {
            let mut inps = self.garbler_inputs.lock().unwrap();
            assert!(inps.len() > 0, "not enough garbler inputs");
            let val = inps.remove(0);
            DummyVal { val, modulus }
        }
    }

    fn evaluator_input(&self, ix: Option<usize>, modulus: u16) -> DummyVal {
        if self.in_sync() {
            let ix = ix.expect("dummy: sync mode requires index");
            self.request(ix, Request::EvaluatorInput(modulus))
        } else {
            let mut inps = self.evaluator_inputs.lock().unwrap();
            assert!(inps.len() > 0, "not enough evaluator inputs");
            let val = inps.remove(0);
            DummyVal { val, modulus }
        }
    }

    fn constant(&self, _ix: Option<usize>, val: u16, modulus: u16) -> DummyVal {
        DummyVal { val, modulus }
    }

    fn add(&self, x: &DummyVal, y: &DummyVal) -> DummyVal {
        assert!(x.modulus == y.modulus);
        let val = (x.val + y.val) % x.modulus;
        DummyVal { val, modulus: x.modulus }
    }

    fn sub(&self, x: &DummyVal, y: &DummyVal) -> DummyVal {
        assert!(x.modulus == y.modulus);
        let val = (x.modulus + x.val - y.val) % x.modulus;
        DummyVal { val, modulus: x.modulus }
    }

    fn cmul(&self, x: &DummyVal, c: u16) -> DummyVal {
        let val = (x.val * c) % x.modulus;
        DummyVal { val, modulus: x.modulus }
    }

    fn mul(&self, ix: Option<usize>, x: &DummyVal, y: &DummyVal) -> DummyVal {
        if x.modulus < y.modulus {
            return self.mul(ix,y,x);
        }
        let val = (x.val * y.val) % x.modulus;
        DummyVal { val, modulus: x.modulus }
    }

    fn proj(&self, _ix: Option<usize>, x: &DummyVal, modulus: u16, tt: &[u16]) -> DummyVal {
        assert_eq!(tt.len(), x.modulus as usize);
        assert!(tt.iter().all(|&x| x < modulus));
        assert!(x.val < x.modulus);
        let val = tt[x.val as usize];
        DummyVal { val, modulus }
    }

    fn output(&self, _ix: Option<usize>, x: &DummyVal) {
        self.outputs.lock().unwrap().push(x.val);
    }

    fn begin_sync(&self, begin_index: usize, end_index: usize) {
        *self.begin_index.write().unwrap() = Some(begin_index);
        *self.requests.write().unwrap()  = Some((begin_index..end_index).map(|_| MsQueue::new()).collect_vec());
        *self.index_done.lock().unwrap() = Some(vec![false; end_index - begin_index]);

        let (tx, rx) = channel();
        let p_done = self.index_done.clone();
        let p_reqs = self.requests.clone();
        let p_gb   = self.garbler_inputs.clone();
        let p_ev   = self.evaluator_inputs.clone();
        let h = thread::spawn(move || {
            postman(begin_index, end_index, p_done, p_reqs, p_gb, p_ev, rx);
        });

        *self.postman_handle.lock().unwrap() = Some(h);
        *self.postman_notify.lock().unwrap() = Some(tx);
    }

    fn finish_index(&self, index: usize) {
        if self.in_sync() {
            let mut cleanup = false;
            {
                let mut done = self.index_done.lock().unwrap();
                let done = done.as_mut().unwrap();
                done[index - self.starting_index()] = true;
                self.postman_notify.lock().unwrap().as_ref().unwrap().send(()).unwrap();
                if done.iter().all(|&x|x) {
                    cleanup = true;
                }
            }
            // if we are completely done, clean up
            if cleanup {
                *self.begin_index.write().unwrap() = None;
                *self.index_done.lock().unwrap()   = None;
                *self.requests.write().unwrap()    = None;
                self.postman_handle.lock().unwrap().take().unwrap().join().unwrap();
                *self.postman_notify.lock().unwrap() = None;
            }
        }
    }
}

fn postman(
    begin_index: usize,
    end_index: usize,
    done: Arc<Mutex<Option<Vec<bool>>>>,
    reqs: Arc<RwLock<Option<Vec<MsQueue<(Request, Sender<DummyVal>)>>>>>,
    gb_inps: Arc<Mutex<Vec<u16>>>,
    ev_inps: Arc<Mutex<Vec<u16>>>,
    notify: Receiver<()>,
){
    let mut c = begin_index;
    while c < end_index {
        if let Some((r,tx)) = reqs.read().unwrap().as_ref().unwrap()[c].try_pop() {
            match r {
                Request::GarblerInput(modulus) => {
                    let mut inps = gb_inps.lock().unwrap();
                    assert!(inps.len() > 0, "not enough garbler inputs");
                    let val = inps.remove(0);
                    tx.send(DummyVal { val, modulus }).unwrap();
                }
                Request::EvaluatorInput(modulus) => {
                    let mut inps = ev_inps.lock().unwrap();
                    assert!(inps.len() > 0, "not enough evaluator inputs");
                    let val = inps.remove(0);
                    tx.send(DummyVal { val, modulus }).unwrap();
                }
            }
        } else {
            // wait to be notified
            notify.recv().unwrap();
        }
        let done_mutex = done.lock().unwrap();
        if let Some(ref done) = *done_mutex {
            if done[c] {
                c += 1;
            }
        } else {
            break;
        }
    }
}

#[cfg(test)]
mod bundle {
    use super::*;
    use crate::fancy::BundleGadgets;
    use crate::util::{self, RngExt, crt_factor, crt_inv_factor};
    use itertools::Itertools;
    use rand::thread_rng;

    #[test] // bundle addition {{{
    fn addition() {
        let mut rng = thread_rng();
        for _ in 0..16 {
            let q = rng.gen_usable_composite_modulus();
            let x = rng.gen_u128() % q;
            let y = rng.gen_u128() % q;
            let d = Dummy::new(&crt_factor(x,q), &crt_factor(y,q));
            {
                let x = d.garbler_input_bundle_crt(None,q);
                let y = d.evaluator_input_bundle_crt(None,q);
                let z = d.add_bundles(&x,&y);
                d.output_bundle(None,&z);
            }
            let z = crt_inv_factor(&d.get_output(),q);
            assert_eq!(z, (x+y)%q);
        }
    }
    //}}}
    #[test] // bundle subtraction {{{
    fn subtraction() {
        let mut rng = thread_rng();
        for _ in 0..16 {
            let q = rng.gen_usable_composite_modulus();
            let x = rng.gen_u128() % q;
            let y = rng.gen_u128() % q;
            let d = Dummy::new(&crt_factor(x,q), &crt_factor(y,q));
            {
                let x = d.garbler_input_bundle_crt(None,q);
                let y = d.evaluator_input_bundle_crt(None,q);
                let z = d.sub_bundles(&x,&y);
                d.output_bundle(None,&z);
            }
            let z = crt_inv_factor(&d.get_output(),q);
            assert_eq!(z, (x+q-y)%q);
        }
    }
    //}}}
    #[test] // binary cmul {{{
    fn binary_cmul() {
        let mut rng = thread_rng();
        for _ in 0..16 {
            let nbits = 64;
            let q = 1<<nbits;
            let x = rng.gen_u128() % q;
            let c = 1 + rng.gen_u128() % q;
            let d = Dummy::new(&util::u128_to_bits(x,nbits), &[]);
            {
                let x = d.garbler_input_bundle(None,&vec![2;nbits]);
                let z = d.binary_cmul(None,&x,c,nbits);
                d.output_bundle(None,&z);
            }
            let z = util::u128_from_bits(&d.get_output());
            assert_eq!(z, (x*c)%q);
        }
    }
    //}}}
    #[test] // bundle max {{{
    fn max() {
        let mut rng = thread_rng();
        let q = util::modulus_with_width(10);
        let n = 10;
        for _ in 0..16 {
            let inps = (0..n).map(|_| rng.gen_u128() % (q/2)).collect_vec();
            let should_be = *inps.iter().max().unwrap();
            let enc_inps = inps.into_iter().flat_map(|x| crt_factor(x,q)).collect_vec();
            let d = Dummy::new(&enc_inps, &[]);
            {
                let xs = d.garbler_input_bundles_crt(None,q,n);
                let z = d.max(None,&xs);
                d.output_bundle(None,&z);
            }
            let z = crt_inv_factor(&d.get_output(),q);
            assert_eq!(z, should_be);
        }
    }
    //}}}
    #[test] // binary max {{{
    fn binary_max() {
        let mut rng = thread_rng();
        let n = 10;
        let nbits = 16;
        let q = 1<<nbits;
        for _ in 0..16 {
            let inps = (0..n).map(|_| rng.gen_u128() % q).collect_vec();
            let should_be = *inps.iter().max().unwrap();
            let enc_inps = inps.into_iter().flat_map(|x| util::u128_to_bits(x,nbits)).collect_vec();
            let d = Dummy::new(&enc_inps, &[]);
            {
                let xs = d.garbler_input_bundles(None,&vec![2;nbits], n);
                let z = d.max(None,&xs);
                d.output_bundle(None,&z);
            }
            let z = util::u128_from_bits(&d.get_output());
            assert_eq!(z, should_be);
        }
    }
    //}}}
    #[test] // abs {{{
    fn binary_abs() {
        let mut rng = thread_rng();
        for _ in 0..16 {
            let nbits = 64;
            let q = 1<<nbits;
            let x = rng.gen_u128() % q;
            let d = Dummy::new(&util::u128_to_bits(x,nbits), &[]);
            {
                let x = d.garbler_input_bundle_binary(None,nbits);
                let z = d.abs(None,&x);
                d.output_bundle(None,&z);
            }
            let z = util::u128_from_bits(&d.get_output());
            let should_be = if x >> (nbits-1) > 0 {
                ((!x) + 1) & ((1<<nbits) - 1)
            } else {
                x
            };
            assert_eq!(z, should_be);
        }
    }
    //}}}
    #[test] // dummy has send and sync {{{
    fn dummy_has_send_and_sync() {
        fn check_send(_: impl Send) { }
        fn check_sync(_: impl Sync) { }
        check_send(Dummy::new(&[], &[]));
        check_sync(Dummy::new(&[], &[]));
    } // }}}
}
