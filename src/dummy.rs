//! Dummy implementation of Fancy.
//!
//! Useful for evaluating the circuits produced by Fancy without actually creating any
//! circuits.

use crate::fancy::{Fancy, HasModulus};
use std::sync::{Arc, Mutex, RwLock};
use std::sync::mpsc::{channel, Sender};
use crossbeam::queue::MsQueue;

/// Simple struct that performs the fancy computation over u16.
pub struct Dummy {
    outputs:          Arc<Mutex<Vec<u16>>>,
    garbler_inputs:   Arc<Mutex<Vec<u16>>>,
    evaluator_inputs: Arc<Mutex<Vec<u16>>>,
    sync_info:        Arc<RwLock<Option<SyncInfo>>>,
    current_index:    Arc<RwLock<usize>>,
    waiting_threads:  Arc<MsQueue<Sender<()>>>,
    index_done:       Arc<Mutex<Vec<bool>>>,
}

struct SyncInfo {
    begin_index: usize,
    end_index: usize,
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
            sync_info:        Arc::new(RwLock::new(None)),
            current_index:    Arc::new(RwLock::new(0)),
            waiting_threads:  Arc::new(MsQueue::new()),
            index_done:       Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Get the output from the fancy computation, consuming the Dummy.
    pub fn get_output(self) -> Vec<u16> {
        Arc::try_unwrap(self.outputs).unwrap().into_inner().unwrap()
    }

    fn in_sync(&self) -> bool {
        self.sync_info.read().unwrap().is_some()
    }

    fn internal_garbler_input(&self, modulus: u16) -> DummyVal {
        let mut inps = self.garbler_inputs.lock().unwrap();
        assert!(inps.len() > 0, "not enough garbler inputs");
        let val = inps.remove(0);
        DummyVal { val, modulus }
    }

    fn internal_evaluator_input(&self, modulus: u16) -> DummyVal {
        let mut inps = self.evaluator_inputs.lock().unwrap();
        assert!(inps.len() > 0, "not enough evaluator inputs");
        let val = inps.remove(0);
        DummyVal { val, modulus }
    }
}

impl Fancy for Dummy {
    type Item = DummyVal;

    fn garbler_input(&self, ix: Option<usize>, modulus: u16) -> DummyVal {
        if self.in_sync() {
            let (tx,rx) = channel();
            {
                let c = self.current_index.read().unwrap();
                let ix = ix.expect("dummy: sync mode requires index");
                if ix == *c {
                    return self.internal_garbler_input(modulus);
                } else {
                    self.waiting_threads.push(tx);
                }
            }
            // otherwise wait and try again
            rx.recv().unwrap();
            self.garbler_input(ix, modulus)
        } else {
            self.internal_garbler_input(modulus)
        }
    }

    fn evaluator_input(&self, ix: Option<usize>, modulus: u16) -> DummyVal {
        if self.in_sync() {
            let (tx,rx) = channel();
            {
                let c = self.current_index.read().unwrap();
                let ix = ix.expect("dummy: sync mode requires index");
                if ix == *c {
                    return self.internal_evaluator_input(modulus);
                } else {
                    self.waiting_threads.push(tx);
                }
            }
            // otherwise wait and try again
            rx.recv().unwrap();
            self.evaluator_input(ix, modulus)
        } else {
            self.internal_evaluator_input(modulus)
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
        *self.sync_info.write().unwrap() = Some(SyncInfo {
            begin_index,
            end_index,
        });
        *self.current_index.write().unwrap() = begin_index;
        *self.index_done.lock().unwrap()     = vec![false; end_index - begin_index];
    }

    fn finish_index(&self, index: usize) {
        if self.in_sync() {
            let mut cleanup = false;
            {
                let opt_info = self.sync_info.read().unwrap();
                let info = opt_info.as_ref().unwrap();
                let mut done = self.index_done.lock().unwrap();
                done[index - info.begin_index] = true;
                loop {
                    *self.current_index.write().unwrap() += 1;
                    let c = *self.current_index.read().unwrap();

                    if c >= info.end_index {
                        cleanup = true;
                        break;
                    }

                    // release current index lock
                    while let Some(tx) = self.waiting_threads.try_pop() {
                        tx.send(()).unwrap();
                    }

                    if !done[c - info.begin_index] {
                        break;
                    }
                }
            }

            // if we are completely done, clean up
            if cleanup {
                *self.sync_info.write().unwrap() = None;
            }

        } else {
            panic!("dummy: finish index called outside of sync!");
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
