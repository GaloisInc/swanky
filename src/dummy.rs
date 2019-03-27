//! Dummy implementation of Fancy.
//!
//! Useful for evaluating the circuits produced by Fancy without actually creating any
//! circuits.

use crossbeam::queue::SegQueue;
use itertools::Itertools;

use std::sync::mpsc::{channel, Sender};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex, RwLock,
};

use crate::error::{DummyError, FancyError, SyncError};
use crate::fancy::{Fancy, HasModulus, SyncIndex};

/// Simple struct that performs the fancy computation over u16.
pub struct Dummy {
    outputs: Arc<Mutex<Vec<u16>>>,
    garbler_inputs: Arc<Mutex<Vec<u16>>>,
    evaluator_inputs: Arc<Mutex<Vec<u16>>>,

    // sync stuff to allow parallel inputs
    requests: Arc<RwLock<Option<Vec<SegQueue<(Request, Sender<DummyVal>)>>>>>,
    index_done: Arc<RwLock<Option<Vec<AtomicBool>>>>,
}

enum Request {
    GarblerInput(u16),
    EvaluatorInput(u16),
}

/// Wrapper around u16.
#[derive(Clone, Debug)]
pub struct DummyVal {
    val: u16,
    modulus: u16,
}

impl HasModulus for DummyVal {
    fn modulus(&self) -> u16 {
        self.modulus
    }
}

impl Dummy {
    /// Create a new Dummy.
    pub fn new(garbler_inputs: &[u16], evaluator_inputs: &[u16]) -> Dummy {
        Dummy {
            garbler_inputs: Arc::new(Mutex::new(garbler_inputs.to_vec())),
            evaluator_inputs: Arc::new(Mutex::new(evaluator_inputs.to_vec())),
            outputs: Arc::new(Mutex::new(Vec::new())),

            requests: Arc::new(RwLock::new(None)),
            index_done: Arc::new(RwLock::new(None)),
        }
    }

    /// Get the output from the fancy computation, consuming the Dummy.
    pub fn get_output(self) -> Vec<u16> {
        Arc::try_unwrap(self.outputs).unwrap().into_inner().unwrap()
    }

    fn in_sync(&self) -> bool {
        self.requests.read().unwrap().is_some()
    }

    fn request(&self, ix: SyncIndex, m: Request) -> DummyVal {
        let (tx, rx) = channel();
        self.requests.read().unwrap().as_ref().unwrap()[ix as usize].push((m, tx));
        rx.recv().unwrap()
    }
}

impl Fancy for Dummy {
    type Item = DummyVal;
    type Error = DummyError;

    fn garbler_input(
        &self,
        ix: Option<SyncIndex>,
        modulus: u16,
        opt_x: Option<u16>,
    ) -> Result<DummyVal, Self::Error> {
        let res = if let Some(val) = opt_x {
            DummyVal { val, modulus }
        } else if self.in_sync() {
            let ix = ix.ok_or_else(|| DummyError::from(SyncError::IndexRequired))?;
            self.request(ix, Request::GarblerInput(modulus))
        } else {
            let mut inps = self.garbler_inputs.lock().unwrap();
            if inps.len() == 0 {
                return Err(DummyError::NotEnoughGarblerInputs)?;
            }
            let val = inps.remove(0);
            DummyVal { val, modulus }
        };
        Ok(res)
    }

    fn evaluator_input(
        &self,
        ix: Option<SyncIndex>,
        modulus: u16,
    ) -> Result<DummyVal, Self::Error> {
        let res = if self.in_sync() {
            let ix = ix.ok_or_else(|| DummyError::from(SyncError::IndexRequired))?;
            self.request(ix, Request::EvaluatorInput(modulus))
        } else {
            let mut inps = self.evaluator_inputs.lock().unwrap();
            if inps.len() == 0 {
                return Err(DummyError::NotEnoughEvaluatorInputs)?;
            }
            let val = inps.remove(0);
            DummyVal { val, modulus }
        };
        Ok(res)
    }

    fn constant(
        &self,
        _ix: Option<SyncIndex>,
        val: u16,
        modulus: u16,
    ) -> Result<DummyVal, Self::Error> {
        Ok(DummyVal { val, modulus })
    }

    fn add(&self, x: &DummyVal, y: &DummyVal) -> Result<DummyVal, Self::Error> {
        if x.modulus() != y.modulus() {
            return Err(Self::Error::from(FancyError::UnequalModuli));
        }
        Ok(DummyVal {
            val: (x.val + y.val) % x.modulus,
            modulus: x.modulus,
        })
    }

    fn sub(&self, x: &DummyVal, y: &DummyVal) -> Result<DummyVal, Self::Error> {
        if x.modulus() != y.modulus() {
            return Err(Self::Error::from(FancyError::UnequalModuli));
        }
        Ok(DummyVal {
            val: (x.modulus + x.val - y.val) % x.modulus,
            modulus: x.modulus,
        })
    }

    fn cmul(&self, x: &DummyVal, c: u16) -> Result<DummyVal, Self::Error> {
        Ok(DummyVal {
            val: (x.val * c) % x.modulus,
            modulus: x.modulus,
        })
    }

    fn mul(
        &self,
        _ix: Option<SyncIndex>,
        x: &DummyVal,
        y: &DummyVal,
    ) -> Result<DummyVal, Self::Error> {
        Ok(DummyVal {
            val: x.val * y.val % x.modulus,
            modulus: x.modulus,
        })
    }

    fn proj(
        &self,
        _ix: Option<SyncIndex>,
        x: &DummyVal,
        modulus: u16,
        tt: Option<Vec<u16>>,
    ) -> Result<DummyVal, Self::Error> {
        let tt = tt.ok_or(Self::Error::from(FancyError::NoTruthTable))?;
        if tt.len() < x.modulus() as usize || !tt.iter().all(|&x| x < modulus) {
            return Err(Self::Error::from(FancyError::InvalidTruthTable));
        }
        let val = tt[x.val as usize];
        Ok(DummyVal { val, modulus })
    }

    fn output(&self, _ix: Option<SyncIndex>, x: &DummyVal) -> Result<(), Self::Error> {
        self.outputs.lock().unwrap().push(x.val);
        Ok(())
    }

    fn begin_sync(&self, num_indices: SyncIndex) -> Result<(), Self::Error> {
        *self.requests.write().unwrap() =
            Some((0..num_indices).map(|_| SegQueue::new()).collect_vec());
        *self.index_done.write().unwrap() = Some(
            (0..num_indices)
                .map(|_| AtomicBool::new(false))
                .collect_vec(),
        );

        start_postman(
            num_indices,
            self.index_done.clone(),
            self.requests.clone(),
            self.garbler_inputs.clone(),
            self.evaluator_inputs.clone(),
        );

        Ok(())
    }

    fn finish_index(&self, index: SyncIndex) -> Result<(), Self::Error> {
        if self.in_sync() {
            let mut cleanup = false;
            {
                let done = self.index_done.read().unwrap();
                let done = done
                    .as_ref()
                    .ok_or_else(|| DummyError::from(SyncError::IndexUsedOutOfSync))?;
                if index as usize >= done.len() {
                    return Err(DummyError::from(SyncError::IndexOutOfBounds))?;
                }
                done[index as usize].store(true, Ordering::SeqCst);
                if done.iter().all(|x| x.load(Ordering::SeqCst)) {
                    cleanup = true;
                }
            }
            // if we are completely done, clean up
            if cleanup {
                *self.index_done.write().unwrap() = None;
                *self.requests.write().unwrap() = None;
            }
        }
        Ok(())
    }
}

fn start_postman(
    end_index: SyncIndex,
    done: Arc<RwLock<Option<Vec<AtomicBool>>>>,
    reqs: Arc<RwLock<Option<Vec<SegQueue<(Request, Sender<DummyVal>)>>>>>,
    gb_inps: Arc<Mutex<Vec<u16>>>,
    ev_inps: Arc<Mutex<Vec<u16>>>,
) {
    std::thread::spawn(move || {
        let mut c = 0;
        while c < end_index {
            if let Some(ref reqs) = *reqs.read().unwrap() {
                if let Some(q) = reqs.get(c as usize) {
                    // avoid mysterious indexing error
                    if let Ok((r, tx)) = q.pop() {
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
                    }
                }
                let done_mutex = done.read().unwrap();
                if let Some(ref done) = *done_mutex {
                    if let Some(atomic_bool) = done.get(c as usize) {
                        if atomic_bool.load(Ordering::SeqCst) {
                            c += 1;
                        }
                    }
                }
            } else {
                // requests is None- finish_index has been called
                return;
            }
            std::thread::yield_now();
        }
    });
}

#[cfg(test)]
mod bundle {
    use super::*;
    use crate::fancy::BundleGadgets;
    use crate::util::{self, crt_factor, crt_inv_factor, RngExt};
    use itertools::Itertools;
    use rand::thread_rng;

    const NITERS: usize = 1 << 10;

    #[test] // bundle addition {{{
    fn test_addition() {
        let mut rng = thread_rng();
        for _ in 0..NITERS {
            let q = rng.gen_usable_composite_modulus();
            let x = rng.gen_u128() % q;
            let y = rng.gen_u128() % q;
            let d = Dummy::new(&crt_factor(x, q), &crt_factor(y, q));
            {
                let x = d.garbler_input_bundle_crt(None, q, None).unwrap();
                let y = d.evaluator_input_bundle_crt(None, q).unwrap();
                let z = d.add_bundles(&x, &y).unwrap();
                d.output_bundle(None, &z).unwrap();
            }
            let z = crt_inv_factor(&d.get_output(), q);
            assert_eq!(z, (x + y) % q);
        }
    }
    //}}}
    #[test] // bundle subtraction {{{
    fn test_subtraction() {
        let mut rng = thread_rng();
        for _ in 0..NITERS {
            let q = rng.gen_usable_composite_modulus();
            let x = rng.gen_u128() % q;
            let y = rng.gen_u128() % q;
            let d = Dummy::new(&crt_factor(x, q), &crt_factor(y, q));
            {
                let x = d.garbler_input_bundle_crt(None, q, None).unwrap();
                let y = d.evaluator_input_bundle_crt(None, q).unwrap();
                let z = d.sub_bundles(&x, &y).unwrap();
                d.output_bundle(None, &z).unwrap();
            }
            let z = crt_inv_factor(&d.get_output(), q);
            assert_eq!(z, (x + q - y) % q);
        }
    }
    //}}}
    #[test] // binary cmul {{{
    fn test_binary_cmul() {
        let mut rng = thread_rng();
        for _ in 0..NITERS {
            let nbits = 64;
            let q = 1 << nbits;
            let x = rng.gen_u128() % q;
            let c = 1 + rng.gen_u128() % q;
            let d = Dummy::new(&util::u128_to_bits(x, nbits), &[]);
            {
                let x = d.garbler_input_bundle(None, &vec![2; nbits], None).unwrap();
                let z = d.binary_cmul(None, &x, c, nbits).unwrap();
                d.output_bundle(None, &z).unwrap();
            }
            let z = util::u128_from_bits(&d.get_output());
            assert_eq!(z, (x * c) % q);
        }
    }
    //}}}
    #[test] // binary multiplication {{{
    fn test_binary_multiplication() {
        let mut rng = thread_rng();
        for _ in 0..NITERS {
            let nbits = 64;
            let q = 1 << nbits;
            let x = rng.gen_u128() % q;
            let y = rng.gen_u128() % q;
            let d = Dummy::new(&util::u128_to_bits(x, nbits), &util::u128_to_bits(y, nbits));
            {
                let x = d.garbler_input_bundle_binary(None, nbits, None).unwrap();
                let y = d.evaluator_input_bundle_binary(None, nbits).unwrap();
                let z = d.binary_multiplication_lower_half(None, &x, &y).unwrap();
                d.output_bundle(None, &z).unwrap();
            }
            let z = util::u128_from_bits(&d.get_output());
            assert_eq!(z, (x * y) & (q - 1));
        }
    }
    //}}}
    #[test] // bundle max {{{
    fn max() {
        let mut rng = thread_rng();
        let q = util::modulus_with_width(10);
        let n = 10;
        for _ in 0..NITERS {
            let inps = (0..n).map(|_| rng.gen_u128() % (q / 2)).collect_vec();
            let should_be = *inps.iter().max().unwrap();
            let enc_inps = inps
                .into_iter()
                .flat_map(|x| crt_factor(x, q))
                .collect_vec();
            let d = Dummy::new(&enc_inps, &[]);
            {
                let xs = d.garbler_input_bundles_crt(None, q, n, None).unwrap();
                let z = d.max(None, &xs, "100%").unwrap();
                d.output_bundle(None, &z).unwrap();
            }
            let z = crt_inv_factor(&d.get_output(), q);
            assert_eq!(z, should_be);
        }
    }
    //}}}
    #[test] // twos complement {{{
    fn twos_complement() {
        let mut rng = thread_rng();
        let nbits = 16;
        let q = 1 << nbits;
        for _ in 0..NITERS {
            let x = rng.gen_u128() % q;
            let should_be = (!x + 1) % q;
            let d = Dummy::new(&util::u128_to_bits(x, nbits), &[]);
            {
                let x = d.garbler_input_bundle_binary(None, nbits, None).unwrap();
                let y = d.twos_complement(None, &x).unwrap();
                d.output_bundle(None, &y).unwrap();
            }
            let outs = d.get_output();
            let y = util::u128_from_bits(&outs);
            assert_eq!(y, should_be, "x={} y={} should_be={}", x, y, should_be);
        }
    }
    //}}}
    #[test] // binary addition {{{
    fn binary_addition() {
        let mut rng = thread_rng();
        let nbits = 16;
        let q = 1 << nbits;
        for _ in 0..NITERS {
            let x = rng.gen_u128() % q;
            let y = rng.gen_u128() % q;
            let should_be = (x + y) % q;
            let enc_inps = [x, y]
                .into_iter()
                .flat_map(|&x| util::u128_to_bits(x, nbits))
                .collect_vec();
            let d = Dummy::new(&enc_inps, &[]);
            {
                let x = d.garbler_input_bundle_binary(None, nbits, None).unwrap();
                let y = d.garbler_input_bundle_binary(None, nbits, None).unwrap();
                let (z, overflow) = d.binary_addition(None, &x, &y).unwrap();
                d.output(None, &overflow).unwrap();
                d.output_bundle(None, &z).unwrap();
            }
            let outs = d.get_output();
            let overflow = outs[0] > 0;
            let z = util::u128_from_bits(&outs[1..]);
            assert_eq!(
                z, should_be,
                "x={} y={} z={} should_be={}",
                x, y, z, should_be
            );
            assert_eq!(overflow, x + y >= q, "x={} y={}", x, y);
        }
    }
    //}}}
    #[test] // binary subtraction {{{
    fn binary_subtraction() {
        let mut rng = thread_rng();
        let nbits = 16;
        let q = 1 << nbits;
        for _ in 0..NITERS {
            let x = rng.gen_u128() % q;
            let y = rng.gen_u128() % q;
            let should_be = (x - y) % q;
            let enc_inps = [x, y]
                .into_iter()
                .flat_map(|&x| util::u128_to_bits(x, nbits))
                .collect_vec();
            let d = Dummy::new(&enc_inps, &[]);
            {
                let x = d.garbler_input_bundle_binary(None, nbits, None).unwrap();
                let y = d.garbler_input_bundle_binary(None, nbits, None).unwrap();
                let (z, overflow) = d.binary_subtraction(None, &x, &y).unwrap();
                d.output(None, &overflow).unwrap();
                d.output_bundle(None, &z).unwrap();
            }
            let outs = d.get_output();
            let overflow = outs[0] > 0;
            let z = util::u128_from_bits(&outs[1..]);
            assert_eq!(
                z, should_be,
                "x={} y={} z={} should_be={}",
                x, y, z, should_be
            );
            assert_eq!(overflow, (y != 0 && x >= y), "x={} y={}", x, y);
        }
    }
    //}}}
    #[test] // binary lt {{{
    fn binary_lt() {
        let mut rng = thread_rng();
        let nbits = 16;
        let q = 1 << nbits;
        for _ in 0..NITERS {
            let x = rng.gen_u128() % q;
            let y = rng.gen_u128() % q;
            let should_be = x < y;
            let enc_inps = [x, y]
                .into_iter()
                .flat_map(|&x| util::u128_to_bits(x, nbits))
                .collect_vec();
            let d = Dummy::new(&enc_inps, &[]);
            {
                let x = d.garbler_input_bundle_binary(None, nbits, None).unwrap();
                let y = d.garbler_input_bundle_binary(None, nbits, None).unwrap();
                let z = d.lt(None, &x, &y, "100%").unwrap();
                d.output(None, &z).unwrap();
            }
            let z = d.get_output()[0] > 0;
            assert_eq!(z, should_be, "x={} y={}", x, y);
        }
    }
    //}}}
    #[test] // binary max {{{
    fn binary_max() {
        let mut rng = thread_rng();
        let n = 10;
        let nbits = 16;
        let q = 1 << nbits;
        for _ in 0..NITERS {
            let inps = (0..n).map(|_| rng.gen_u128() % q).collect_vec();
            let should_be = *inps.iter().max().unwrap();
            let enc_inps = inps
                .into_iter()
                .flat_map(|x| util::u128_to_bits(x, nbits))
                .collect_vec();
            let d = Dummy::new(&enc_inps, &[]);
            {
                let xs = d
                    .garbler_input_bundles(None, &vec![2; nbits], n, None)
                    .unwrap();
                let z = d.max(None, &xs, "100%").unwrap();
                d.output_bundle(None, &z).unwrap();
            }
            let z = util::u128_from_bits(&d.get_output());
            assert_eq!(z, should_be);
        }
    }
    //}}}
    #[test] // bundle relu {{{
    fn test_relu() {
        let mut rng = thread_rng();
        for _ in 0..NITERS {
            let q = crate::util::modulus_with_nprimes(4 + rng.gen_usize() % 7); // exact relu supports up to 11 primes
            let x = rng.gen_u128() % q;
            let d = Dummy::new(&crt_factor(x, q), &[]);
            {
                let x = d.garbler_input_bundle_crt(None, q, None).unwrap();
                let z = d.relu(None, &x, "100%", None).unwrap();
                d.output_bundle(None, &z).unwrap();
            }
            let z = crt_inv_factor(&d.get_output(), q);
            if x >= q / 2 {
                assert_eq!(z, 0);
            } else {
                assert_eq!(z, x);
            }
        }
    }
    //}}}
    #[test] // abs {{{
    fn binary_abs() {
        let mut rng = thread_rng();
        for _ in 0..NITERS {
            let nbits = 64;
            let q = 1 << nbits;
            let x = rng.gen_u128() % q;
            let d = Dummy::new(&util::u128_to_bits(x, nbits), &[]);
            {
                let x = d.garbler_input_bundle_binary(None, nbits, None).unwrap();
                let z = d.abs(None, &x).unwrap();
                d.output_bundle(None, &z).unwrap();
            }
            let z = util::u128_from_bits(&d.get_output());
            let should_be = if x >> (nbits - 1) > 0 {
                ((!x) + 1) & ((1 << nbits) - 1)
            } else {
                x
            };
            assert_eq!(z, should_be);
        }
    }
    //}}}
    #[test] // bundle mixed_radix_addition MSB {{{
    fn test_mixed_radix_addition_msb_only() {
        let mut rng = thread_rng();
        for _ in 0..NITERS {
            let nargs = 2 + rng.gen_usize() % 10;
            let mods = (0..7).map(|_| rng.gen_modulus()).collect_vec();
            let Q: u128 = util::product(&mods);

            println!("nargs={} mods={:?} Q={}", nargs, mods, Q);

            // test maximum overflow
            let mut ds = Vec::new();
            for _ in 0..nargs {
                ds.extend(util::as_mixed_radix(Q - 1, &mods).iter());
            }

            let b = Dummy::new(&ds, &[]);
            let xs = b.garbler_input_bundles(None, &mods, nargs, None).unwrap();
            let z = b.mixed_radix_addition_msb_only(None, &xs).unwrap();
            b.output(None, &z).unwrap();
            let res = b.get_output()[0];

            let should_be = *util::as_mixed_radix((Q - 1) * (nargs as u128) % Q, &mods)
                .last()
                .unwrap();
            assert_eq!(res, should_be);

            // test random values
            for _ in 0..4 {
                let mut sum = 0;
                let mut ds = Vec::new();
                for _ in 0..nargs {
                    let x = rng.gen_u128() % Q;
                    sum = (sum + x) % Q;
                    ds.extend(util::as_mixed_radix(x, &mods).iter());
                }

                let b = Dummy::new(&ds, &[]);
                let xs = b.garbler_input_bundles(None, &mods, nargs, None).unwrap();
                let z = b.mixed_radix_addition_msb_only(None, &xs).unwrap();
                b.output(None, &z).unwrap();
                let res = b.get_output()[0];

                let should_be = *util::as_mixed_radix(sum, &mods).last().unwrap();
                assert_eq!(res, should_be);
            }
        }
    }
    //}}}
    #[test] // dummy has send and sync {{{
    fn dummy_has_send_and_sync() {
        fn check_send(_: impl Send) {}
        fn check_sync(_: impl Sync) {}
        check_send(Dummy::new(&[], &[]));
        check_sync(Dummy::new(&[], &[]));
    } // }}}
}
