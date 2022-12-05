//! This module implements a basic cache for the various MPC-in-the-head
//! executions to share common computations.

use crate::secretsharing::LagrangeEvaluator;
use parking_lot::{RwLock, RwLockUpgradableReadGuard};
use rayon::iter::{ParallelDrainFull, ParallelIterator};
use scuttlebutt::field::{polynomial::NewtonPolynomial, FiniteField};
use simple_arith_circuit::Circuit;
use std::collections::{HashMap, HashSet};

/// Cached computations used by the prover and verifier.
///
/// We wrap a bunch of these cached computations in a `RwLock` because each MPC-in-the-head
/// execution is executed in a different thread.
// TODO: There's probably a better way of doing this without using `RwLock`!
pub(crate) struct Cache<F: FiniteField> {
    /// Contains the points `g, g^2, ..., g^{2k}`, where `g` is the field generator
    /// and `k` is the compression factor.
    pub points: Vec<F>,
    /// Map from chunk size to its associated Lagrange evaluator.
    pub evaluators: RwLock<HashMap<usize, LagrangeEvaluator<F>>>,
    /// Map from chunk size to its associated Newton polynomial.
    pub newton_polys: RwLock<HashMap<usize, NewtonPolynomial<F>>>,
    /// Map from (chunk size, is final round) tuple to its associated Newton bases.
    pub newton_bases: RwLock<HashMap<(usize, bool), Vec<Vec<F>>>>,
}

impl<F: FiniteField> Cache<F> {
    pub fn new(
        circuit: &Circuit<F::PrimeField>,
        compression_factor: usize,
        is_prover: bool,
    ) -> Self {
        // Pre-compute points for polynomial interpolation.
        let mut points = vec![F::ZERO; 2 * compression_factor + 1];
        points[0] = F::GENERATOR;
        for i in 1..2 * compression_factor + 1 {
            points[i] = points[i - 1] * F::GENERATOR;
        }
        let nrounds = crate::utils::nrounds(circuit, compression_factor);
        let mut cache = Self {
            points,
            newton_polys: RwLock::new(HashMap::new()),
            newton_bases: RwLock::new(HashMap::new()),
            evaluators: RwLock::new(HashMap::new()),
        };
        cache.fill(circuit, nrounds, compression_factor, is_prover);
        cache
    }

    // Fills the cache with the necessary precomputed values.
    fn fill(
        &mut self,
        circuit: &Circuit<F::PrimeField>,
        nrounds: usize,
        compression_factor: usize,
        is_prover: bool,
    ) {
        // Compute the sizes needed for the cached newton polynomials and newton bases.
        let mut set = HashSet::new();
        let mut nmuls = circuit.nmuls();
        for i in 0..=nrounds {
            let final_round = i == nrounds;
            let dimension = (nmuls as f32 / compression_factor as f32).ceil() as usize;
            let k = (nmuls as f32 / dimension as f32).ceil() as usize;
            set.insert((k, final_round));
            nmuls = dimension;
        }
        // Build the cache.
        set.par_drain().for_each(|(k, final_round)| {
            let nchunks = if final_round { k + 1 } else { k };
            {
                let evaluators = self.evaluators.upgradable_read();
                if !evaluators.contains_key(&nchunks) {
                    let evaluator = LagrangeEvaluator::new(&self.points[0..nchunks]);
                    let mut evaluators = RwLockUpgradableReadGuard::upgrade(evaluators);
                    evaluators.insert(nchunks, evaluator);
                }
            }
            {
                let evaluators = self.evaluators.upgradable_read();
                if !evaluators.contains_key(&(2 * nchunks - 1)) {
                    let evaluator = LagrangeEvaluator::new(&self.points[0..2 * nchunks - 1]);
                    let mut evaluators = RwLockUpgradableReadGuard::upgrade(evaluators);
                    evaluators.insert(2 * nchunks - 1, evaluator);
                }
            }
            if is_prover {
                {
                    let newton_polys = self.newton_polys.upgradable_read();
                    if !newton_polys.contains_key(&nchunks) {
                        let poly = NewtonPolynomial::new(self.points[0..nchunks].to_vec());
                        let mut newton_polys = RwLockUpgradableReadGuard::upgrade(newton_polys);
                        newton_polys.insert(nchunks, poly);
                    }
                }
                let newton_polys = self.newton_polys.read();
                let poly = newton_polys.get(&nchunks).unwrap();
                let newton_bases = self.newton_bases.upgradable_read();
                if !newton_bases.contains_key(&(k, final_round)) {
                    let top = if final_round { 2 * k + 1 } else { 2 * k - 1 };
                    let mut bases = Vec::with_capacity(top - k - 1);
                    for u in (k + 1)..=top {
                        let mut basis = Vec::with_capacity(nchunks);
                        poly.basis_polynomial(self.points[u - 1], &mut basis);
                        bases.push(basis);
                    }
                    let mut newton_bases = RwLockUpgradableReadGuard::upgrade(newton_bases);
                    newton_bases.insert((k, final_round), bases);
                }
            }
        });
    }
}
