#![deny(missing_docs)]
//! Testing utilities for oblivious transfer protocols

use rand::{
    RngExt,
    distr::{Distribution, StandardUniform},
};

fn rand_vec<T>(size: usize) -> Vec<T>
where
    StandardUniform: Distribution<T>,
{
    let mut rng = rand::rng();
    (0..size).map(|_| rng.random::<T>()).collect()
}
