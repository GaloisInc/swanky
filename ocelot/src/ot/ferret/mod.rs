// mod ferret;
mod cache;
mod ferret;
mod mpcot;
mod spcot;
mod util;

use cache::{CachedReceiver, CachedSender};
use lazy_static::lazy_static;
use mpcot::Buckets;

// The statistical security parameter.
const SSP: usize = 40;

// The computational security parameter: \kappa in the paper.
const CSP: usize = 128;

const SETUP_K: usize = 37_248;
const SETUP_N: usize = 616_092;
const SETUP_T: usize = 1_254;
const SETUP_M: usize = (SETUP_T * 3) / 2;
const SETUP_BUCKET_LOG_SIZE: usize = 11;
const SETUP_BUCKET_SIZE: usize = 1 << SETUP_BUCKET_LOG_SIZE;

const MAIN_K: usize = 588_160;
const MAIN_N: usize = 10_616_092;
const MAIN_T: usize = 1_324;
const MAIN_M: usize = (MAIN_T * 3) / 2;
const MAIN_BUCKET_LOG_SIZE: usize = 14;
const MAIN_BUCKET_SIZE: usize = 1 << MAIN_BUCKET_LOG_SIZE;

lazy_static! {
    static ref BUCKETS_SETUP: Buckets = Buckets::build(SETUP_N, SETUP_M);
    static ref BUCKETS_MAIN: Buckets = Buckets::build(MAIN_N, MAIN_M);
}
