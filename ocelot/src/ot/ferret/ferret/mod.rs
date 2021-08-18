use super::{
    cache::{CachedReceiver, CachedSender},
    lpn::LLCode,
    mpcot,
    mpcot::Buckets,
    spcot,
    util,
};

mod receiver;
mod sender;

pub use receiver::Receiver;
pub use sender::Sender;

use scuttlebutt::Block;

use lazy_static::lazy_static;

const CODE_D: usize = 10;

const fn cots_required(k: usize, m: usize, log_bucket: usize) -> usize {
    k + log_bucket * m + 128
}

const SETUP_K: usize = 37_248;
const SETUP_N: usize = 616_092;
const SETUP_T: usize = 1_254;
const SETUP_M: usize = (SETUP_T * 3) / 2;
const SETUP_BUCKET_LOG_SIZE: usize = 11;
const SETUP_BUCKET_SIZE: usize = 1 << SETUP_BUCKET_LOG_SIZE;
pub const SETUP_COTS: usize = cots_required(SETUP_K, SETUP_M, SETUP_BUCKET_LOG_SIZE);

const MAIN_K: usize = 588_160;
const MAIN_N: usize = 10_616_092;
const MAIN_T: usize = 1_324;
const MAIN_M: usize = (MAIN_T * 3) / 2;
const MAIN_BUCKET_LOG_SIZE: usize = 14;
const MAIN_BUCKET_SIZE: usize = 1 << MAIN_BUCKET_LOG_SIZE;
pub const MAIN_COTS: usize = cots_required(MAIN_K, MAIN_M, MAIN_BUCKET_LOG_SIZE);

lazy_static! {
    // first iteration
    static ref SETUP_BUCKETS: Buckets = Buckets::build(SETUP_N, SETUP_M);
    static ref SETUP_CODE: LLCode::<SETUP_K, SETUP_N, CODE_D> = LLCode::from_seed(Block::default());

    // main iterations
    static ref MAIN_BUCKETS: Buckets = Buckets::build(MAIN_N, MAIN_M);
    static ref MAIN_CODE: LLCode::<MAIN_K, MAIN_N, CODE_D> = LLCode::from_seed(Block::default());
}

#[cfg(test)]
mod tests {
    use super::*;

    // sanity check: bucket sizes are optimal
    #[test]
    fn check_optimal_bucket_size() {
        assert!(SETUP_BUCKETS.max() > 1 << (SETUP_BUCKET_LOG_SIZE - 1));
        assert!(MAIN_BUCKETS.max() > 1 << (MAIN_BUCKET_LOG_SIZE - 1));
    }
}
