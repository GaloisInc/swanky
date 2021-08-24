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

const fn uni_cots_required(k: usize, m: usize, log_bucket_size: usize) -> usize {
    k + log_bucket_size * m + 128
}

const fn reg_cots_required(k: usize, t: usize, log_splen: usize) -> usize {
    k + log_splen * t + 128
}

// setup parameters for regular error distribution
const REG_SETUP_K: usize = 36_248;
// const REG_SETUP_N: usize = 609_728; Note: there is a typo in the paper!
const REG_SETUP_N: usize = 649_728;
const REG_SETUP_T: usize = 1_269;
const REG_SETUP_LOG_SPLEN: usize = 9;
const REG_SETUP_SPLEN: usize = 1 << REG_SETUP_LOG_SPLEN;
pub const REG_SETUP_COTS: usize = reg_cots_required(REG_SETUP_K, REG_SETUP_T, REG_SETUP_LOG_SPLEN);

// main iteration parameters for regular error distribution
const REG_MAIN_K: usize = 589_760;
const REG_MAIN_N: usize = 10_805_248;
const REG_MAIN_T: usize = 1_319;
const REG_MAIN_LOG_SPLEN: usize = 13;
const REG_MAIN_SPLEN: usize = 1 << REG_MAIN_LOG_SPLEN;
pub const REG_MAIN_COTS: usize = reg_cots_required(REG_MAIN_K, REG_MAIN_T, REG_MAIN_LOG_SPLEN);

lazy_static! {
    static ref REG_SETUP_CODE: LLCode::<REG_SETUP_K, REG_SETUP_N, CODE_D> =
        LLCode::from_seed(Block::default());
    static ref REG_MAIN_CODE: LLCode::<REG_MAIN_K, REG_MAIN_N, CODE_D> =
        LLCode::from_seed(Block::default());
}

// setup parameters for uniform error distribution
const UNI_SETUP_K: usize = 37_248;
const UNI_SETUP_N: usize = 616_092;
const UNI_SETUP_T: usize = 1_254;
const UNI_SETUP_M: usize = (UNI_SETUP_T * 3) / 2;
const UNI_SETUP_BUCKET_LOG_SIZE: usize = 11;
const UNI_SETUP_BUCKET_SIZE: usize = 1 << UNI_SETUP_BUCKET_LOG_SIZE;
pub const UNI_SETUP_COTS: usize =
    uni_cots_required(UNI_SETUP_K, UNI_SETUP_M, UNI_SETUP_BUCKET_LOG_SIZE);

// main iteration parameters for uniform error distribution
const UNI_MAIN_K: usize = 588_160;
const UNI_MAIN_N: usize = 10_616_092;
const UNI_MAIN_T: usize = 1_324;
const UNI_MAIN_M: usize = (UNI_MAIN_T * 3) / 2;
const UNI_MAIN_BUCKET_LOG_SIZE: usize = 14;
const UNI_MAIN_BUCKET_SIZE: usize = 1 << UNI_MAIN_BUCKET_LOG_SIZE;
pub const UNI_MAIN_COTS: usize =
    uni_cots_required(UNI_MAIN_K, UNI_MAIN_M, UNI_MAIN_BUCKET_LOG_SIZE);

lazy_static! {
    // first iteration
    static ref UNI_SETUP_BUCKETS: Buckets = Buckets::build(UNI_SETUP_N, UNI_SETUP_M);
    static ref UNI_SETUP_CODE: LLCode::<UNI_SETUP_K, UNI_SETUP_N, CODE_D> = LLCode::from_seed(Block::default());

    // main iterations
    static ref UNI_MAIN_BUCKETS: Buckets = Buckets::build(UNI_MAIN_N, UNI_MAIN_M);
    static ref UNI_MAIN_CODE: LLCode::<UNI_MAIN_K, UNI_MAIN_N, CODE_D> = LLCode::from_seed(Block::default());
}

#[cfg(test)]
mod tests {
    use super::*;

    // sanity check: bucket sizes are optimal
    #[test]
    fn check_optimal_bucket_size() {
        assert!(UNI_SETUP_BUCKETS.max() > 1 << (UNI_SETUP_BUCKET_LOG_SIZE - 1));
        assert!(UNI_MAIN_BUCKETS.max() > 1 << (UNI_MAIN_BUCKET_LOG_SIZE - 1));
    }
}
