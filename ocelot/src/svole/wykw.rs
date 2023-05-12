//! Implementation of the Weng-Yang-Katz-Wang random subfield VOLE protocol (cf.
//! <https://eprint.iacr.org/2020/925>).

pub mod base_svole;
mod copee;
pub mod ggm_utils;
mod spsvole;
mod svole;
mod utils;

pub use svole::{
    LpnParams, Receiver, Sender, LPN_EXTEND_EXTRASMALL, LPN_EXTEND_LARGE, LPN_EXTEND_MEDIUM,
    LPN_EXTEND_SMALL, LPN_SETUP_EXTRASMALL, LPN_SETUP_LARGE, LPN_SETUP_MEDIUM, LPN_SETUP_SMALL,
};
