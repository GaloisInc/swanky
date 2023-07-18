//! (Random) subfield vector oblivious linear evaluation (sVOLE) traits +
//! instantiations.
//!
//! This module implements the Weng-Yang-Katz-Wang maliciously secure random
//! sVOLE protocol.
//!

mod wykw;
pub use wykw::base_svole;
pub use wykw::ggm_utils;
pub use wykw::{
    LpnParams, LPN_EXTEND_EXTRASMALL, LPN_EXTEND_LARGE, LPN_EXTEND_MEDIUM, LPN_EXTEND_SMALL,
    LPN_SETUP_EXTRASMALL, LPN_SETUP_LARGE, LPN_SETUP_MEDIUM, LPN_SETUP_SMALL,
};
pub use wykw::{Receiver, Sender};
