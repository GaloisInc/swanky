// mod ferret;
mod cache;
mod mpcot;
mod spcot;

use cache::{CachedReceiver, CachedSender};

// The statistical security parameter.
const SSP: usize = 40;

// The computational security parameter: \kappa in the paper.
const CSP: usize = 128;
