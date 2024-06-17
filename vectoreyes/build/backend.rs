use cfg::Cfg;
use proc_macro2::TokenStream;

use types::VectorType;

mod avx2;
mod cfg;
mod code_block;
mod generate;
mod neon;
mod types;
pub use generate::*;

/// A vector backend for vectoreyes
///
/// The default implementations of methods in this trait implement the scalar backend. As a result,
/// backends can incrementally implement the features they support, while falling back to the
/// scalar implementation by default.
pub trait VectorBackend {
    /// What [`Cfg`] string is required to be true for this backend to be usable.
    fn cfg(&self) -> Cfg;
    /// What's the internal type/representation for vector `ty`?
    fn vector_contents(&self, ty: VectorType) -> TokenStream {
        ty.array()
    }
}

/// The scalar (non-vector) backend for vectoreyes.
pub struct Scalar;
impl VectorBackend for Scalar {
    fn cfg(&self) -> Cfg {
        // The scalar backend unconditionally works.
        Cfg::true_()
    }
}
