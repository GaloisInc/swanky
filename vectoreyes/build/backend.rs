use cfg::Cfg;
use proc_macro2::TokenStream;

use quote::{quote, ToTokens};
use types::VectorType;

mod avx2;
mod cfg;
mod code_block;
mod generate;
mod neon;
mod types;
mod utils;
pub use generate::*;
use utils::index_literals;

/// Markdown formatted documentation which will be added to the documentation of wrapper functions.
///
/// For example, the AVX2 pairwise addition function for U32x4 might note that it uses the `PADD`
/// instruction.
type Docs = String;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairwiseOperator {
    WrappingAdd,
    WrappingSub,
    Xor,
    Or,
    And,
}

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

    /// What documentation should be generated for scalar implementations in this backend?
    ///
    /// As an example, the AVX2 implementation might have this function return "The AVX2 backend
    /// currently uses a slow scalar implementation for this function."
    fn scalar_docs(&self) -> Docs;

    fn pairwise(
        &self,
        ty: VectorType,
        op: PairwiseOperator,
        lhs: &dyn ToTokens,
        rhs: &dyn ToTokens,
    ) -> (TokenStream, Docs) {
        let idx = index_literals(ty.count());
        let fn_body = |fn_name: TokenStream| {
            quote! {
                #ty::from([#(
                    #lhs.as_array()[#idx].#fn_name(#rhs.as_array()[#idx]),
                )*])
            }
        };
        let op_body = |op: TokenStream| {
            quote! {
                #ty::from([#(
                    #lhs.as_array()[#idx] #op #rhs.as_array()[#idx],
                )*])
            }
        };
        (
            match op {
                PairwiseOperator::WrappingAdd => fn_body(quote! {wrapping_add}),
                PairwiseOperator::WrappingSub => fn_body(quote! {wrapping_sub}),
                PairwiseOperator::Xor => op_body(quote! { ^ }),
                PairwiseOperator::Or => op_body(quote! { | }),
                PairwiseOperator::And => op_body(quote! { & }),
            },
            self.scalar_docs(),
        )
    }
}

/// The scalar (non-vector) backend for vectoreyes.
pub struct Scalar;
impl VectorBackend for Scalar {
    fn cfg(&self) -> Cfg {
        // The scalar backend unconditionally works.
        Cfg::true_()
    }
    fn scalar_docs(&self) -> Docs {
        String::new()
    }
}
