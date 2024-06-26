//! Types for describing integers and vectors of integers.

use proc_macro2::TokenStream;
use quote::{format_ident, quote, ToTokens, TokenStreamExt};

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum Signedness {
    Signed,
    Unsigned,
}
impl std::fmt::Display for Signedness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Signedness::Signed => write!(f, "i"),
            Signedness::Unsigned => write!(f, "u"),
        }
    }
}

/// An integer type.
///
/// It's guaranteed to be one of `IntType::all()`.
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct IntType {
    signedness: Signedness,
    bits: usize,
}
/// Display this integer as the corresponding rust type.
///
/// For example, `i32`.
impl std::fmt::Display for IntType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}{}", self.signedness(), self.bits())
    }
}
impl IntType {
    pub fn bits(&self) -> usize {
        self.bits
    }

    pub fn signedness(&self) -> Signedness {
        self.signedness
    }

    /// An `Iterator` over all integer types we support.
    pub fn all() -> impl Iterator<Item = IntType> {
        INT_SIZES.iter().flat_map(|sz| {
            [int(Signedness::Unsigned, *sz), int(Signedness::Signed, *sz)].into_iter()
        })
    }
}
impl quote::ToTokens for IntType {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        tokens.append(proc_macro2::Ident::new(
            &self.to_string(),
            proc_macro2::Span::call_site(),
        ));
    }
}

const INT_SIZES: &[usize] = &[8, 16, 32, 64];

/// Construct an `IntType`.
///
/// This function panics if the requested int isn't a supported integer type (i.e. if it's not
/// listed in `IntType::all()`).
pub fn int(signedness: Signedness, bits: usize) -> IntType {
    assert!(INT_SIZES.contains(&bits));
    IntType { signedness, bits }
}

/// A vector of `count` elements of type `of`.
///
/// It's guaranteed to be an element of `VectorType::all()`.
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct VectorType {
    of: IntType,
    count: usize,
}
/// Display this integer as the corresponding vectoreyes type.
///
/// For example, `I32x4`.
impl std::fmt::Display for VectorType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}x{}", self.of.to_string().to_uppercase(), self.count)
    }
}
impl VectorType {
    pub fn of(&self) -> IntType {
        self.of
    }

    pub fn count(&self) -> usize {
        self.count
    }

    /// Return the tokens for this vector, but in array form.
    ///
    /// For example, `U8x32` maps to `[u8; 32]`.
    pub fn array(&self) -> TokenStream {
        let of = self.of();
        let count = self.count();
        quote! { [#of; #count] }
    }

    pub fn all() -> impl Iterator<Item = Self> {
        IntType::all().flat_map(|int_type| {
            VECTOR_SIZES
                .iter()
                .copied()
                .map(move |vec_sz| vec(int_type, vec_sz / int_type.bits()))
        })
    }

    /// The total number of bits in the vector.
    pub fn bits(&self) -> usize {
        self.count() * self.of().bits()
    }
}
impl ToTokens for VectorType {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        tokens.append(format_ident!("{self}"));
    }
}

/// Construct a `VectorType`.
///
/// This function panics if the requested int isn't a supported vector type (i.e. if it's not
/// listed in `VectorType::all()`).
pub fn vec(of: IntType, count: usize) -> VectorType {
    assert!(VECTOR_SIZES.contains(&(of.bits() * count)));
    VectorType { of, count }
}
const VECTOR_SIZES: &[usize] = &[128, 256];
