/// Dependent crates might not neccessarily depend on `proptest`, for example, themsevles.
/// Nonetheless, macros written in _this_ crate need to be able to access `proptest`, even when
/// those macros are invoked from other crates. To solve this problem, we re-export the crates that
/// our macros need.
#[doc(hidden)]
pub mod __internal_macro_exports {
    pub use generic_array;
    pub use proptest;
    pub use swanky_field;
    pub use swanky_serialization;
}

mod field;
mod ring;
pub use field::*;
pub use ring::*;
