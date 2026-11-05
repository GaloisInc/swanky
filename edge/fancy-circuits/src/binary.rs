//! Circuits for operating over binary values.

mod abs;
pub use abs::AbsoluteValue;
mod add;
pub use add::{Add, AddBit, AddNoCarry, TestAdd};
mod binary_ops;
pub use binary_ops::{
    AndMany, OrMany, PairwiseAnd, PairwiseOr, PairwiseXor, TestAndMany, TestOrMany, TestXorMany,
    XorMany,
};
mod comparison;
pub use comparison::{GreaterThanOrEqual, LessThan, LessThanSigned};
mod constant;
pub use constant::Constant;
mod div;
pub use div::Div;
mod eq;
pub use eq::Eq;
mod max;
pub use max::Max;
mod mul;
pub use mul::{Mul, MulConstant, MulLowerHalf, TestMul};
mod mux;
pub use mux::{Mux, MuxBit, MuxBitConstants, MuxConstants};
mod shift;
pub use shift::{
    ArithmeticRightShift, LeftShift, LeftShiftExtend, LeftShiftPad, RightShift, RightShiftPad,
};
mod sub;
pub use sub::{Sub, TestSub};
mod to_unary;
pub use to_unary::ToUnary;
mod twos_complement;
pub use twos_complement::{TestTwosComplement, TwosComplement};
