//! Circuits for operating over binary values.

mod binary_ops;
pub use binary_ops::{AndMany, OrMany, PairwiseAnd, PairwiseOr, PairwiseXor, XorMany};

mod mux;
pub use mux::{Mux, MuxBit, MuxBitConstants, MuxConstants};

mod binary_adder;
pub use binary_adder::BinaryAdder;

mod constant;
pub use constant::Constant;
pub use constant::test::TestConstant;

mod binary_addition;
pub use binary_addition::BinaryAddition;
pub use binary_addition::BinaryAdditionNoCarry;
pub use binary_addition::test::TestBinaryAddition;

mod sub;
pub use sub::{Sub, TestSub};

mod mul;
pub use mul::{Mul, MulLowerHalf, Mulc, TestMul};

mod div;
pub use div::Div;

mod comparison;
pub use comparison::{GreaterThanOrEqual, LessThan, LessThanSigned};

mod eq;
pub use eq::Eq;

mod twos_complement;
pub use twos_complement::{TestTwosComplement, TwosComplement};

mod max;
pub use max::Max;

mod shift;
pub use shift::{
    ArithmeticRightShift, LeftShift, LeftShiftExtend, LeftShiftPad, RightShift, RightShiftPad,
};

mod abs;
pub use abs::AbsoluteValue;

mod to_unary;
pub use to_unary::ToUnary;
