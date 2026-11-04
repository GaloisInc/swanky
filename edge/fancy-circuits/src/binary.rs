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

mod binary_less_than;
pub use binary_less_than::BinaryLessThan;
pub use binary_less_than::BinaryLessThanSigned;
pub use binary_less_than::test::TestBinaryLessThan;
pub use binary_less_than::test::TestBinaryLessThanSigned;

mod binary_greater_than_or_equal;
pub use binary_greater_than_or_equal::BinaryGreaterThanOrEqual;
pub use binary_greater_than_or_equal::test::TestBinaryGreaterThanOrEqual;

mod eq;
pub use eq::Eq;

mod twos_complement;
pub use twos_complement::{TestTwosComplement, TwosComplement};

mod max;
pub use max::Max;

mod binary_shift;
pub use binary_shift::BinaryArithmeticRightShift;
pub use binary_shift::BinaryLeftShift;
pub use binary_shift::BinaryLeftShiftExtend;
pub use binary_shift::BinaryLeftShiftPad;
pub use binary_shift::BinaryRightShift;
pub use binary_shift::BinaryRightShiftPad;

mod abs;
pub use abs::AbsoluteValue;

mod to_unary;
pub use to_unary::ToUnary;
