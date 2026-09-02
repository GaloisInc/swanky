//! Circuits for operating over binary values.

mod mux;
pub use mux::Mux;
pub use mux::MuxConstants;

mod pairwise_xor;
pub use pairwise_xor::PairwiseXor;

mod pairwise_and;
pub use pairwise_and::PairwiseAnd;

mod pairwise_or;
pub use pairwise_or::PairwiseOr;

mod and_many;
pub use and_many::AndMany;

mod or_many;
pub use or_many::OrMany;

mod xor_many;
pub use xor_many::XorMany;

mod binary_adder;
pub use binary_adder::BinaryAdder;

mod binary_constant;
pub use binary_constant::BinaryConstant;
pub use binary_constant::test::TestBinaryConstant;

mod binary_addition;
pub use binary_addition::BinaryAddition;
pub use binary_addition::BinaryAdditionNoCarry;
pub use binary_addition::test::TestBinaryAddition;

mod binary_subtraction;
pub use binary_subtraction::BinarySubtraction;
pub use binary_subtraction::test::TestBinarySubtraction;

mod binary_multiplication;
pub use binary_multiplication::BinaryConstantMultiplication;
pub use binary_multiplication::BinaryMultiplication;
pub use binary_multiplication::BinaryMultiplicationLowerHalf;
pub use binary_multiplication::TestBinaryMultiplication;

mod binary_division;
pub use binary_division::BinaryDivision;

mod binary_less_than;
pub use binary_less_than::BinaryLessThan;
pub use binary_less_than::BinaryLessThanSigned;
pub use binary_less_than::test::TestBinaryLessThan;
pub use binary_less_than::test::TestBinaryLessThanSigned;

mod binary_greater_than_or_equal;
pub use binary_greater_than_or_equal::BinaryGreaterThanOrEqual;
pub use binary_greater_than_or_equal::test::TestBinaryGreaterThanOrEqual;

mod binary_equality;
pub use binary_equality::BinaryEquality;
pub use binary_equality::test::TestBinaryEquality;

mod binary_twos_complement;
pub use binary_twos_complement::BinaryTwosComplement;
pub use binary_twos_complement::test::TestBinaryTwosComplement;

mod binary_multiplex;
pub use binary_multiplex::BinaryMultiplex;
pub use binary_multiplex::BinaryMultiplexConstantBits;

mod binary_max;
pub use binary_max::BinaryMax;

mod binary_shift;
pub use binary_shift::BinaryArithmeticRightShift;
pub use binary_shift::BinaryLeftShift;
pub use binary_shift::BinaryLeftShiftExtend;
pub use binary_shift::BinaryLeftShiftPad;
pub use binary_shift::BinaryRightShift;
pub use binary_shift::BinaryRightShiftPad;

mod binary_abs;
pub use binary_abs::BinaryAbs;

mod binary_to_unary;
pub use binary_to_unary::BinaryToUnary;
