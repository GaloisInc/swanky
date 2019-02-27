use std::fmt::{self, Display, Formatter};

#[derive(Debug)]
pub enum FancyError<T> {
    UnequalModuli,
    NotImplemented,
    InvalidArg { desc: String },
    InvalidArgNum { got: usize, needed: usize },
    InvalidArgMod { got: u16, needed: u16 },
    ArgNotBinary,
    NoTruthTable,
    InvalidTruthTable,
    IndexRequired,
    IndexOutOfBounds,
    IndexUsedOutOfSync,
    ClientError(T),
}

#[derive(Debug)]
pub enum DummyError {
    NotEnoughGarblerInputs,
    NotEnoughEvaluatorInputs,
}

#[derive(Debug)]
pub enum EvaluatorError {
    InvalidMessage { expected: String, got: String },
}

#[derive(Debug)]
pub struct GarblerError;

#[derive(Debug)]
pub struct CircuitBuilderError;

#[derive(Debug)]
pub struct InformerError;

////////////////////////////////////////////////////////////////////////////////

impl<T: Display> Display for FancyError<T> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            FancyError::UnequalModuli => "unequal moduli".fmt(f),
            FancyError::NotImplemented => "not implemented".fmt(f),
            FancyError::InvalidArg { desc } => write!(f, "invalid argument: {}", desc),
            FancyError::InvalidArgNum { got, needed } => write!(
                f,
                "invalid number of args: needed {} but got {}",
                got, needed
            ),
            FancyError::InvalidArgMod { got, needed } => {
                write!(f, "invalid mod: got mod {} but require mod {}", got, needed)
            }
            FancyError::ArgNotBinary => "argument bundle must be boolean".fmt(f),
            FancyError::NoTruthTable => "truth table required".fmt(f),
            FancyError::InvalidTruthTable => "invalid truth table".fmt(f),
            FancyError::IndexRequired => "sync index required in sync mode".fmt(f),
            FancyError::IndexOutOfBounds => "sync index out of bounds".fmt(f),
            FancyError::IndexUsedOutOfSync => "sync index used out of sync mode".fmt(f),
            FancyError::ClientError(e) => write!(f, "client error: {}", e),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// Dummy error

impl From<DummyError> for FancyError<DummyError> {
    fn from(e: DummyError) -> FancyError<DummyError> {
        FancyError::ClientError(e)
    }
}

impl Display for DummyError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            DummyError::NotEnoughGarblerInputs => "not enough garbler inputs".fmt(f),
            DummyError::NotEnoughEvaluatorInputs => "not enough evaluator inputs".fmt(f),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// Evaluator error

impl From<EvaluatorError> for FancyError<EvaluatorError> {
    fn from(e: EvaluatorError) -> FancyError<EvaluatorError> {
        FancyError::ClientError(e)
    }
}

impl Display for EvaluatorError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            EvaluatorError::InvalidMessage { expected, got } => {
                write!(f, "expected message {} but got {}", expected, got)
            }
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// Garbler error

impl From<GarblerError> for FancyError<GarblerError> {
    fn from(e: GarblerError) -> FancyError<GarblerError> {
        FancyError::ClientError(e)
    }
}

impl Display for GarblerError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        "GarblerError".fmt(f)
    }
}

////////////////////////////////////////////////////////////////////////////////
// circuit builder error

impl From<CircuitBuilderError> for FancyError<CircuitBuilderError> {
    fn from(e: CircuitBuilderError) -> FancyError<CircuitBuilderError> {
        FancyError::ClientError(e)
    }
}

impl Display for CircuitBuilderError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        "CircuitBuilderError".fmt(f)
    }
}

////////////////////////////////////////////////////////////////////////////////
// informer error

impl From<InformerError> for FancyError<InformerError> {
    fn from(e: InformerError) -> FancyError<InformerError> {
        FancyError::ClientError(e)
    }
}

impl Display for InformerError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        "InformerError".fmt(f)
    }
}
