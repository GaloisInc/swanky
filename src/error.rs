use std::error::Error;
use std::fmt::{self, Display, Formatter};

#[derive(PartialEq, Eq, Clone, Debug)]
pub enum FancyError {
    UnequalModuli { xmod: u16, ymod: u16 },
    NotImplemented,
    NotEnoughArgs { nargs: usize, needed: usize },
    NoTruthTable,
    InvalidTruthTable,
    IndexRequired,
    IndexOutOfBounds,
    IndexUsedOUtOfSync,
    LockError(Box<Error>),
    ClientError(Box<Error>),
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum DummyError {
    NotEnoughGarblerInputs,
    NotEnoughEvaluatorInputs,
}

#[derive(PartialEq, Eq, Clone, Debug)]
pub enum EvaluatorError {
    InvalidMessage { expected: String, got: String },
}

////////////////////////////////////////////////////////////////////////////////

impl Error for FancyError {
    fn cause(&self) -> Option<&dyn Error> {
        match self {
            FancyError::ClientError(err) => Some(err),
            None => None,
        }
    }
}

impl Display for FancyError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            FancyError::UnequalModuli { xmod, ymod } => {
                write!(f, "unequal moduli: {} and {}", xmod, ymod)
            }
            FancyError::NotImplemented { name } => "not implemented".fmt(f),
            FancyError::NotEnoughArgs { nargs, needed } => write!(
                f,
                "not enough args: need at least {} but got {}",
                nargs, needed
            ),
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

impl Error for DummyError {
    fn cause(&self) -> Option<&dyn Error> {
        None
    }
}

impl From<DummyError> for FancyError {
    fn from(e: DummyError) -> FancyError {
        FancyError::ClientError(Box::new(e))
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

impl Error for EvaluatorError {
    fn cause(&self) -> Option<&dyn Error> {
        None
    }
}

impl From<EvaluatorError> for FancyError {
    fn from(e: EvaluatorError) -> FancyError {
        FancyError::ClientError(Box::new(e))
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
// standard library stuff

impl<T> From<std::sync::PoisonError<T>> for FancyError {
    fn from(e: std::sync::PoisonError<T>) -> FancyError {
        FancyError::LockError(Box::new(e))
    }
}
