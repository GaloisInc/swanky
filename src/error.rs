//! Errors that may be output by this library.

use std::fmt::{self, Display, Formatter};

/// Errors that may occur when using the `Fancy` trait. These errors are
/// API-usage errors, such as trying to add two `Items` with different moduli.
#[derive(Debug)]
pub enum FancyError {
    UnequalModuli,
    NotImplemented,
    InvalidArg { desc: String },
    InvalidArgNum { got: usize, needed: usize },
    InvalidArgMod { got: u16, needed: u16 },
    ArgNotBinary,
    NoTruthTable,
    InvalidTruthTable,
    UninitializedValue,
}

/// Errors from the dummy fancy object.
#[derive(Debug)]
pub enum DummyError {
    NotEnoughGarblerInputs,
    NotEnoughEvaluatorInputs,
    FancyError(FancyError),
}

/// Errors from the evaluator.
#[derive(Debug)]
pub enum EvaluatorError {
    InvalidMessage { expected: String, got: String },
    IndexReceivedInSyncMode,
    FancyError(FancyError),
}

/// Errors from the garbler.
#[derive(Debug)]
pub enum GarblerError {
    AsymmetricHalfGateModuliMax8(u16),
    TruthTableRequired,
    FancyError(FancyError),
}

/// Errors emitted when building a circuit.
#[derive(Debug)]
pub enum CircuitBuilderError {
    FancyError(FancyError),
}

/// Errors emitted when running the informer.
#[derive(Debug)]
pub enum InformerError {
    FancyError(FancyError),
}

////////////////////////////////////////////////////////////////////////////////
// fancy error

impl Display for FancyError {
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
            FancyError::UninitializedValue => {
                "uninitialized value in circuit. is the circuit topologically sorted?".fmt(f)
            }
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// Dummy error

impl Display for DummyError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            DummyError::NotEnoughGarblerInputs => "not enough garbler inputs".fmt(f),
            DummyError::NotEnoughEvaluatorInputs => "not enough evaluator inputs".fmt(f),
            DummyError::FancyError(e) => write!(f, "fancy error: {}", e),
        }
    }
}

impl From<FancyError> for DummyError {
    fn from(e: FancyError) -> DummyError {
        DummyError::FancyError(e)
    }
}

////////////////////////////////////////////////////////////////////////////////
// Evaluator error

impl Display for EvaluatorError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            EvaluatorError::InvalidMessage { expected, got } => {
                write!(f, "expected message {} but got {}", expected, got)
            }
            EvaluatorError::IndexReceivedInSyncMode => "index received in sync mode".fmt(f),
            EvaluatorError::FancyError(e) => write!(f, "fancy error: {}", e),
        }
    }
}

impl From<FancyError> for EvaluatorError {
    fn from(e: FancyError) -> EvaluatorError {
        EvaluatorError::FancyError(e)
    }
}

////////////////////////////////////////////////////////////////////////////////
// Garbler error

impl Display for GarblerError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            GarblerError::AsymmetricHalfGateModuliMax8(q) => write!(
                f,
                "the small modulus in a half gate with asymmetric moduli is capped at 8, got {}",
                q
            ),
            GarblerError::TruthTableRequired => {
                "truth table required for garbler projection gates".fmt(f)
            }
            GarblerError::FancyError(e) => write!(f, "fancy error: {}", e),
        }
    }
}

impl From<FancyError> for GarblerError {
    fn from(e: FancyError) -> GarblerError {
        GarblerError::FancyError(e)
    }
}

////////////////////////////////////////////////////////////////////////////////
// circuit builder error

impl Display for CircuitBuilderError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            CircuitBuilderError::FancyError(e) => write!(f, "fancy error: {}", e),
        }
    }
}

impl From<FancyError> for CircuitBuilderError {
    fn from(e: FancyError) -> CircuitBuilderError {
        CircuitBuilderError::FancyError(e)
    }
}

////////////////////////////////////////////////////////////////////////////////
// informer error

impl Display for InformerError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            InformerError::FancyError(e) => write!(f, "fancy error: {}", e),
        }
    }
}

impl From<FancyError> for InformerError {
    fn from(e: FancyError) -> InformerError {
        InformerError::FancyError(e)
    }
}

/// Errors emitted by the circuit parser.
#[derive(Debug)]
pub enum CircuitParserError {
    IoError(std::io::Error),
    RegexError(regex::Error),
    ParseIntError,
    ParseLineError(String),
    ParseGateError(String),
}

impl Display for CircuitParserError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            CircuitParserError::IoError(e) => write!(f, "io error: {}", e),
            CircuitParserError::RegexError(e) => write!(f, "regex error: {}", e),
            CircuitParserError::ParseIntError => write!(f, "unable to parse integer"),
            CircuitParserError::ParseLineError(s) => write!(f, "unable to parse line '{}'", s),
            CircuitParserError::ParseGateError(s) => write!(f, "unable to parse gate '{}'", s),
        }
    }
}

impl From<std::io::Error> for CircuitParserError {
    fn from(e: std::io::Error) -> CircuitParserError {
        CircuitParserError::IoError(e)
    }
}

impl From<regex::Error> for CircuitParserError {
    fn from(e: regex::Error) -> CircuitParserError {
        CircuitParserError::RegexError(e)
    }
}

impl From<std::num::ParseIntError> for CircuitParserError {
    fn from(_: std::num::ParseIntError) -> CircuitParserError {
        CircuitParserError::ParseIntError
    }
}
