//! Errors that may be outputted by this library.

use std::fmt::{self, Display, Formatter};

/// Errors that may occur when using the `Fancy` trait. `ClientError` wraps errors from
/// underlying fancy object.
///
/// With the exception of ClientError, FancyErrors should be API-usage errors, such as
/// trying to add two Items with different moduli.
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
    UninitializedValue,
    ClientError(T),
}

/// Common errors emitted by fancy objects in sync mode.
#[derive(Debug)]
pub enum SyncError {
    IndexRequired,
    IndexOutOfBounds,
    IndexUsedOutOfSync,
    SyncStartedInSync,
}

/// Errors from the dummy fancy object.
#[derive(Debug)]
pub enum DummyError {
    NotEnoughGarblerInputs,
    NotEnoughEvaluatorInputs,
    SyncError(SyncError),
}

/// Errors from the evaluator.
#[derive(Debug)]
pub enum EvaluatorError {
    InvalidMessage { expected: String, got: String },
    IndexReceivedInSyncMode,
    SyncError(SyncError),
}

/// Errors from the garbler.
#[derive(Debug)]
pub enum GarblerError {
    AsymmetricHalfGateModuliMax8(u16),
    TruthTableRequired,
    SyncError(SyncError),
}

/// Errors emitted when building a circuit.
#[derive(Debug)]
pub struct CircuitBuilderError;

/// Errors emitted when running the informer.
#[derive(Debug)]
pub struct InformerError;

////////////////////////////////////////////////////////////////////////////////
// fancy error

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
            FancyError::UninitializedValue => {
                "uninitialized value in circuit. is the circuit topologically sorted?".fmt(f)
            }
            FancyError::ClientError(e) => write!(f, "client error: {}", e),
        }
    }
}

impl <A> FancyError<A> {
    /// Map the underlying client error type.
    ///
    /// Useful for wrapping errors from fancy objects.
    pub fn map_client_err<B>(self, f: impl Fn(A) -> B) -> FancyError<B> {
        match self {
            FancyError::UnequalModuli => FancyError::UnequalModuli,
            FancyError::NotImplemented => FancyError::NotImplemented,
            FancyError::InvalidArg { desc } => FancyError::InvalidArg { desc },
            FancyError::InvalidArgNum { got, needed } => FancyError::InvalidArgNum { got, needed },
            FancyError::InvalidArgMod { got, needed } => FancyError::InvalidArgMod { got, needed },
            FancyError::ArgNotBinary => FancyError::ArgNotBinary,
            FancyError::NoTruthTable => FancyError::NoTruthTable,
            FancyError::InvalidTruthTable => FancyError::InvalidTruthTable,
            FancyError::UninitializedValue => FancyError::UninitializedValue,
            FancyError::ClientError(e) => FancyError::ClientError(f(e)),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// sync error

impl Display for SyncError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            SyncError::IndexRequired => "sync index required in sync mode".fmt(f),
            SyncError::IndexOutOfBounds => "sync index out of bounds".fmt(f),
            SyncError::IndexUsedOutOfSync => "sync index used out of sync mode".fmt(f),
            SyncError::SyncStartedInSync => {
                "begin_sync called before finishing previous sync".fmt(f)
            }
        }
    }
}

impl From<SyncError> for GarblerError {
    fn from(e: SyncError) -> GarblerError {
        GarblerError::SyncError(e)
    }
}

impl From<SyncError> for EvaluatorError {
    fn from(e: SyncError) -> EvaluatorError {
        EvaluatorError::SyncError(e)
    }
}

impl From<SyncError> for DummyError {
    fn from(e: SyncError) -> DummyError {
        DummyError::SyncError(e)
    }
}

////////////////////////////////////////////////////////////////////////////////
// Dummy error

impl Display for DummyError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            DummyError::NotEnoughGarblerInputs => "not enough garbler inputs".fmt(f),
            DummyError::NotEnoughEvaluatorInputs => "not enough evaluator inputs".fmt(f),
            DummyError::SyncError(e) => write!(f, "dummy sync error: {}", e),
        }
    }
}

impl From<DummyError> for FancyError<DummyError> {
    fn from(e: DummyError) -> FancyError<DummyError> {
        FancyError::ClientError(e)
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
            EvaluatorError::SyncError(e) => write!(f, "evaluator sync error: {}", e),
        }
    }
}

impl From<EvaluatorError> for FancyError<EvaluatorError> {
    fn from(e: EvaluatorError) -> FancyError<EvaluatorError> {
        FancyError::ClientError(e)
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
        match self {
            GarblerError::AsymmetricHalfGateModuliMax8(q) => write!(
                f,
                "the small modulus in a half gate with asymmetric moduli is capped at 8, got {}",
                q
            ),
            GarblerError::TruthTableRequired => {
                "truth table required for garbler projection gates".fmt(f)
            }
            GarblerError::SyncError(e) => write!(f, "garbler sync error: {}", e),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// circuit builder error

impl Display for CircuitBuilderError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        "CircuitBuilderError".fmt(f)
    }
}

impl From<CircuitBuilderError> for FancyError<CircuitBuilderError> {
    fn from(e: CircuitBuilderError) -> FancyError<CircuitBuilderError> {
        FancyError::ClientError(e)
    }
}

////////////////////////////////////////////////////////////////////////////////
// informer error

impl Display for InformerError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        "InformerError".fmt(f)
    }
}

impl From<InformerError> for FancyError<InformerError> {
    fn from(e: InformerError) -> FancyError<InformerError> {
        FancyError::ClientError(e)
    }
}
