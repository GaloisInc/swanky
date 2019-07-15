// -*- mode: rust; -*-
//
// This file is part of twopac.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use fancy_garbling::error::{EvaluatorError, FancyError, GarblerError};

/// Errors produced by `twopac`.
#[derive(Debug)]
pub enum Error {
    /// An I/O error has occurred.
    IoError(std::io::Error),
    /// An oblivious transfer error has occurred.
    OtError(ocelot::Error),
    /// The garbler produced an error.
    GarblerError(GarblerError),
    /// The evaluator produced an error.
    EvaluatorError(EvaluatorError),
    /// Processing the garbled circuit produced an error.
    FancyError(FancyError),
}

impl From<ocelot::Error> for Error {
    fn from(e: ocelot::Error) -> Error {
        Error::OtError(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Error {
        Error::IoError(e)
    }
}

impl From<EvaluatorError> for Error {
    fn from(e: EvaluatorError) -> Error {
        Error::EvaluatorError(e)
    }
}

impl From<GarblerError> for Error {
    fn from(e: GarblerError) -> Error {
        Error::GarblerError(e)
    }
}

impl From<FancyError> for Error {
    fn from(e: FancyError) -> Error {
        Error::FancyError(e)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::IoError(e) => write!(f, "IO error: {}", e),
            Error::OtError(e) => write!(f, "oblivious transfer error: {}", e),
            Error::EvaluatorError(e) => write!(f, "evaluator error: {}", e),
            Error::GarblerError(e) => write!(f, "garbler error: {}", e),
            Error::FancyError(e) => write!(f, "fancy error: {}", e),
        }
    }
}

impl From<Error> for GarblerError {
    fn from(e: Error) -> GarblerError {
        GarblerError::CommunicationError(e.to_string())
    }
}

impl From<Error> for EvaluatorError {
    fn from(e: Error) -> EvaluatorError {
        EvaluatorError::CommunicationError(e.to_string())
    }
}
