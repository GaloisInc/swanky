// -*- mode: rust; -*-
//
// This file is part of twopac.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

#[derive(Debug)]
pub enum Error {
    IoError(std::io::Error),
    OtError(ocelot::Error),
    GarblerError(fancy_garbling::error::GarblerError),
    EvaluatorError(fancy_garbling::error::EvaluatorError),
    FancyError(fancy_garbling::error::FancyError),
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

impl From<fancy_garbling::error::EvaluatorError> for Error {
    fn from(e: fancy_garbling::error::EvaluatorError) -> Error {
        Error::EvaluatorError(e)
    }
}

impl From<fancy_garbling::error::GarblerError> for Error {
    fn from(e: fancy_garbling::error::GarblerError) -> Error {
        Error::GarblerError(e)
    }
}

impl From<fancy_garbling::error::FancyError> for Error {
    fn from(e: fancy_garbling::error::FancyError) -> Error {
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
