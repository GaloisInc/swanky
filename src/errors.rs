// -*- mode: rust; -*-
//
// This file is part of twopac.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use fancy_garbling::error as fancy;

#[derive(Debug)]
pub enum Error {
    IoError(std::io::Error),
    OtError(ocelot::Error),
    EvError(fancy::EvaluatorError),
    GbError(fancy::GarblerError),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::IoError(e) => write!(f, "IO Error: {}", e),
            Error::OtError(_e) => write!(f, "OT Error: ???"), // XXX: Print OT error when Ocelot adds Display
            Error::EvError(e) => write!(f, "Evaluator Error: {}", e),
            Error::GbError(e) => write!(f, "Garbler Error: {}", e),
        }
    }
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

impl From<fancy::EvaluatorError> for Error {
    fn from(e: fancy::EvaluatorError) -> Error {
        Error::EvError(e)
    }
}

impl From<fancy::GarblerError> for Error {
    fn from(e: fancy::GarblerError) -> Error {
        Error::GbError(e)
    }
}

pub fn from_fancy_gb_err(e: fancy::FancyError<fancy::GarblerError>) -> fancy::FancyError<Error> {
    e.map_client_err(Error::GbError)
}

pub fn from_fancy_ev_err(e: fancy::FancyError<fancy::EvaluatorError>) -> fancy::FancyError<Error> {
    e.map_client_err(Error::EvError)
}
