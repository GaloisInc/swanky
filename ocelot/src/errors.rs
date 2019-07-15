// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

/// Errors produced by `ocelot`.
#[derive(Debug)]
pub enum Error {
    /// The input length is invalid.
    InvalidInputLength,
    /// An I/O error has occurred.
    IoError(std::io::Error),
    /// Some other error, given by `String`.
    Other(String),
    /// Coin tossing failed.
    CoinTossError(scuttlebutt::cointoss::Error),
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Error {
        Error::IoError(e)
    }
}

impl From<scuttlebutt::cointoss::Error> for Error {
    fn from(e: scuttlebutt::cointoss::Error) -> Error {
        Error::CoinTossError(e)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::InvalidInputLength => "invalid input length".fmt(f),
            Error::IoError(e) => write!(f, "IO error: {}", e),
            Error::Other(s) => write!(f, "other error: {}", s),
            Error::CoinTossError(e) => write!(f, "coin toss error: {}", e),
        }
    }
}
