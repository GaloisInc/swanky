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
    /// Correlation check failed.
    CorrelationCheckError(String),
    /// EQ check failed.
    EqCheckFailed,
    /// `t` doesn't divide the column `n` in LPN params `(n, k, t)`.
    InvalidWeight,
    /// `n` is not multiples of `2`.
    InvalidColumns,
    /// `k` is supposed to be less than or equal to `n`.
    InvalidRows,
    /// `d` in linear codes must be less than or equal to `k`.
    InvalidD,
    /// Commitment opening failed.
    InvalidOpening,
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
            Error::CorrelationCheckError(e) => write!(f, "correlation check error: {}", e),
            Error::EqCheckFailed => "EQ check failed!".fmt(f),
            Error::InvalidWeight => {
                "weight t doesn't divide n (length of the error vector e in the LPN assumption)!"
                    .fmt(f)
            }
            Error::InvalidColumns => "column n is not multiples of 2!".fmt(f),
            Error::InvalidRows => "rows are greater than cols!".fmt(f),
            Error::InvalidD => "d (linear codes) is greater than rows!".fmt(f),
            Error::InvalidOpening => "Invalid commitment opening!".fmt(f),
        }
    }
}
