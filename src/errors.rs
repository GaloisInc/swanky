// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

/// Errors produced by oblivious transfer protocols.
#[derive(Debug)]
pub enum Error {
    InvalidInputLength,
    IoError(std::io::Error),
    Other(String),
    DecompressPoint,
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
            Error::DecompressPoint => "could not decompress point".fmt(f),
            Error::CoinTossError(e) => write!(f, "coin toss error: {}", e),
        }
    }
}
