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
    CommitmentCheck,
    DecompressPoint,
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Error {
        Error::IoError(e)
    }
}
