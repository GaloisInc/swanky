// -*- mode: rust; -*-
//
// This file is part of `popsicle`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

/// Errors produced by the private set intersection protocols.
#[derive(Debug)]
pub enum Error {
    OprfError(ocelot::Error),
    IoError(std::io::Error),
    CuckooStashOverflow,
    InvalidCuckooSetSize(usize),
    InvalidCuckooParameters { nitems: usize, nhashes: usize },
}

impl From<std::io::Error> for Error {
    #[inline]
    fn from(e: std::io::Error) -> Error {
        Error::IoError(e)
    }
}

impl From<ocelot::Error> for Error {
    #[inline]
    fn from(e: ocelot::Error) -> Error {
        Error::OprfError(e)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::OprfError(e) => write!(f, "oblivious PRF error: {}", e),
            Error::IoError(e) => write!(f, "IO error: {}", e),
            Error::CuckooStashOverflow => write!(f, "CuckooHash: overflowed stash"),
            Error::InvalidCuckooSetSize(n) => write!(f, "CuckooHash: invalid size {}", n),
            Error::InvalidCuckooParameters { nitems, nhashes } => write!(f, "CuckooHash: no parameters set for {} items and {} hashes", nitems, nhashes),
        }
    }
}
