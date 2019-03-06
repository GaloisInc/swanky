// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

#[derive(Debug)]
pub enum OprfError {
    InvalidInputLength,
    Other(String),
}

#[derive(Debug)]
pub enum OtError {}

impl From<failure::Error> for OprfError {
    fn from(e: failure::Error) -> OprfError {
        OprfError::Other(e.to_string())
    }
}
