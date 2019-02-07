// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use failure::Error;
use std::io::{Read, Write};

pub fn send<T: Read + Write>(stream: &mut T, data: &[u8]) -> Result<(), Error> {
    let len = data.len().to_le_bytes();
    stream.write_all(&len)?;
    stream.write_all(&data)?;
    Ok(())
}

pub fn receive<T: Read + Write>(stream: &mut T) -> Result<Vec<u8>, Error> {
    let mut bytes: [u8; 8] = Default::default();
    stream.read_exact(&mut bytes)?;
    let len = usize::from_le_bytes(bytes);
    let mut v = vec![0u8; len];
    stream.read_exact(&mut v)?;
    Ok(v)
}
