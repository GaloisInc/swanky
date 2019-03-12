// -*- mode: rust; -*-
//
// This file is part of twopac.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use crate::errors::Error;
use std::io::{Read, Write};

pub fn send<W: Write>(writer: &mut W, data: &[u8]) -> Result<(), Error> {
    let len = data.len().to_le_bytes();
    writer.write_all(&len)?;
    writer.write_all(&data)?;
    writer.flush()?;
    Ok(())
}

pub fn receive<R: Read>(reader: &mut R) -> Result<Vec<u8>, Error> {
    let mut bytes = [0u8; 8];
    reader.read_exact(&mut bytes)?;
    let len = usize::from_le_bytes(bytes);
    let mut v = vec![0u8; len];
    reader.read_exact(&mut v)?;
    Ok(v)
}
