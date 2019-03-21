// -*- mode: rust; -*-
//
// This file is part of `popsicle`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use crate::errors::Error;
use std::io::{Read, Write};

#[inline]
pub fn read_usize<T: Read>(reader: &mut T) -> Result<usize, Error> {
    let mut data = [0u8; 8];
    reader.read_exact(&mut data)?;
    let s = unsafe { std::mem::transmute(data) };
    Ok(s)
}

#[inline]
pub fn write_usize<T: Write>(writer: &mut T, s: usize) -> Result<(), Error> {
    let data: [u8; 8] = unsafe { std::mem::transmute(s) };
    writer.write_all(&data)?;
    Ok(())
}
