// -*- mode: rust; -*-
//
// This file is part of `popsicle`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use crate::errors::Error;
use std::io::{Read, Write};

#[inline]
pub fn read_usize<T: Read>(stream: &mut T) -> Result<usize, Error> {
    let mut data = [0u8; 4];
    stream.read_exact(&mut data)?;
    let s = unsafe { std::mem::transmute(data) };
    Ok(s)
}

#[inline]
pub fn write_usize<T: Write>(stream: &mut T, s: usize) -> Result<(), Error> {
    let data: [u8; 4] = unsafe { std::mem::transmute(s) };
    stream.write(&data)?;
    Ok(())
}
