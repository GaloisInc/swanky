// -*- mode: rust; -*-
//
// This file is part of twopac.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use crate::errors::Error;
use scuttlebutt::Block;
use std::io::{Read, Write};

pub fn send_blocks<W: Write>(writer: &mut W, blocks: &[Block]) -> Result<(), Error> {
    for block in blocks.iter() {
        block.write(writer)?;
    }
    writer.flush()?;
    Ok(())
}

pub fn receive_blocks<R: Read>(reader: &mut R, nblocks: usize) -> Result<Vec<Block>, Error> {
    let mut out = Vec::with_capacity(nblocks);
    for _ in 0..nblocks {
        let b = Block::read(reader)?;
        out.push(b);
    }
    Ok(out)
}
