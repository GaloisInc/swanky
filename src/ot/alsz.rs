// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Implementation of the Asharov-Lindell-Schneider-Zohner oblivious transfer
//! extension protocol (cf. <https://eprint.iacr.org/2016/602>, Protocol 4).

use crate::errors::Error;
use crate::ot::{
    CorrelatedReceiver, CorrelatedSender, RandomReceiver, RandomSender, Receiver as OtReceiver,
    Sender as OtSender,
};
use crate::{stream, utils};
use arrayref::array_ref;
use rand::CryptoRng;
use rand_core::{RngCore, SeedableRng};
use scuttlebutt::utils as scutils;
use scuttlebutt::{AesHash, AesRng, Block, SemiHonest, AES_HASH};
use std::io::{ErrorKind, Read, Write};
use std::marker::PhantomData;

/// Oblivious transfer sender.
pub struct Sender<OT: OtReceiver<Msg = Block> + SemiHonest> {
    _ot: PhantomData<OT>,
    pub(super) hash: AesHash,
    s: Vec<bool>,
    pub(super) s_: Block,
    rngs: Vec<AesRng>,
}
/// Oblivious transfer receiver.
pub struct Receiver<OT: OtSender<Msg = Block> + SemiHonest> {
    _ot: PhantomData<OT>,
    pub(super) hash: AesHash,
    rngs: Vec<(AesRng, AesRng)>,
}

impl<OT: OtReceiver<Msg = Block> + SemiHonest> Sender<OT> {
    #[inline]
    pub(super) fn send_setup<R: Read + Send>(
        &mut self,
        reader: &mut R,
        m: usize,
    ) -> Result<Vec<u8>, Error> {
        if m % 8 != 0 {
            return Err(Error::from(std::io::Error::new(
                ErrorKind::InvalidInput,
                "Number of inputs must be divisible by 8",
            )));
        }
        let (nrows, ncols) = (128, m);
        let mut qs = vec![0u8; nrows * ncols / 8];
        let mut u = vec![0u8; ncols / 8];
        for (j, (b, mut rng)) in self.s.iter().zip(self.rngs.iter_mut()).enumerate() {
            let range = j * ncols / 8..(j + 1) * ncols / 8;
            let mut q = &mut qs[range];
            stream::read_bytes_inplace(reader, &mut u)?;
            // XXX: make constant time independent of `b`
            if !b {
                std::mem::replace(&mut u, vec![0u8; ncols / 8]);
            };
            let rng = &mut rng;
            rng.fill_bytes(&mut q);
            scutils::xor_inplace(&mut q, &u);
        }
        Ok(utils::transpose(&qs, nrows, ncols))
    }
}

impl<OT: OtReceiver<Msg = Block> + SemiHonest> OtSender for Sender<OT> {
    type Msg = Block;

    fn init<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        reader: &mut R,
        writer: &mut W,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let mut ot = OT::init(reader, writer, rng)?;
        let mut s_ = [0u8; 16];
        rng.fill_bytes(&mut s_);
        let s = utils::u8vec_to_boolvec(&s_);
        let ks = ot.receive(reader, writer, &s, rng)?;
        let rngs = ks
            .into_iter()
            .map(AesRng::from_seed)
            .collect::<Vec<AesRng>>();
        Ok(Self {
            _ot: PhantomData::<OT>,
            hash: AES_HASH,
            s,
            s_: Block::from(s_),
            rngs,
        })
    }

    fn send<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        inputs: &[(Self::Msg, Self::Msg)],
        _: &mut RNG,
    ) -> Result<(), Error> {
        let m = inputs.len();
        let qs = self.send_setup(reader, m)?;
        for (j, input) in inputs.iter().enumerate() {
            let q = &qs[j * 16..(j + 1) * 16];
            let q = Block::from(*array_ref![q, 0, 16]);
            let y0 = self.hash.cr_hash(Block::from(j as u128), q) ^ input.0;
            let q = q ^ self.s_;
            let y1 = self.hash.cr_hash(Block::from(j as u128), q) ^ input.1;
            y0.write(writer)?;
            y1.write(writer)?;
        }
        writer.flush()?;
        Ok(())
    }
}

impl<OT: OtReceiver<Msg = Block> + SemiHonest> CorrelatedSender for Sender<OT> {
    fn send_correlated<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        deltas: &[Self::Msg],
        _: &mut RNG,
    ) -> Result<Vec<(Self::Msg, Self::Msg)>, Error> {
        let m = deltas.len();
        let qs = self.send_setup(reader, m)?;
        let mut out = Vec::with_capacity(m);
        for (j, delta) in deltas.iter().enumerate() {
            let q = &qs[j * 16..(j + 1) * 16];
            let q = Block::from(*array_ref![q, 0, 16]);
            let x0 = self.hash.cr_hash(Block::from(j as u128), q);
            let x1 = x0 ^ *delta;
            let q = q ^ self.s_;
            let y = self.hash.cr_hash(Block::from(j as u128), q) ^ x1;
            y.write(writer)?;
            out.push((x0, x1));
        }
        writer.flush()?;
        Ok(out)
    }
}

impl<OT: OtReceiver<Msg = Block> + SemiHonest> RandomSender for Sender<OT> {
    fn send_random<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        &mut self,
        reader: &mut R,
        _: &mut W,
        m: usize,
        _: &mut RNG,
    ) -> Result<Vec<(Self::Msg, Self::Msg)>, Error> {
        let qs = self.send_setup(reader, m)?;
        let mut out = Vec::with_capacity(m);
        for j in 0..m {
            let q = &qs[j * 16..(j + 1) * 16];
            let q = Block::from(*array_ref![q, 0, 16]);
            let x0 = self.hash.cr_hash(Block::from(j as u128), q);
            let q = q ^ self.s_;
            let x1 = self.hash.cr_hash(Block::from(j as u128), q);
            out.push((x0, x1));
        }
        Ok(out)
    }
}

impl<OT: OtSender<Msg = Block> + SemiHonest> Receiver<OT> {
    #[inline]
    pub(super) fn receive_setup<W: Write + Send>(
        &mut self,
        writer: &mut W,
        r: &[u8],
        m: usize,
    ) -> Result<Vec<u8>, Error> {
        if m % 8 != 0 {
            return Err(Error::from(std::io::Error::new(
                ErrorKind::InvalidInput,
                "Number of inputs must be divisible by 8",
            )));
        }
        let (nrows, ncols) = (128, m);
        let mut ts = vec![0u8; nrows * ncols / 8];
        let mut g = vec![0u8; ncols / 8];
        for j in 0..self.rngs.len() {
            let range = j * ncols / 8..(j + 1) * ncols / 8;
            let mut t = &mut ts[range];
            self.rngs[j].0.fill_bytes(&mut t);
            self.rngs[j].1.fill_bytes(&mut g);
            scutils::xor_inplace(&mut g, &t);
            scutils::xor_inplace(&mut g, &r);
            stream::write_bytes(writer, &g)?;
            writer.flush()?;
        }
        Ok(utils::transpose(&ts, nrows, ncols))
    }
}

impl<OT: OtSender<Msg = Block> + SemiHonest> OtReceiver for Receiver<OT> {
    type Msg = Block;

    fn init<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        reader: &mut R,
        writer: &mut W,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let mut ot = OT::init(reader, writer, rng)?;
        let mut ks = Vec::with_capacity(128);
        let mut k0 = Block::default();
        let mut k1 = Block::default();
        for _ in 0..128 {
            rng.fill_bytes(&mut k0.as_mut());
            rng.fill_bytes(&mut k1.as_mut());
            ks.push((k0, k1));
        }
        ot.send(reader, writer, &ks, rng)?;
        let rngs = ks
            .into_iter()
            .map(|(k0, k1)| (AesRng::from_seed(k0), AesRng::from_seed(k1)))
            .collect::<Vec<(AesRng, AesRng)>>();
        Ok(Self {
            _ot: PhantomData::<OT>,
            hash: AES_HASH,
            rngs,
        })
    }

    fn receive<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        inputs: &[bool],
        _: &mut RNG,
    ) -> Result<Vec<Self::Msg>, Error> {
        let r = utils::boolvec_to_u8vec(inputs);
        let ts = self.receive_setup(writer, &r, inputs.len())?;
        let mut out = Vec::with_capacity(inputs.len());
        for (j, b) in inputs.iter().enumerate() {
            let t = &ts[j * 16..(j + 1) * 16];
            let y0 = Block::read(reader)?;
            let y1 = Block::read(reader)?;
            let y = if *b { y1 } else { y0 };
            let y = y ^ self
                .hash
                .cr_hash(Block::from(j as u128), Block::from(*array_ref![t, 0, 16]));
            out.push(y);
        }
        Ok(out)
    }
}

impl<OT: OtSender<Msg = Block> + SemiHonest> CorrelatedReceiver for Receiver<OT> {
    fn receive_correlated<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        inputs: &[bool],
        _: &mut RNG,
    ) -> Result<Vec<Self::Msg>, Error> {
        let r = utils::boolvec_to_u8vec(inputs);
        let ts = self.receive_setup(writer, &r, inputs.len())?;
        let mut out = Vec::with_capacity(inputs.len());
        for (j, b) in inputs.iter().enumerate() {
            let t = &ts[j * 16..(j + 1) * 16];
            let y = Block::read(reader)?;
            let y = if *b { y } else { Block::default() };
            let h = self
                .hash
                .cr_hash(Block::from(j as u128), Block::from(*array_ref![t, 0, 16]));
            out.push(y ^ h);
        }
        Ok(out)
    }
}

impl<OT: OtSender<Msg = Block> + SemiHonest> RandomReceiver for Receiver<OT> {
    fn receive_random<R: Read + Send, W: Write + Send, RNG: CryptoRng + RngCore>(
        &mut self,
        _: &mut R,
        writer: &mut W,
        inputs: &[bool],
        _: &mut RNG,
    ) -> Result<Vec<Self::Msg>, Error> {
        let r = utils::boolvec_to_u8vec(inputs);
        let ts = self.receive_setup(writer, &r, inputs.len())?;
        let mut out = Vec::with_capacity(inputs.len());
        for j in 0..inputs.len() {
            let t = &ts[j * 16..(j + 1) * 16];
            let h = self
                .hash
                .cr_hash(Block::from(j as u128), Block::from(*array_ref![t, 0, 16]));
            out.push(h);
        }
        Ok(out)
    }
}

impl<OT: OtReceiver<Msg = Block> + SemiHonest> SemiHonest for Sender<OT> {}
impl<OT: OtSender<Msg = Block> + SemiHonest> SemiHonest for Receiver<OT> {}
