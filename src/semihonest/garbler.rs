// -*- mode: rust; -*-
//
// This file is part of twopac.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

// use crate::comm;
use crate::errors::Error;
// use fancy_garbling::error::GarblerError;
use fancy_garbling::{Fancy, FancyInput, Garbler as Gb, Wire};
use ocelot::ot::Sender as OtSender;
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use scuttlebutt::{Block, Channel, SemiHonest, AbstractChannel};
use std::fmt::Debug;
use std::io::{Read, Write};

/// Semi-honest garbler.
pub struct Garbler<R, W, RNG, OT> {
    garbler: Gb<W, RNG>,
    channel: Channel<R, W>,
    ot: OT,
    rng: RNG,
}

impl<R, W, OT, RNG> std::ops::Deref for Garbler<R, W, RNG, OT> {
    type Target = Gb<W, RNG>;
    fn deref(&self) -> &Self::Target {
        &self.garbler
    }
}

impl<R, W, OT, RNG> std::ops::DerefMut for Garbler<R, W, RNG, OT> {
    fn deref_mut(&mut self) -> &mut Gb<W, RNG> {
        &mut self.garbler
    }
}

impl<
        R: Read + Send,
        W: Write + Send + Debug + 'static,
        RNG: CryptoRng + RngCore + SeedableRng<Seed = Block>,
        OT: OtSender<Msg = Block>, // + SemiHonest
    > Garbler<R, W, RNG, OT>
{
    /// Make a new `Garbler`.
    pub fn new(
        mut channel: Channel<R, W>,
        mut rng: RNG,
        reused_deltas: &[Wire],
    ) -> Result<Self, Error> {
        let ot = OT::init(&mut channel, &mut rng)?;
        let garbler = Gb::new(channel.writer(), RNG::from_seed(rng.gen()), reused_deltas);
        Ok(Garbler {
            garbler,
            channel,
            ot,
            rng,
        })
    }

    #[inline]
    fn _evaluator_input(&mut self, delta: &Wire, q: u16) -> (Wire, Vec<(Block, Block)>) {
        let len = (q as f32).log(2.0).ceil() as u16;
        let mut wire = Wire::zero(q);
        let inputs = (0..len)
            .map(|i| {
                let zero = Wire::rand(&mut self.rng, q);
                let one = zero.plus(&delta);
                wire = wire.plus(&zero.cmul(1 << i));
                (zero.as_block(), one.as_block())
            })
            .collect::<Vec<(Block, Block)>>();
        (wire, inputs)
    }
}

impl<
        R: Read + Send,
        W: Write + Send + Debug + 'static,
        RNG: CryptoRng + RngCore + SeedableRng<Seed = Block>,
        OT: OtSender<Msg = Block>, // + SemiHonest
    > FancyInput for Garbler<R, W, RNG, OT>
{
    fn encode(&mut self, val: u16, modulus: u16) -> Result<Wire, Error> {
        let (mine, theirs) = self.garbler.encode_wire(val, modulus);
        self.garbler.send_wire(&theirs)?;
        self.channel.flush()?;
        Ok(mine)
    }

    fn encode_many(&mut self, vals: &[u16], moduli: &[u16]) -> Result<Vec<Wire>, Error> {
        let ws = vals
            .iter()
            .zip(moduli.iter())
            .map(|(x, q)| {
                let (mine, theirs) = self.garbler.encode_wire(*x, *q);
                self.garbler.send_wire(&theirs)?;
                Ok(mine)
            })
            .collect();
        self.channel.flush()?;
        ws
    }

    fn receive_many(&mut self, qs: &[u16]) -> Result<Vec<Wire>, Error> {
        let n = qs.len();
        let lens = qs.iter().map(|q| (*q as f32).log(2.0).ceil() as usize);
        let mut wires = Vec::with_capacity(n);
        let mut inputs = Vec::with_capacity(lens.sum());

        for q in qs.into_iter() {
            let delta = self.garbler.delta(*q);
            let (wire, input) = self._evaluator_input(&delta, *q);
            wires.push(wire);
            for i in input.into_iter() {
                inputs.push(i);
            }
        }

        self.ot.send(&mut self.channel, &inputs, &mut self.rng)?;
        Ok(wires)
    }
}

impl<
        R: Read + Send,
        W: Write + Send + Debug + 'static,
        RNG: CryptoRng + RngCore,
        OT: OtSender<Msg = Block>, // + SemiHonest
    > Fancy for Garbler<R, W, RNG, OT>
{
    type Item = Wire;
    type Error = Error;

    #[inline]
    fn constant(&mut self, x: u16, q: u16) -> Result<Self::Item, Self::Error> {
        self.garbler.constant(x, q).map_err(Self::Error::from)
    }

    #[inline]
    fn add(&mut self, x: &Wire, y: &Wire) -> Result<Self::Item, Self::Error> {
        self.garbler.add(x, y).map_err(Self::Error::from)
    }

    #[inline]
    fn sub(&mut self, x: &Wire, y: &Wire) -> Result<Self::Item, Self::Error> {
        self.garbler.sub(x, y).map_err(Self::Error::from)
    }

    #[inline]
    fn cmul(&mut self, x: &Wire, c: u16) -> Result<Self::Item, Self::Error> {
        self.garbler.cmul(x, c).map_err(Self::Error::from)
    }

    #[inline]
    fn mul(&mut self, x: &Wire, y: &Wire) -> Result<Self::Item, Self::Error> {
        self.garbler.mul(x, y).map_err(Self::Error::from)
    }

    #[inline]
    fn proj(&mut self, x: &Wire, q: u16, tt: Option<Vec<u16>>) -> Result<Self::Item, Self::Error> {
        self.garbler.proj(x, q, tt).map_err(Self::Error::from)
    }

    #[inline]
    fn output(&mut self, x: &Self::Item) -> Result<(), Self::Error> {
        self.garbler.output(x).map_err(Self::Error::from)
    }
}

impl<R, W, RNG, OT> SemiHonest for Garbler<R, W, RNG, OT>
where
    R: Read + Send,
    W: Write + Send + Debug + 'static,
    RNG: CryptoRng + RngCore,
    OT: OtSender<Msg = Block>, // + SemiHonest
{
}
