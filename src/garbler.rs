// -*- mode: rust; -*-
//
// This file is part of twopac.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use crate::comm;
use crate::errors::Error;
use fancy_garbling::error::GarblerError;
use fancy_garbling::{Fancy, Garbler as Gb, Message, Wire};
use ocelot::ot::Sender as OtSender;
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use scuttlebutt::{AesRng, Block, SemiHonest};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

pub struct Garbler<
    R: Read + Send,
    W: Write + Send,
    RNG: CryptoRng + RngCore,
    OT: OtSender, // + SemiHonest
> {
    garbler: Gb<AesRng>,
    reader: Arc<Mutex<R>>,
    writer: Arc<Mutex<W>>,
    ot: Arc<Mutex<OT>>,
    rng: RNG,
}

impl<
        R: Read + Send,
        W: Write + Send + 'static,
        RNG: CryptoRng + RngCore,
        OT: OtSender<Msg = Block>, // + SemiHonest
    > Garbler<R, W, RNG, OT>
{
    pub fn new(mut reader: R, mut writer: W, inputs: &[u16], mut rng: RNG) -> Result<Self, Error> {
        let ot = OT::init(&mut reader, &mut writer, &mut rng)?;
        let mut inputs = inputs.to_vec().into_iter();
        let reader = Arc::new(Mutex::new(reader));
        let writer = Arc::new(Mutex::new(writer));
        let writer_ = writer.clone();
        let callback = move |m| {
            let mut writer = writer_.lock().unwrap();
            let res = match m {
                Message::UnencodedGarblerInput { zero, delta } => {
                    if let Some(input) = inputs.next() {
                        comm::send_block(&mut *writer, &zero.plus(&delta.cmul(input)).as_block())
                            .map_err(GarblerError::from)
                    } else {
                        Err(GarblerError::MessageError(
                            "not enough garbler inputs".to_string(),
                        ))
                    }
                }
                Message::Constant { wire, .. } => {
                    comm::send_block(&mut *writer, &wire.as_block()).map_err(GarblerError::from)
                }
                Message::GarbledGate(gate) => {
                    comm::send_blocks(&mut *writer, &gate).map_err(GarblerError::from)
                }
                Message::OutputCiphertext(ct) => {
                    comm::send_blocks(&mut *writer, &ct).map_err(GarblerError::from)
                }
                m => Err(GarblerError::MessageError(format!("invalid message {}", m))),
            };
            writer.flush()?;
            res
        };
        let garbler = Gb::new(callback, AesRng::from_seed(rng.gen::<Block>()));
        let ot = Arc::new(Mutex::new(ot));
        Ok(Garbler {
            garbler,
            reader,
            writer,
            ot,
            rng,
        })
    }

    fn run_ot(&mut self, inputs: &[(Block, Block)]) -> Result<(), Error> {
        let mut ot = self.ot.lock().unwrap();
        let mut reader = self.reader.lock().unwrap();
        let mut writer = self.writer.lock().unwrap();
        ot.send(&mut *reader, &mut *writer, inputs, &mut self.rng)
            .map_err(Error::from)
    }

    #[inline]
    fn _evaluator_input(&mut self, delta: &Wire, q: u16) -> (Wire, Vec<(Block, Block)>) {
        let len = (q as f32).log(2.0).ceil() as u16;
        let mut wire = Wire::zero(q);
        let inputs = (0..len)
            .into_iter()
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
        W: Write + Send + 'static,
        RNG: CryptoRng + RngCore,
        OT: OtSender<Msg = Block>, // + SemiHonest
    > Fancy for Garbler<R, W, RNG, OT>
{
    type Item = Wire;
    type Error = Error;

    #[inline]
    fn garbler_input(&mut self, q: u16, opt_x: Option<u16>) -> Result<Self::Item, Self::Error> {
        self.garbler
            .garbler_input(q, opt_x)
            .map_err(Self::Error::from)
    }
    #[inline]
    fn evaluator_input(&mut self, q: u16) -> Result<Self::Item, Self::Error> {
        let wires = self.evaluator_inputs(&[q])?;
        Ok(wires[0].clone())
    }
    #[inline]
    fn evaluator_inputs(&mut self, qs: &[u16]) -> Result<Vec<Self::Item>, Self::Error> {
        let n = qs.len();
        let lens = qs.into_iter().map(|q| (*q as f32).log(2.0).ceil() as usize);
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
        self.run_ot(&inputs)?;
        Ok(wires)
    }
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
    W: Write + Send + 'static,
    RNG: CryptoRng + RngCore,
    OT: OtSender<Msg = Block>, // + SemiHonest
{
}
