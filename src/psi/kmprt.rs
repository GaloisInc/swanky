// -*- mode: rust; -*-
//
// This file is part of `popsicle`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Implementation of the "Kolesnikov-Matania-Pinkas-Rosulek-Trieu" multi-party private
//! set intersection protocol (cf. <https://eprint.iacr.org/2017/799.pdf>).

use crate::Error;
use itertools::Itertools;
use ocelot::oprf::{KmprtReceiver, KmprtSender};
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use scuttlebutt::{AbstractChannel, Block, Block512};

/// The party number for each party.
pub type PartyId = usize;

/// KMPRT party - there can be many of these.
pub struct Party {
    id: PartyId,
    opprf_senders: Vec<KmprtSender>,
    opprf_receivers: Vec<KmprtReceiver>,
}

impl Party {
    /// Initialize the PSI sender.
    pub fn init<C: AbstractChannel, RNG: RngCore + CryptoRng + SeedableRng>(
        me: PartyId,
        channels: &mut [(PartyId, C)],
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let mut opprf_senders = Vec::with_capacity(channels.len());
        let mut opprf_receivers = Vec::with_capacity(channels.len());

        // XXX: potential deadlock if channels are not consistently ordered among parties
        for (them, c) in channels.iter_mut() {
            // the party with the lowest PID gets to initialize their OPPRF sender first
            if me < *them {
                opprf_senders.push(KmprtSender::init(c, rng)?);
                opprf_receivers.push(KmprtReceiver::init(c, rng)?);
            } else {
                opprf_receivers.push(KmprtReceiver::init(c, rng)?);
                opprf_senders.push(KmprtSender::init(c, rng)?);
            }
        }

        Ok(Self {
            id: me,
            opprf_senders,
            opprf_receivers,
        })
    }

    /// Send inputs to all parties and particpate in one party receiving the output.
    pub fn send<C: AbstractChannel, RNG: RngCore + CryptoRng + SeedableRng>(
        &mut self,
        inputs: &[Block],
        channels: &mut [(PartyId, C)],
        rng: &mut RNG,
    ) -> Result<(), Error> {
        unimplemented!()
    }

    /// Send inputs and receive result - only one party should call this.
    pub fn receive<C: AbstractChannel, RNG: RngCore + CryptoRng + SeedableRng>(
        inputs: &[Block],
        channels: &mut [(PartyId, C)],
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        unimplemented!()
    }

    /// Share secret shares of zero using OPPRF
    fn share_secret_shares<C: AbstractChannel, RNG: RngCore + CryptoRng + SeedableRng>(
        &mut self,
        inputs: &[Block],
        channels: &mut [(PartyId, C)],
        rng: &mut RNG
    ) -> Result<(), Error>
    {
        let nparties = channels.len() + 1;
        let ninputs = inputs.len();

        let s = (0..ninputs)
            .map(|_| secret_sharing_of_zero(nparties, rng))
            .collect_vec();

        for (channel_num, (other_id, c)) in channels.iter_mut().enumerate() {
            if self.id < *other_id {
                self.phase1_send(inputs, &s, *other_id, c, channel_num, rng)?;
                self.phase1_recv(inputs, c, channel_num, rng)?;
            } else {
                self.phase1_recv(inputs, c, channel_num, rng)?;
                self.phase1_send(inputs, &s, *other_id, c, channel_num, rng)?;
            }
        }

        unimplemented!()
    }

    fn phase1_send<C: AbstractChannel, RNG: RngCore + CryptoRng + SeedableRng>(
        &mut self,
        inputs: &[Block],
        s: &[Vec<Block512>],
        other_id: PartyId,
        channel: &mut C,
        channel_num: usize,
        rng: &mut RNG
    ) -> Result<(), Error> {
        let points = inputs
            .iter()
            .enumerate()
            .map(|(i, x)| {
                (*x, s[i][other_id].clone())
            })
            .collect_vec();
        self.opprf_senders[channel_num].send(channel, &points, inputs.len(), rng)?;
        Ok(())
    }

    fn phase1_recv<C: AbstractChannel, RNG: RngCore + CryptoRng + SeedableRng>(
        &mut self,
        inputs: &[Block],
        channel: &mut C,
        channel_num: usize,
        rng: &mut RNG
    ) -> Result<Vec<Block512>, Error> {
        let bs = self.opprf_receivers[channel_num].receive(channel, inputs, rng)?;
        Ok(bs)
    }
}

fn secret_sharing_of_zero<R: Rng>(nparties: usize, rng: &mut R) -> Vec<Block512> {
    unimplemented!()
}
