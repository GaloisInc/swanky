// -*- mode: rust; -*-
//
// This file is part of `popsicle`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Implementation of the "Kolesnikov-Matania-Pinkas-Rosulek-Trieu" multi-party private
//! set intersection protocol (cf. <https://eprint.iacr.org/2017/799>).

use crate::Error;
use ocelot::oprf::{KmprtReceiver, KmprtSender};
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use scuttlebutt::{AbstractChannel, Block, Block512, SemiHonest};

/// KMPRT party - there can be many of these.
pub struct Party {
    opprf_senders: Vec<KmprtSender>,
    opprf_receivers: Vec<KmprtReceiver>,
}

type PartyId = usize;

impl Party {
    /// Initialize the PSI sender.
    pub fn init<C: AbstractChannel, RNG: RngCore + CryptoRng + SeedableRng>(
        me: PartyId,
        channels: &mut [(PartyId, C)],
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let mut opprf_senders   = Vec::with_capacity(channels.len());
        let mut opprf_receivers = Vec::with_capacity(channels.len());

        // XXX: potential deadlock if channels are not consistently ordered among parties
        for (them, c) in channels.iter_mut() {
            // the party with the lowest PID gets to initialize their OPPRF sender first
            if me < them {
                opprf_senders.push(KmprtSender::init(c, rng)?);
                opprf_receivers.push(KmprtReceiver::init(c, rng)?);
            } else {
                opprf_receivers.push(KmprtReceiver::init(c, rng)?);
                opprf_senders.push(KmprtSender::init(c, rng)?);
            }
        }

        Ok(Self { opprf_senders, opprf_receivers })
    }
}
