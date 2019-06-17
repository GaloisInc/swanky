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
    s_hat: Vec<Block512>,
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
            s_hat: vec![Block512::default(); channels.len() + 1],
        })
    }

    /// Send inputs to all parties and particpate in one party receiving the output.
    pub fn send<C: AbstractChannel, RNG: RngCore + CryptoRng + SeedableRng>(
        &mut self,
        inputs: &[Block],
        channels: &mut [(PartyId, C)],
        rng: &mut RNG,
    ) -> Result<(), Error> {
        self.share_secret_shares(inputs, channels, rng)?;
        unimplemented!()
    }

    /// Send inputs and receive result - only one party should call this.
    pub fn receive<C: AbstractChannel, RNG: RngCore + CryptoRng + SeedableRng>(
        &mut self,
        inputs: &[Block],
        channels: &mut [(PartyId, C)],
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        self.share_secret_shares(inputs, channels, rng)?;
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
            .map(|i| {
                let shares = secret_sharing_of_zero(nparties, rng);
                self.s_hat[i] = shares[0];
                shares
            })
            .collect_vec();

        for (channel_num, (other_id, channel)) in channels.iter_mut().enumerate() {
            let points = inputs
                .iter()
                .enumerate()
                .map(|(i, x)| {
                    (*x, s[i][*other_id].clone())
                })
                .collect_vec();

            let bs;
            if self.id < *other_id {
                self.opprf_senders[channel_num].send(channel, &points, inputs.len(), rng)?;
                bs = self.opprf_receivers[channel_num].receive(channel, inputs, rng)?;
            } else {
                bs = self.opprf_receivers[channel_num].receive(channel, inputs, rng)?;
                self.opprf_senders[channel_num].send(channel, &points, inputs.len(), rng)?;
            }

            for (i,b) in bs.into_iter().enumerate() {
                self.s_hat[i] ^= b;
            }
        }

        Ok(())
    }
}

fn secret_sharing_of_zero<R: Rng>(nparties: usize, rng: &mut R) -> Vec<Block512> {
    let mut sum = Block512::default();
    let mut shares = (0..nparties - 1).map(|_| {
        let b = rng.gen();
        sum ^= b;
        b
    }).collect_vec();
    shares.push(sum);
    shares
}

#[cfg(test)]
mod tests {
    use super::*;
    use scuttlebutt::AesRng;
    use rand::Rng;

    #[test]
    fn test_secret_sharing_of_zero() {
        let mut rng = AesRng::new();
        let nparties = (rng.gen::<usize>() % 98) + 2;
        let shares = secret_sharing_of_zero(nparties, &mut rng);
        assert!(shares.len() == nparties);
        let mut sum = Block512::default();
        for b in shares.into_iter() {
            assert!(b != Block512::default());
            sum ^= b;
        }
        assert_eq!(sum, Block512::default());
    }
}
