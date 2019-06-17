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
        let s_hat = self.conditional_secret_sharing(inputs, channels, rng)?;

        // conditional reconstruction
        let points = inputs.iter().cloned().zip(s_hat.into_iter()).collect_vec();
        self.opprf_senders[0].send(&mut channels[0].1, &points, inputs.len(), rng)?;

        Ok(())
    }

    /// Send inputs and receive result - only one party should call this.
    pub fn receive<C: AbstractChannel, RNG: RngCore + CryptoRng + SeedableRng>(
        &mut self,
        inputs: &[Block],
        channels: &mut [(PartyId, C)],
        rng: &mut RNG,
    ) -> Result<Vec<Block>, Error> {
        let mut s_hat = self.conditional_secret_sharing(inputs, channels, rng)?;

        // conditional reconstruction
        assert_eq!(self.id, 0);

        for (channel_num, (_, channel)) in channels.iter_mut().enumerate() {
            let shares = self.opprf_receivers[channel_num].receive(channel, inputs, rng)?;
            for (i, share) in shares.into_iter().enumerate() {
                s_hat[i] ^= share;
            }
        }

        let intersection = inputs.iter().zip(s_hat.into_iter()).filter_map(|(x,s)| {
            if s == Block512::default() {
                Some(*x)
            } else {
                None
            }
        }).collect_vec();

        Ok(intersection)
    }

    /// Share secret shares of zero using OPPRF, returning the xor of the OPPRF outputs -
    /// this phase is common to both the senders and the receiver.
    fn conditional_secret_sharing<C: AbstractChannel, RNG: RngCore + CryptoRng + SeedableRng>(
        &mut self,
        inputs: &[Block],
        channels: &mut [(PartyId, C)],
        rng: &mut RNG
    ) -> Result<Vec<Block512>, Error>
    {
        let nparties = channels.len() + 1;
        let ninputs = inputs.len();

        let mut s_hat = vec![Block512::default(); ninputs];

        let s = (0..ninputs)
            .map(|i| {
                let shares = secret_sharing_of_zero(nparties, rng);
                s_hat[i] = shares[0];
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
                s_hat[i] ^= b;
            }
        }

        Ok(s_hat)
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
    use rand::Rng;
    use scuttlebutt::{AesRng, Channel};
    use std::io::{BufReader, BufWriter};
    use std::os::unix::net::UnixStream;
    use super::*;

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

    #[test]
    fn test_protocol() {
        let mut rng = AesRng::new();
        let nparties = (rng.gen::<usize>() % 16) + 2;
        let set_size = 1 << 10;
        let item_size = 4;
        let set = crate::utils::rand_vec_vec(set_size, item_size, &mut rng);

        // create channels
        let mut channel_pairs = (0..nparties).map(|i| {
            (i+1..nparties).map(|_| {
                let (s,r) = UnixStream::pair().unwrap();
                let left  = Channel::new(BufReader::new(s.try_clone().unwrap()), BufWriter::new(s));
                let right = Channel::new(BufReader::new(r.try_clone().unwrap()), BufWriter::new(r));
                (Some(left), Some(right))
            }).collect_vec()
        }).collect_vec();

        let mut channels = (0..nparties).map(|i| {
            (i+1..nparties).map(|j| {
                let other_index = j - (i+1);
                let c = if channel_pairs[i][other_index].0.is_some() {
                    channel_pairs[i][other_index].0.take().unwrap()
                } else {
                    channel_pairs[i][other_index].1.take().unwrap()
                };
                (j, c)
            }).collect_vec()
        }).collect_vec();

        // let parties = (0..nparties).map(|pid| Party::init(pid, &mut channels[pid], &mut rng)).collect_vec();
    }
}
