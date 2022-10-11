//! Implementation of the "Kolesnikov-Matania-Pinkas-Rosulek-Trieu" multi-party private
//! set intersection protocol (cf. <https://eprint.iacr.org/2017/799.pdf>).

use crate::Error;
use itertools::Itertools;
use ocelot::oprf::{KmprtReceiver, KmprtSender};
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use scuttlebutt::{AbstractChannel, Block, Block512};

/// The party number for each party.
pub type PartyId = usize;

/// Base KMPRT Party.
struct Party {
    id: PartyId,
    opprf_senders: Vec<KmprtSender>,
    opprf_receivers: Vec<KmprtReceiver>,
}

/// KMPRT sender - there can be many of these.
pub struct Sender(Party);

/// KMPRT receiver - there can only be one of these.
pub struct Receiver(Party);

impl Sender {
    /// Initialize a PSI sender.
    pub fn init<C: AbstractChannel, RNG: RngCore + CryptoRng + SeedableRng>(
        me: PartyId,
        channels: &mut [(PartyId, C)],
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        Party::init(me, channels, rng).map(Self)
    }

    /// Send inputs to all parties and particpate in one party receiving the output.
    pub fn send<C: AbstractChannel, RNG: RngCore + CryptoRng + SeedableRng>(
        &mut self,
        inputs: &[Block],
        channels: &mut [(PartyId, C)],
        rng: &mut RNG,
    ) -> Result<(), Error> {
        assert!(self.0.id != 0);

        let s_hat = self.0.conditional_secret_sharing(inputs, channels, rng)?;

        // conditional reconstruction
        let points = inputs.iter().cloned().zip(s_hat.into_iter()).collect_vec();
        self.0.opprf_senders[0].send(&mut channels[0].1, &points, inputs.len(), rng)?;

        Ok(())
    }
}

impl Receiver {
    /// Initialize the PSI receiver.
    pub fn init<C: AbstractChannel, RNG: RngCore + CryptoRng + SeedableRng>(
        channels: &mut [(PartyId, C)],
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        Party::init(0, channels, rng).map(Self)
    }

    /// Send inputs and receive result - only one party should call this.
    pub fn receive<C: AbstractChannel, RNG: RngCore + CryptoRng + SeedableRng>(
        &mut self,
        inputs: &[Block],
        channels: &mut [(PartyId, C)],
        rng: &mut RNG,
    ) -> Result<Vec<Block>, Error> {
        let mut s_hat = self.0.conditional_secret_sharing(inputs, channels, rng)?;

        // conditional reconstruction
        for (channel_num, (_, channel)) in channels.iter_mut().enumerate() {
            let shares = self.0.opprf_receivers[channel_num].receive(channel, inputs, rng)?;
            for (i, share) in shares.into_iter().enumerate() {
                s_hat[i] ^= share;
            }
        }

        let intersection = inputs
            .iter()
            .zip(s_hat.into_iter())
            .filter_map(|(x, s)| {
                if s == Block512::default() {
                    Some(*x)
                } else {
                    None
                }
            })
            .collect_vec();

        Ok(intersection)
    }
}

impl Party {
    fn init<C: AbstractChannel, RNG: RngCore + CryptoRng + SeedableRng>(
        me: PartyId,
        channels: &mut [(PartyId, C)],
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let mut opprf_senders = Vec::with_capacity(channels.len());
        let mut opprf_receivers = Vec::with_capacity(channels.len());

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

    /// Share secret shares of zero using OPPRF, returning the xor of the OPPRF outputs -
    /// this phase is common to both the senders and the receiver.
    fn conditional_secret_sharing<C: AbstractChannel, RNG: RngCore + CryptoRng + SeedableRng>(
        &mut self,
        inputs: &[Block],
        channels: &mut [(PartyId, C)],
        rng: &mut RNG,
    ) -> Result<Vec<Block512>, Error> {
        let nparties = channels.len() + 1;
        let ninputs = inputs.len();

        let mut s_hat = vec![Block512::default(); ninputs];

        let s = (0..ninputs)
            .map(|i| {
                let shares = secret_sharing_of_zero(nparties, rng);
                s_hat[i] = shares[self.id];
                shares
            })
            .collect_vec();

        for (channel_num, (other_id, channel)) in channels.iter_mut().enumerate() {
            let points = inputs
                .iter()
                .enumerate()
                .map(|(i, x)| (*x, s[i][*other_id]))
                .collect_vec();

            let bs;
            if self.id < *other_id {
                self.opprf_senders[channel_num].send(channel, &points, inputs.len(), rng)?;
                bs = self.opprf_receivers[channel_num].receive(channel, inputs, rng)?;
            } else {
                bs = self.opprf_receivers[channel_num].receive(channel, inputs, rng)?;
                self.opprf_senders[channel_num].send(channel, &points, inputs.len(), rng)?;
            }

            for (i, b) in bs.into_iter().enumerate() {
                s_hat[i] ^= b;
            }
        }

        Ok(s_hat)
    }
}

fn secret_sharing_of_zero<R: Rng>(nparties: usize, rng: &mut R) -> Vec<Block512> {
    let mut sum = Block512::default();
    let mut shares = (0..nparties - 1)
        .map(|_| {
            let b = rng.gen();
            sum ^= b;
            b
        })
        .collect_vec();
    shares.push(sum);
    shares
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;
    use scuttlebutt::{AesRng, SyncChannel};
    use std::{
        io::{BufReader, BufWriter},
        os::unix::net::UnixStream,
    };

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

        let nparties = 3;
        let set_size = 1 << 6;
        let intersection_size = rng.gen::<usize>() % set_size;
        let intersection = (0..intersection_size)
            .map(|_| rng.gen::<Block>())
            .collect_vec();
        let mut set1 = intersection.clone();
        let mut set2 = intersection.clone();
        set1.extend((intersection_size..set_size).map(|_| rng.gen::<Block>()));
        set2.extend((intersection_size..set_size).map(|_| rng.gen::<Block>()));

        // create channels
        let mut channels = (0..nparties)
            .map(|_| (0..nparties).map(|_| None).collect_vec())
            .collect_vec();
        for i in 0..nparties {
            for j in 0..nparties {
                if i != j {
                    let (s, r) = UnixStream::pair().unwrap();
                    let left =
                        SyncChannel::new(BufReader::new(s.try_clone().unwrap()), BufWriter::new(s));
                    let right =
                        SyncChannel::new(BufReader::new(r.try_clone().unwrap()), BufWriter::new(r));
                    channels[i][j] = Some((j, left));
                    channels[j][i] = Some((i, right));
                }
            }
        }
        let mut channels = channels
            .into_iter()
            .map(|cs| cs.into_iter().flatten().collect_vec())
            .collect_vec();

        let mut receiver_channels = channels.remove(0);

        for (i, mut channels) in channels.into_iter().enumerate() {
            // create and fork senders
            let pid = i + 1;
            let my_set = set1.clone();
            std::thread::spawn(move || {
                let mut rng = AesRng::new();
                let mut sender = Sender::init(pid, &mut channels, &mut rng).unwrap();
                sender.send(&my_set, &mut channels, &mut rng).unwrap();
            });
        }

        // create and run receiver
        let mut receiver = Receiver::init(&mut receiver_channels, &mut rng).unwrap();
        let res = receiver
            .receive(&set2, &mut receiver_channels, &mut rng)
            .unwrap();

        assert_eq!(res, intersection);
    }
}
