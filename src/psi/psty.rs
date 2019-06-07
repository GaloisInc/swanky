// -*- mode: rust; -*-
//
// This file is part of `popsicle`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Implementation of the Pinkas-Schneider-Tkachenko-Yanai private set intersection
//! protocol (cf. <https://eprint.iacr.org/2019/241>).

use crate::cuckoo::CuckooHash;
use crate::errors::Error;
use crate::utils;
use fancy_garbling::{BundleGadgets, CrtBundle, CrtGadgets, Fancy, FancyInput, Wire};
use itertools::Itertools;
use ocelot::oprf::{KmprtReceiver, KmprtSender};
use ocelot::ot::{AlszReceiver as OtReceiver, AlszSender as OtSender};
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use scuttlebutt::{AbstractChannel, Block, Block512};
use twopac::semihonest::{Evaluator, Garbler};

const NHASHES: usize = 3;
// How many bytes of the hash to use for the equality tests.
const HASH_SIZE: usize = 4;

/// The type of values in the sender and receiver's sets.
pub type Msg = Vec<u8>;

/// Private set intersection sender.
pub struct Sender {
    opprf: KmprtSender,
}

/// PSI state returned by send, used by the MPC computations.
pub struct SenderState {
    opprf_outputs: Vec<Block512>,
}

/// Private set intersection receiver.
pub struct Receiver {
    opprf: KmprtReceiver,
}

/// PSI state returned by receive, used by the MPC computations.
pub struct ReceiverState {
    opprf_outputs: Vec<Block512>,
    cuckoo: CuckooHash,
    inputs: Vec<Msg>,
}

impl Sender {
    /// Initialize the PSI sender.
    pub fn init<C: AbstractChannel, RNG: RngCore + CryptoRng + SeedableRng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let opprf = KmprtSender::init(channel, rng)?;
        Ok(Self { opprf })
    }

    /// Run the PSI protocol over `inputs`.
    pub fn send<C: AbstractChannel, RNG: RngCore + CryptoRng + SeedableRng>(
        &mut self,
        channel: &mut C,
        inputs: &[Msg],
        rng: &mut RNG,
    ) -> Result<SenderState, Error> {
        // receive cuckoo hash info from sender
        let key = channel.read_block()?;
        let hashes = utils::compress_and_hash_inputs(inputs, key);

        // map inputs to table using all hash functions
        let nbins = channel.read_usize()?;
        let mut table = vec![Vec::new(); nbins];

        for &x in &hashes {
            let mut bins = Vec::with_capacity(NHASHES);
            for h in 0..NHASHES {
                let bin = CuckooHash::bin(x, h, nbins);
                table[bin].push(x ^ Block::from(h as u128));
                bins.push(bin);
            }
            // if j = H1(y) = H2(y) for some y, then P2 adds a uniformly random element to
            // table2[j].
            if bins.iter().skip(1).all(|&x| x == bins[0]) {
                table[bins[0]].push(rng.gen());
            }
        }

        // select the target values
        let ts = (0..nbins).map(|_| rng.gen::<Block512>()).collect_vec();

        let points = table
            .into_iter()
            .zip_eq(ts.iter())
            .flat_map(|(bin, t)| {
                // map all the points in a bin to the same tag
                bin.into_iter().map(move |item| (item, t.clone()))
            })
            .collect_vec();

        let _ = self.opprf.send(channel, &points, nbins, rng)?;

        Ok(SenderState { opprf_outputs: ts })
    }

    /// Set up a Garbler and encode the inputs using the State.
    pub fn compute_setup<C, RNG>(
        channel: &mut C,
        state: &SenderState,
        rng: &mut RNG,
    ) -> Result<(Garbler<C, RNG, OtSender>, Vec<Wire>, Vec<Wire>), Error>
    where
        C: AbstractChannel,
        RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>,
    {
        let mut gb =
            Garbler::<C, RNG, OtSender>::new(channel.clone(), RNG::from_seed(rng.gen()), &[])?;

        let (my_input_bits, mods) = encode_inputs_as_crt(&state.opprf_outputs);
        let sender_inputs = gb.encode_many(&my_input_bits, &mods)?;
        let receiver_inputs = gb.receive_many(&mods)?;

        // println!("garbler inputs: {}\nevaluator inputs: {}", sender_inputs.len(), receiver_inputs.len());
        Ok((gb, sender_inputs, receiver_inputs))
    }

    /// Compute the intersection.
    pub fn compute_intersection<C, RNG>(
        channel: &mut C,
        state: SenderState,
        rng: &mut RNG,
    ) -> Result<(), Error>
    where
        C: AbstractChannel,
        RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>,
    {
        let (mut gb, x, y) = Self::compute_setup(channel, &state, rng)?;
        let outs = fancy_compute_intersection(&mut gb, &x, &y)?;
        gb.outputs(&outs)?;
        Ok(())
    }

    /// Compute the cardinality of the intersection.
    pub fn compute_cardinality<C, RNG>(
        channel: &mut C,
        state: SenderState,
        rng: &mut RNG,
    ) -> Result<(), Error>
    where
        C: AbstractChannel,
        RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>,
    {
        let (mut gb, x, y) = Self::compute_setup(channel, &state, rng)?;
        let (outs, _) = fancy_compute_cardinality(&mut gb, &x, &y)?;
        gb.outputs(&outs)?;
        Ok(())
    }
}

impl Receiver {
    /// Initialize the PSI receiver.
    pub fn init<C: AbstractChannel, RNG: RngCore + CryptoRng + SeedableRng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let opprf = KmprtReceiver::init(channel, rng)?;
        Ok(Self { opprf })
    }

    /// Run the PSI protocol over `inputs`.
    pub fn receive<C: AbstractChannel, RNG: RngCore + CryptoRng + SeedableRng>(
        &mut self,
        channel: &mut C,
        inputs: &[Msg],
        rng: &mut RNG,
    ) -> Result<ReceiverState, Error> {
        let key = rng.gen();
        let hashed_inputs = utils::compress_and_hash_inputs(inputs, key);
        let cuckoo = CuckooHash::new(&hashed_inputs, NHASHES)?;

        // Send cuckoo hash info to receiver.
        channel.write_block(&key)?;
        channel.write_usize(cuckoo.nbins)?;
        channel.flush()?;

        // Build `table` to include a cuckoo hash entry xored with its hash
        // index, if such a entry exists, or a random value.
        let table = cuckoo
            .items
            .iter()
            .map(|opt_item| match opt_item {
                Some(item) => item.entry,
                None => rng.gen(),
            })
            .collect::<Vec<Block>>();

        let opprf_outputs = self.opprf.receive(channel, &table, rng)?;

        Ok(ReceiverState {
            opprf_outputs,
            cuckoo,
            inputs: inputs.to_vec(),
        })
    }

    /// Set up a Evaluator and encode the inputs using the State.
    pub fn compute_setup<C, RNG>(
        channel: &mut C,
        state: &ReceiverState,
        rng: &mut RNG,
    ) -> Result<(Evaluator<C, RNG, OtReceiver>, Vec<Wire>, Vec<Wire>), Error>
    where
        C: AbstractChannel,
        RNG: CryptoRng + RngCore + SeedableRng<Seed = Block>,
    {
        let mut ev =
            Evaluator::<C, RNG, OtReceiver>::new(channel.clone(), RNG::from_seed(rng.gen()))?;

        let (my_input_bits, mods) = encode_inputs_as_crt(&state.opprf_outputs);
        let sender_inputs = ev.receive_many(&mods)?;
        let receiver_inputs = ev.encode_many(&my_input_bits, &mods)?;
        Ok((ev, sender_inputs, receiver_inputs))
    }

    /// Compute the intersection.
    pub fn compute_intersection<C, RNG>(
        channel: &mut C,
        state: ReceiverState,
        rng: &mut RNG,
    ) -> Result<Vec<Msg>, Error>
    where
        C: AbstractChannel,
        RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>,
    {
        let (mut ev, x, y) = Self::compute_setup(channel, &state, rng)?;
        let outs = fancy_compute_intersection(&mut ev, &x, &y)?;
        ev.outputs(&outs)?;
        let mpc_outs = ev.decode_output()?;

        let mut intersection = Vec::new();
        for (opt_item, in_intersection) in state.cuckoo.items.iter().zip_eq(mpc_outs.into_iter()) {
            if let Some(item) = opt_item {
                if in_intersection == 1_u16 {
                    intersection.push(state.inputs[item.input_index].clone());
                }
            }
        }
        Ok(intersection)
    }

    /// Compute the cardinality of the intersection.
    pub fn compute_cardinality<C, RNG>(
        channel: &mut C,
        state: ReceiverState,
        rng: &mut RNG,
    ) -> Result<usize, Error>
    where
        C: AbstractChannel,
        RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>,
    {
        let (mut ev, x, y) = Self::compute_setup(channel, &state, rng)?;
        let (outs, mods) = fancy_compute_cardinality(&mut ev, &x, &y)?;
        ev.outputs(&outs)?;
        let mpc_outs = ev.decode_output()?;
        let cardinality = fancy_garbling::util::crt_inv(&mpc_outs, &mods);
        Ok(cardinality as usize)
    }
}

/// Encode the inputs in CRT, returning the input values as well as the moduli.
fn encode_inputs_as_crt(opprf_outputs: &[Block512]) -> (Vec<u16>, Vec<u16>) {
    let qs = fancy_garbling::util::primes_with_width((HASH_SIZE * 8) as u32);

    let inputs = opprf_outputs
        .iter()
        .flat_map(|blk| {
            let mut val = 0;
            for (i,b) in blk.prefix(HASH_SIZE).iter().enumerate() {
                val ^= (*b as u128) << i*8;
            }
            fancy_garbling::util::crt(val, &qs)
        })
        .collect_vec();

    let mods = itertools::repeat_n(qs, opprf_outputs.len()).flatten().collect_vec();

    debug_assert_eq!(inputs.len(), mods.len());

    (inputs, mods)
}


/// Fancy function to compute the intersection and return encoded vector of 0/1 masks.
fn fancy_compute_intersection<F: Fancy>(
    f: &mut F,
    sender_inputs: &[F::Item],
    receiver_inputs: &[F::Item],
) -> Result<Vec<F::Item>, F::Error> {
    debug_assert_eq!(sender_inputs.len(), receiver_inputs.len());

    let qs = fancy_garbling::util::primes_with_width((HASH_SIZE * 8) as u32);
    let nprimes = qs.len();

    sender_inputs
        .chunks(nprimes)
        .zip_eq(receiver_inputs.chunks(nprimes))
        .map(|(xs, ys)| {
            f.eq_bundles(
                &CrtBundle::new(xs.to_vec()),
                &CrtBundle::new(ys.to_vec()),
            )
        })
        .collect()
}

/// Fancy function to compute the cardinaility and return CRT value containing the result
/// along with the moduli of that value.
fn fancy_compute_cardinality<F: Fancy>(
    f: &mut F,
    sender_inputs: &[F::Item],
    receiver_inputs: &[F::Item],
) -> Result<(Vec<F::Item>, Vec<u16>), F::Error> {
    debug_assert_eq!(sender_inputs.len(), receiver_inputs.len());

    let qs = fancy_garbling::util::primes_with_width((HASH_SIZE * 8) as u32);
    let nprimes = qs.len();

    let eqs = sender_inputs
        .chunks(nprimes)
        .zip_eq(receiver_inputs.chunks(nprimes))
        .map(|(xs, ys)| {
            f.eq_bundles(
                &CrtBundle::new(xs.to_vec()),
                &CrtBundle::new(ys.to_vec()),
            )
        })
        .collect::<Result<Vec<F::Item>, F::Error>>()?;

    // compute sum of equalities
    let qs = fancy_garbling::util::primes_with_width(16);
    let q = fancy_garbling::util::product(&qs);
    let mut acc = f.crt_constant_bundle(0, q)?;
    let one = f.crt_constant_bundle(1, q)?;

    for b in eqs.into_iter() {
        let b_ws = one
            .iter()
            .map(|w| f.mul(w, &b))
            .collect::<Result<Vec<F::Item>, F::Error>>()?;
        let b_crt = CrtBundle::new(b_ws);
        acc = f.crt_add(&acc, &b_crt)?;
    }

    Ok((acc.wires().to_vec(), qs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::rand_vec_vec;
    use scuttlebutt::{AesRng, Channel};
    use std::io::{BufReader, BufWriter};
    use std::os::unix::net::UnixStream;

    const ITEM_SIZE: usize = 8;
    const SET_SIZE: usize = 1 << 6;

    #[test]
    fn full_protocol() {
        let mut rng = AesRng::new();
        let (sender, receiver) = UnixStream::pair().unwrap();
        let sender_inputs = rand_vec_vec(SET_SIZE, ITEM_SIZE, &mut rng);
        let receiver_inputs = sender_inputs.clone();

        std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut psi = Sender::init(&mut channel, &mut rng).unwrap();

            let state = psi.send(&mut channel, &sender_inputs, &mut rng).unwrap();
            Sender::compute_cardinality(&mut channel, state, &mut rng).unwrap();
        });

        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut psi = Receiver::init(&mut channel, &mut rng).unwrap();

        let state = psi
            .receive(&mut channel, &receiver_inputs, &mut rng)
            .unwrap();
        let cardinality = Receiver::compute_cardinality(&mut channel, state, &mut rng).unwrap();

        assert_eq!(cardinality, SET_SIZE);
    }

}
