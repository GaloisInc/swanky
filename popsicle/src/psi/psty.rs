// -*- mode: rust; -*-
//
// This file is part of `popsicle`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Implementation of the Pinkas-Schneider-Tkachenko-Yanai "extended" private
//! set intersection protocol (cf. <https://eprint.iacr.org/2019/241>).

use crate::{cuckoo::CuckooHash, errors::Error, utils};
use fancy_garbling::{
    twopac::semihonest::{Evaluator, Garbler},
    BinaryBundle,
    BinaryGadgets,
    Bundle,
    BundleGadgets,
    CrtBundle,
    CrtGadgets,
    Fancy,
    FancyInput,
    Wire,
};
use itertools::Itertools;
use ocelot::{
    oprf::{KmprtReceiver, KmprtSender},
    ot::{AlszReceiver as OtReceiver, AlszSender as OtSender},
};
use openssl::symm::{decrypt, encrypt, Cipher};
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use scuttlebutt::{AbstractChannel, Block, Block512, SemiHonest};

const NHASHES: usize = 3;
// How many bytes of the hash to use for the equality tests. This affects
// correctness, with a lower value increasing the likelihood of a false
// positive.
const HASH_SIZE: usize = 3;

// How many bytes are used for payloads
const PAYLOAD_SIZE: usize = 8;

// How many bytes to use to determine whether decryption succeeded in the send/recv
// payload methods.
const PAD_LEN: usize = 16;

/// The type of values in the sender and receiver's sets.
pub type Msg = Vec<u8>;

/// Private set intersection sender.
pub struct Sender {
    opprf: KmprtSender,
    opprf_payload: KmprtSender,
}

/// State of the sender.
pub struct SenderState {
    opprf_outputs: Vec<Block512>,
    pub opprf_payload_outputs: Vec<Block512>,
    table: Vec<Vec<Block>>,
    mapping: Vec<Vec<usize>>,
    input_size: usize,
}

/// Private set intersection receiver.
pub struct Receiver {
    opprf: KmprtReceiver,
    opprf_payload: KmprtReceiver,
}

/// State of the receiver.
pub struct ReceiverState {
    opprf_outputs: Vec<Block512>,
    pub opprf_payload_outputs: Vec<Block512>,
    table: Vec<Block>,
    cuckoo: CuckooHash,
    inputs: Vec<Msg>,
    input_size: usize,
    payload: Vec<Block512>,
}

impl Sender {
    /// Initialize the PSI sender.
    pub fn init<C: AbstractChannel, RNG: RngCore + CryptoRng + SeedableRng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let opprf = KmprtSender::init(channel, rng)?;
        let opprf_payload = KmprtSender::init(channel, rng)?;

        Ok(Self { opprf, opprf_payload })
    }

    /// Run the PSI protocol over `inputs`.
    pub fn send<C: AbstractChannel, RNG: RngCore + CryptoRng + SeedableRng>(
        &mut self,
        inputs: &[Msg],
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<SenderState, Error> {

        // receive cuckoo hash info from sender
        let key = channel.read_block()?;
        let hashes = utils::compress_and_hash_inputs(inputs, key);
        let total = hashes.len();
        // map inputs to table using all hash functions
        let nbins = channel.read_usize()?;
        let mut table = vec![Vec::new(); nbins];

        // stores how elements are mapped to bin for
        // later use in payload computation
        let mut mapping = vec![Vec::new(); nbins];

        for (index, &x) in hashes.iter().enumerate()  {
            let mut bins = Vec::with_capacity(NHASHES);
            for h in 0..NHASHES {
                let bin = CuckooHash::bin(x, h, nbins);
                table[bin].push(x ^ Block::from(h as u128));
                bins.push(bin);
                mapping[bin].push(index);
            }
            // if j = H1(y) = H2(y) for some y, then P2 adds a uniformly random element to
            // table2[j].
            if bins.iter().skip(1).all(|&x| x == bins[0]) {
                table[bins[0]].push(rng.gen());
                mapping[bins[0]].push(total);
            }
        }

        // select the target values
        let ts = (0..nbins).map(|_| rng.gen::<Block512>()).collect_vec();
        let points = table.clone()
            .into_iter()
            .zip_eq(ts.iter())
            .flat_map(|(bin, t)| {
                // map all the points in a bin to the same tag
                bin.into_iter().map(move |item| (item, *t))
            })
            .collect_vec();

        self.opprf.send(channel, &points, nbins, rng)?;

        Ok(SenderState {
            opprf_outputs: ts,
            opprf_payload_outputs: Vec::new(),
            table,
            mapping,
            input_size: 0,
        })
    }
}

impl SenderState {
    /// Run the setup phase, producing a garbler for the next stage.
    pub fn compute_setup<C, RNG>(
        & self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<(Garbler<C, RNG, OtSender>, Vec<Wire>, Vec<Wire>), Error>
    where
        C: AbstractChannel,
        RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>,
    {
        let mut gb = Garbler::<C, RNG, OtSender>::new(channel.clone(), RNG::from_seed(rng.gen()))?;

        let my_input_bits = encode_inputs(&self.opprf_outputs);

        let mods = vec![2; my_input_bits.len()]; // all binary moduli
        let sender_inputs = gb.encode_many(&my_input_bits, &mods)?;
        let receiver_inputs = gb.receive_many(&mods)?;
        Ok((gb, sender_inputs, receiver_inputs))
    }

    /// Compute the intersection.
    pub fn compute_intersection<C, RNG>(&self, channel: &mut C, rng: &mut RNG) -> Result<(), Error>
    where
        C: AbstractChannel,
        RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>,
    {
        let (mut gb, x, y) = self.compute_setup(channel, rng)?;
        let outs = fancy_compute_intersection(&mut gb, &x, &y)?;
        gb.outputs(&outs)?;
        Ok(())
    }

    /// Compute the cardinality of the intersection.
    pub fn compute_cardinality<C, RNG>(&self, channel: &mut C, rng: &mut RNG) -> Result<(), Error>
    where
        C: AbstractChannel,
        RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>,
    {
        let (mut gb, x, y) = self.compute_setup(channel, rng)?;
        let (outs, _) = fancy_compute_cardinality(&mut gb, &x, &y)?;
        gb.outputs(&outs)?;
        Ok(())
    }

    /// Receive encrypted payloads from the Sender.
    pub fn receive_payloads<C>(
        &self,
        payload_len: usize,
        channel: &mut C,
    ) -> Result<Vec<Vec<u8>>, Error>
    where
        C: AbstractChannel,
    {
        let mut payloads = Vec::new();
        for opprf_output in self.opprf_outputs.iter() {
            let iv = channel.read_vec(16)?;
            let ct = channel.read_vec(payload_len + PAD_LEN)?;
            let key = opprf_output.prefix(16);
            let mut dec = decrypt(Cipher::aes_128_ctr(), key, Some(&iv), &ct)?;
            let payload = dec.split_off(PAD_LEN);
            if dec.into_iter().all(|x| x == 0) {
                payloads.push(payload)
            }
        }
        Ok(payloads)
    }

    pub fn prepare_payload<C, RNG>(
        &mut self,
        sender: &mut Sender,
        payloads: &[Block512],
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<(), Error>
    where
        C: AbstractChannel,
        RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>,
    {
        let nbins = self.mapping.len();

        let mut payload_table = vec![Vec::new(); nbins];
        let ts = (0..nbins).map(|_| rng.gen::<Block512>()).collect_vec();
        let total = payloads.len();

        for (index, bin) in self.mapping.iter().enumerate(){
            for element in bin{
                let payload_byte;
                if *element < total {
                    payload_byte = payloads[*element];
                }else{ // j = H1(y) = H2(y) append a random payload
                    payload_byte = rng.gen::<Block512>();
                }
                let p = payload_byte ^ ts[index];
                payload_table[index].push(p);
            }
        }
        let mut points = Vec::new();
        for (row, bin) in self.table.iter().enumerate() {
            for (col, item) in bin.iter().enumerate() {
                points.push((*item, payload_table[row][col]));
            }
        }
        sender.opprf_payload.send(channel, &points, nbins, rng)?;
        self.opprf_payload_outputs = ts.clone();

        Ok(())
    }

 // todo: figure out how to pre-allocate wires for the receivers payload
 //       the issue being that that depends on the set size
    pub fn compute_payload_setup<C, RNG>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<(Garbler<C, RNG, OtSender>, Vec<Wire>, Vec<Wire>), Error>
    where
        C: AbstractChannel,
        RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>,
    {
        let mut gb = Garbler::<C, RNG, OtSender>::new(channel.clone(), RNG::from_seed(rng.gen()))?;

        let mut my_input_bits = encode_inputs(&self.opprf_outputs);
        let mut my_payload_bits = encode_payloads(&self.opprf_payload_outputs);
        self.input_size = my_input_bits.len();
        let payload_len = my_payload_bits.len();

        my_input_bits.append(&mut my_payload_bits);

        // the receiver inputs 3 thing
        // 1. it's input for the intersection
        // 2. it's payload
        // 3. the opprf's output
        let placeholder = vec![2; self.input_size + 2*payload_len];
        let mods = vec![2; my_input_bits.len()];

        let sender_inputs = gb.encode_many(&my_input_bits, &mods)?;
        let receiver_inputs = gb.receive_many(&placeholder)?;

        Ok((gb, sender_inputs, receiver_inputs))
    }

    /// Compute the intersection.
    pub fn compute_payload_aggregate<C, RNG>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<(), Error>
    where
        C: AbstractChannel,
        RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>,
    {
        let (mut gb, mut x, mut y) = self.compute_payload_setup(channel, rng)?;

        let x_payload = x.split_off(self.input_size);
        let mut y_payload = y.split_off(self.input_size);
        let n = y_payload.len();
        let y_opprf_output= y_payload.split_off(n/2);

        let (outs, _) = fancy_compute_payload_aggregate(&mut gb, &x, &y, &x_payload, &y_payload, &y_opprf_output)?;
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
        let opprf_payload = KmprtReceiver::init(channel, rng)?;

        Ok(Self { opprf, opprf_payload })}

    /// Run the PSI protocol over `inputs`.
    pub fn receive<C: AbstractChannel, RNG: RngCore + CryptoRng + SeedableRng>(
        &mut self,
        inputs: &[Msg],
        channel: &mut C,
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
            opprf_payload_outputs:Vec::new(),
            table,
            cuckoo,
            inputs: inputs.to_vec(),
            input_size: 0,
            payload: Vec::new(),
        })
    }
}

impl ReceiverState {
    /// Run the setup phase, producing an evaluator for the next stage.
    pub fn compute_setup<C, RNG>(
        &self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<(Evaluator<C, RNG, OtReceiver>, Vec<Wire>, Vec<Wire>), Error>
    where
        C: AbstractChannel,
        RNG: CryptoRng + RngCore + SeedableRng<Seed = Block>,
    {
        let nbins = self.cuckoo.nbins;
        let my_input_bits = encode_inputs(&self.opprf_outputs);

        let mut ev =
            Evaluator::<C, RNG, OtReceiver>::new(channel.clone(), RNG::from_seed(rng.gen()))?;

        let mods = vec![2; nbins * HASH_SIZE * 8];
        let sender_inputs = ev.receive_many(&mods)?;
        let receiver_inputs = ev.encode_many(&my_input_bits, &mods)?;
        Ok((ev, sender_inputs, receiver_inputs))
    }

    /// Compute the intersection.
    pub fn compute_intersection<C, RNG>(
        &self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Vec<Msg>, Error>
    where
        C: AbstractChannel,
        RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>,
    {
        let (mut ev, x, y) = self.compute_setup(channel, rng)?;
        let outs = fancy_compute_intersection(&mut ev, &x, &y)?;
        let mpc_outs = ev
            .outputs(&outs)?
            .expect("evaluator should produce outputs");

        let mut intersection = Vec::new();
        for (opt_item, in_intersection) in self.cuckoo.items.iter().zip_eq(mpc_outs.into_iter()) {
            if let Some(item) = opt_item {
                if in_intersection == 1_u16 {
                    intersection.push(self.inputs[item.input_index].clone());
                }
            }
        }
        Ok(intersection)
    }

    /// Compute the cardinality of the intersection.
    pub fn compute_cardinality<C, RNG>(
        &self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<usize, Error>
    where
        C: AbstractChannel,
        RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>,
    {
        let (mut ev, x, y) = self.compute_setup(channel, rng)?;
        let (outs, mods) = fancy_compute_cardinality(&mut ev, &x, &y)?;
        let mpc_outs = ev
            .outputs(&outs)?
            .expect("evaluator should produce outputs");

        let cardinality = fancy_garbling::util::crt_inv(&mpc_outs, &mods);
        Ok(cardinality as usize)
    }

    /// Send encrypted payloads to the Receiver, who can only decrypt a payload if they
    /// share the associated element in the intersection.
    pub fn send_payloads<C, RNG>(
        &self,
        payloads: &[Vec<u8>],
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<(), Error>
    where
        C: AbstractChannel,
        RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>,
    {
        let payload_len = payloads[0].len();
        if !(payloads.iter().all(|p| p.len() == payload_len)) {
            return Err(Error::InvalidPayloadsLength);
        }
        let dummy_payload = vec![0; payload_len];

        for (opt_item, opprf_output) in self.cuckoo.items.iter().zip_eq(self.opprf_outputs.iter()) {
            let mut payload = vec![0; PAD_LEN];
            if let Some(item) = opt_item {
                if item.input_index >= payloads.len() {
                    return Err(Error::InvalidPayloadsLength);
                }
                payload.extend_from_slice(&payloads[item.input_index]);
            } else {
                payload.extend_from_slice(&dummy_payload);
            };
            let iv: [u8; 16] = rng.gen();
            let key = opprf_output.prefix(16);
            let ct = encrypt(Cipher::aes_128_ctr(), &key, Some(&iv), &payload)?;
            channel.write_bytes(&iv)?;
            channel.write_bytes(&ct)?;
        }
        channel.flush()?;
        Ok(())
    }

    // prepare the enviornment for payload computation seperately
    pub fn prepare_payload<C, RNG>(
        &mut self,
        receiver: &mut Receiver,
        payloads: &[Block512],
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<(), Error>
    where
        C: AbstractChannel,
        RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>,
    {
        self.opprf_payload_outputs = receiver.opprf_payload.receive(channel, &self.table, rng)?;

        self.payload = self.cuckoo
                            .items
                            .iter()
                            .map(|opt_item| match opt_item {
                                Some(item) => payloads[item.input_index],
                                None => rng.gen::<Block512>(),
                            })

                            .collect::<Vec<Block512>>();

        Ok(())
    }

    pub fn compute_payload_setup<C, RNG>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<(Evaluator<C, RNG, OtReceiver>, Vec<Wire>, Vec<Wire>), Error>
    where
        C: AbstractChannel,
        RNG: CryptoRng + RngCore + SeedableRng<Seed = Block>,
    {

        let mut my_input_bits = encode_inputs(&self.opprf_outputs);
        let mut my_opprf_output = encode_payloads(&self.opprf_payload_outputs);
        let mut my_payload_bits = encode_payloads(&self.payload);

        self.input_size = my_input_bits.len();
        let payload_len = my_payload_bits.len();

        my_input_bits.append(&mut my_payload_bits);
        my_input_bits.append(&mut my_opprf_output);

        let mut ev =
            Evaluator::<C, RNG, OtReceiver>::new(channel.clone(), RNG::from_seed(rng.gen()))?;

        let placeholder = vec![2; self.input_size + payload_len];
        let mods = vec![2; my_input_bits.len()];

        let sender_inputs = ev.receive_many(&placeholder)?;
        let receiver_inputs = ev.encode_many(&my_input_bits, &mods)?;


        Ok((ev, sender_inputs, receiver_inputs))
    }

    pub fn compute_payload_aggregate<C, RNG>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<usize, Error>
    where
        C: AbstractChannel,
        RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>,
    {

        let (mut ev, mut x, mut y) = self.compute_payload_setup(channel, rng)?;

        let x_payload = x.split_off(self.input_size);
        let mut y_payload = y.split_off(self.input_size);
        let n = y_payload.len();
        let y_opprf_output= y_payload.split_off(n/2);

        let (outs, _) = fancy_compute_payload_aggregate(&mut ev, &x, &y, &x_payload, &y_payload, &y_opprf_output)?;
        let mpc_outs = ev
            .outputs(&outs)?
            .expect("evaluator should produce outputs");
        let aggregate = fancy_garbling::util::u128_from_bits(&mpc_outs);
        Ok(aggregate as usize)
    }
}

fn encode_inputs(opprf_outputs: &[Block512]) -> Vec<u16> {
    opprf_outputs
        .iter()
        .flat_map(|blk| {
            blk.prefix(HASH_SIZE)
                .iter()
                .flat_map(|byte| (0..8).map(|i| u16::from((byte >> i) & 1_u8)).collect_vec())
        })
        .collect()
}

fn encode_payloads(opprf_outputs: &[Block512]) -> Vec<u16> {
    opprf_outputs
        .iter()
        .flat_map(|blk| {
            blk.prefix(PAYLOAD_SIZE)
            .iter()
            .flat_map(|byte| (0..8).map(|i| u16::from((byte >> i) & 1_u8)).collect_vec())
        })
        .collect()
}

/// Fancy function to compute the intersection and return encoded vector of 0/1 masks.
fn fancy_compute_intersection<F: Fancy>(
    f: &mut F,
    sender_inputs: &[F::Item],
    receiver_inputs: &[F::Item],
) -> Result<Vec<F::Item>, F::Error> {
    assert_eq!(sender_inputs.len(), receiver_inputs.len());
    sender_inputs
        .chunks(HASH_SIZE * 8)
        .zip_eq(receiver_inputs.chunks(HASH_SIZE * 8))
        .map(|(xs, ys)| {
            f.eq_bundles(
                &BinaryBundle::new(xs.to_vec()),
                &BinaryBundle::new(ys.to_vec()),
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
) -> Result< (Vec<F::Item>, Vec<u16>), F::Error> {
    assert_eq!(sender_inputs.len(), receiver_inputs.len());

    let eqs = sender_inputs
        .chunks(HASH_SIZE * 8)
        .zip_eq(receiver_inputs.chunks(HASH_SIZE * 8))
        .map(|(xs, ys)| {
            f.eq_bundles(
                &BinaryBundle::new(xs.to_vec()),
                &BinaryBundle::new(ys.to_vec()),
            )
        })
        .collect::<Result<Vec<F::Item>, F::Error>>()?;

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

/// Fancy function to compute a weighted average
/// where one party provides the weights and the other
//  the values
fn fancy_compute_payload_aggregate<F: Fancy>(
    f: &mut F,
    sender_inputs: &[F::Item],
    receiver_inputs: &[F::Item],
    sender_payloads: &[F::Item],
    receiver_payloads: &[F::Item],
    receiver_opprf_output: &[F::Item],
) -> Result<(Vec<F::Item>, Vec<u16>), F::Error> {

    assert_eq!(sender_inputs.len(), receiver_inputs.len());
    assert_eq!(sender_payloads.len(), receiver_opprf_output.len());

    assert_eq!(sender_inputs.len(), receiver_inputs.len());
    assert_eq!(sender_payloads.len(), receiver_opprf_output.len());

    let qs = fancy_garbling::util::primes_with_width(8);

    let eqs = sender_inputs
        .chunks(HASH_SIZE * 8)
        .zip_eq(receiver_inputs.chunks(HASH_SIZE * 8))
        .map(|(xs, ys)| {
            f.eq_bundles(
                &BinaryBundle::new(xs.to_vec()),
                &BinaryBundle::new(ys.to_vec()),
            )
        })
        .collect::<Result<Vec<F::Item>, F::Error>>()?;

    let reconstructed_payload = sender_payloads
        .chunks(PAYLOAD_SIZE * 8)
        .zip_eq(receiver_opprf_output.chunks(PAYLOAD_SIZE * 8))
        .map(|(xp, tp)| {
            f.add_bundles(
                &BinaryBundle::new(xp.to_vec()),
                &BinaryBundle::new(tp.to_vec()),
            )
        })
        .collect::<Result<Vec<Bundle<F::Item>>, F::Error>>()?;

    let mut weighted_payloads = Vec::new();
    for it in reconstructed_payload.into_iter().zip_eq(receiver_payloads.chunks(PAYLOAD_SIZE * 8)){
        let (ps, pr) = it;
        let ps_crt = &BinaryBundle::from(ps);
        let pr_crt = &BinaryBundle::new(pr.to_vec());

        let weighted = f.bin_multiplication_lower_half(&ps_crt, &pr_crt)?;
        weighted_payloads.push(weighted);
    }

    assert_eq!(weighted_payloads.len(), eqs.len());

    let mut acc = BinaryBundle::from(f.mask(&eqs[0], &weighted_payloads[0])?);
    for (i, b) in eqs.iter().enumerate(){
        if i > 0 {
            let mut mux = BinaryBundle::from(f.mask(&b, &weighted_payloads[i])?);

            if mux.moduli().len() != acc.moduli().len() {
                let pad_len = acc.moduli().len() - mux.moduli().len();
                let mut w = mux.extract();
                let zero = f.constant(0, 2)?;
                w.pad(&zero, pad_len);
                mux = BinaryBundle::from(w);
            }
            acc = f.bin_addition_no_carry(&acc, &mux)?;
        }
    }

    Ok((acc.wires().to_vec(), qs))
}

impl SemiHonest for Sender {}
impl SemiHonest for Receiver {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::rand_vec_vec;
    use scuttlebutt::{AesRng, Channel};
    use std::{
        io::{BufReader, BufWriter},
        os::unix::net::UnixStream,
    };

    const ITEM_SIZE: usize = 8;
    const SET_SIZE: usize = 1 << 8;

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

            let state = psi.send(&sender_inputs, &mut channel, &mut rng).unwrap();
            state.compute_cardinality(&mut channel, &mut rng).unwrap();
        });

        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut psi = Receiver::init(&mut channel, &mut rng).unwrap();

        let state = psi
            .receive(&receiver_inputs, &mut channel, &mut rng)
            .unwrap();
        let cardinality = state.compute_cardinality(&mut channel, &mut rng).unwrap();

        assert_eq!(cardinality, SET_SIZE);
    }

    #[test]
    fn payloads() {
        let payload_size = 16;

        let mut rng = AesRng::new();
        let (sender, receiver) = UnixStream::pair().unwrap();
        let sender_inputs = rand_vec_vec(SET_SIZE, ITEM_SIZE, &mut rng);
        let receiver_inputs = sender_inputs.clone();
        let payloads = rand_vec_vec(SET_SIZE, payload_size, &mut rng);

        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut psi = Sender::init(&mut channel, &mut rng).unwrap();
            let state = psi.send(&sender_inputs, &mut channel, &mut rng).unwrap();
            state.receive_payloads(payload_size, &mut channel).unwrap()
        });

        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut psi = Receiver::init(&mut channel, &mut rng).unwrap();

        let state = psi
            .receive(&receiver_inputs, &mut channel, &mut rng)
            .unwrap();
        state
            .send_payloads(&payloads, &mut channel, &mut rng)
            .unwrap();

        let received_payloads = handle.join().unwrap();

        for payload in payloads.iter() {
            assert!(received_payloads.contains(payload));
        }
    }
}
