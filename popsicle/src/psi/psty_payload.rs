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

use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use scuttlebutt::{AbstractChannel, Block, Block512};

const NHASHES: usize = 3;
// How many bytes of the hash to use for the equality tests. This affects
// correctness, with a lower value increasing the likelihood of a false
// positive.
const HASH_SIZE: usize = 3;

// How many bytes are used for payloads
const PAYLOAD_SIZE: usize = 2;
// How many u16's are used for the CRT representation
const PAYLOAD_PRIME_SIZE: usize = 7;

// Upper bound on the number of bytes allocated for the payload
// computation's output
const OUTPUT_SIZE: usize = PAYLOAD_SIZE*2;
// How many u16's  are used for the CRT representation
const OUTPUT_PRIME_SIZE: usize = 10;

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

                let p = mask_payload_crt(payload_byte, ts[index]);

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

        self.opprf_payload_outputs = ts.into_iter()
                                        .map(|x| crt_to_block512(block512_to_crt(x))).collect_vec();

        Ok(())
    }

 // todo: figure out how to pre-allocate wires for the receivers payload
 //       the issue being that that depends on the set size
    pub fn compute_payload_setup<C, RNG>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<(Garbler<C, RNG, OtSender>, Vec<Wire>, Vec<Wire>, Vec<Wire>, Vec<Wire>, Vec<Wire>), Error>
    where
        C: AbstractChannel,
        RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>,
    {
        let mut gb = Garbler::<C, RNG, OtSender>::new(channel.clone(), RNG::from_seed(rng.gen()))?;

        let mut my_input_bits = encode_inputs(&self.opprf_outputs);
        let mut my_payload_bits = encode_payloads(&self.opprf_payload_outputs);

        let mods_bits = vec![2; my_input_bits.len()];

        let sender_inputs = gb.encode_many(&my_input_bits, &mods_bits)?;
        let receiver_inputs = gb.receive_many(&mods_bits)?;

        let qs = fancy_garbling::util::primes_with_width(OUTPUT_SIZE as u32 * 8);
        let mut mods_crt = Vec::new();
        for i in 0..self.opprf_payload_outputs.len(){
            mods_crt.append(&mut qs.clone());
        }

        let sender_payloads = gb.encode_many(&my_payload_bits, &mods_crt)?;
        let receiver_payloads = gb.receive_many(&mods_crt)?;
        let receiver_masks = gb.receive_many(&mods_crt)?;


        Ok((gb, sender_inputs, receiver_inputs, sender_payloads, receiver_payloads, receiver_masks))
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
        let (mut gb, x, y, x_payload, y_payload, masks) = self.compute_payload_setup(channel, rng)?;
        let (outs, _) = fancy_compute_payload_aggregate(&mut gb, &x, &y, &x_payload, &y_payload, &masks)?;
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
            input_size: 0,
            payload: Vec::new(),
        })
    }
}

impl ReceiverState {

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
                                Some(item) => { let b = block512_to_crt(payloads[item.input_index]);
                                    let q = fancy_garbling::util::primes_with_width(PAYLOAD_SIZE as u32 * 8);
                                    crt_to_block512(b)
                                    },
                                None => {rng.gen::<Block512>()},
                            })

                            .collect::<Vec<Block512>>();

        Ok(())
    }

    pub fn compute_payload_setup<C, RNG>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<(Evaluator<C, RNG, OtReceiver>, Vec<Wire>, Vec<Wire>, Vec<Wire>, Vec<Wire>, Vec<Wire>), Error>
    where
        C: AbstractChannel,
        RNG: CryptoRng + RngCore + SeedableRng<Seed = Block>,
    {

        let mut my_input_bits = encode_inputs(&self.opprf_outputs);
        let mut my_opprf_output = encode_payloads(&self.opprf_payload_outputs);
        let mut my_payload_bits = encode_payloads(&self.payload);

        let mut ev =
            Evaluator::<C, RNG, OtReceiver>::new(channel.clone(), RNG::from_seed(rng.gen()))?;

        let mods_bits = vec![2; my_input_bits.len()];
        let sender_inputs = ev.receive_many(&mods_bits)?;
        let receiver_inputs = ev.encode_many(&my_input_bits, &mods_bits)?;

        let qs = fancy_garbling::util::primes_with_width(OUTPUT_SIZE as u32 * 8);
        let mut mods_crt = Vec::new();
        for i in 0..self.payload.len(){
            mods_crt.append(&mut qs.clone());
        }
        let sender_payloads = ev.receive_many(&mods_crt)?;
        let receiver_payloads = ev.encode_many(&my_payload_bits, &mods_crt)?;
        let receiver_masks = ev.encode_many(&my_opprf_output, &mods_crt)?;

        Ok((ev, sender_inputs, receiver_inputs, sender_payloads, receiver_payloads, receiver_masks))
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
        let (mut ev, x, y, x_payload, y_payload, masks) = self.compute_payload_setup(channel, rng)?;
        let (outs, mods) = fancy_compute_payload_aggregate(&mut ev, &x, &y, &x_payload, &y_payload, &masks)?;
        let mpc_outs = ev
            .outputs(&outs)?
            .expect("evaluator should produce outputs");
        let aggregate = fancy_garbling::util::crt_inv(&mpc_outs, &mods);
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
             let mut b = blk.prefix(PAYLOAD_PRIME_SIZE*2);
             let mut b_16 =  vec![0 as u16; OUTPUT_PRIME_SIZE];
             for i in 0..b.len()/2{
                 b_16[i] = u16::from_le_bytes([b[2*i], b[2*i+1]]);
             }
             b_16
        })
        .collect()
}

fn block512_to_crt(b: Block512) -> Vec<u16>{
    let b_val = b.prefix(PAYLOAD_SIZE);

    let mut b_128 = [0 as u8; 16];
    for i in 0..PAYLOAD_SIZE{
        b_128[i] = b_val[i];
    }

    let q = fancy_garbling::util::primes_with_width(PAYLOAD_SIZE as u32 * 8);
    let b_crt = fancy_garbling::util::crt(u128::from_le_bytes(b_128), &q);
    b_crt
}

fn crt_to_block512(c: Vec<u16>) -> Block512{
    let mut block = [0 as u8; 64];
    for i in 0..c.len(){
        let b = c[i].to_le_bytes();
        block[2*i] = b[0];
        block[2*i + 1] = b[1];
    }
    Block512::from(block)
}

fn mask_payload_crt(x: Block512, y: Block512) -> Block512{

    let x_crt = block512_to_crt(x);
    let y_crt = block512_to_crt(y);
    let q = fancy_garbling::util::primes_with_width(PAYLOAD_SIZE as u32 * 8);
    let mut res = Vec::new();
    for i in 0..q.len(){
        res.push((x_crt[i]+y_crt[i]) % q[i]);
    }
    crt_to_block512(res)
}

/// Fancy function to compute a weighted average
/// where one party provides the weights and the other
//  the values
fn fancy_compute_payload_aggregate<F: fancy_garbling::FancyReveal + Fancy>(
    f: &mut F,
    sender_inputs: &[F::Item],
    receiver_inputs: &[F::Item],
    sender_payloads:&[F::Item],
    receiver_payloads: &[F::Item],
    receiver_masks: &[F::Item],
) -> Result<(Vec<F::Item>, Vec<u16>), F::Error> {

    assert_eq!(sender_inputs.len(), receiver_inputs.len());
    assert_eq!(sender_payloads.len(), receiver_payloads.len());
    assert_eq!(receiver_payloads.len(), receiver_masks.len());

    let qs = fancy_garbling::util::primes_with_width(OUTPUT_SIZE as u32 * 8);
    let q = fancy_garbling::util::product(&qs);
    println!("qs {:?}", qs);
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
        .chunks(OUTPUT_PRIME_SIZE)
        .zip_eq(receiver_masks.chunks(OUTPUT_PRIME_SIZE))
        .map(|(xp, tp)| {
            f.crt_sub(
                &CrtBundle::new(xp.to_vec()),
                &CrtBundle::new(tp.to_vec()),
            )
        })
        .collect::<Result<Vec<CrtBundle<F::Item>>, F::Error>>()?;
    let a = f.crt_reveal(&reconstructed_payload[0])?;

    let mut weighted_payloads = Vec::new();
    for it in reconstructed_payload.into_iter().zip_eq(receiver_payloads.chunks(OUTPUT_PRIME_SIZE)){
        let (ps, pr) = it;
        let weighted = f.crt_mul(&ps, &CrtBundle::new(pr.to_vec()))?;
        weighted_payloads.push(weighted);
    }
    //
    //
    assert_eq!(eqs.len(), weighted_payloads.len());

    let mut acc = f.crt_constant_bundle(0, q)?;
    let one = f.crt_constant_bundle(1, q)?;
    for (i, b) in eqs.iter().enumerate(){
        let b_ws = one
            .iter()
            .map(|w| f.mul(w, &b))
            .collect::<Result<Vec<F::Item>, F::Error>>()?;
        let b_crt = CrtBundle::new(b_ws);
        let mux = f.crt_mul(&b_crt, &weighted_payloads[i])?;
        acc = f.crt_add(&acc, &mux)?;
    }

    Ok((acc.wires().to_vec(), qs))
}
