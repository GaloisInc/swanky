// -*- mode: rust; -*-
//
// This file is part of `popsicle`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Implementation of the Pinkas-Schneider-Tkachenko-Yanai "extended" private
//! set intersection protocol (cf. <https://eprint.iacr.org/2019/241>).

use crate::{cuckoo::CuckooHash, cuckoo::CuckooHashLarge, errors::Error, utils};
use fancy_garbling::{
    twopac::semihonest::{Evaluator, Garbler},
    BinaryBundle,
    Bundle,
    BundleGadgets,
    CrtBundle,
    CrtGadgets,
    Fancy,
    FancyInput,
    Wire,
};
use std::sync::{Arc, Barrier};
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
const PAYLOAD_SIZE: usize = 8;
// How many u16's are used for the CRT representation
const PAYLOAD_PRIME_SIZE: usize = 16;

// How many bytes to use to determine whether decryption succeeded in the send/recv
// payload methods.

/// The type of values in the sender and receiver's sets.
pub type Msg = Vec<u8>;

/// Private set intersection sender.
pub struct MegaBin {
    bins_id: Vec<Block>,
    bins_payload: Vec<usize>,
    mega_index: usize,
    mega_size: usize,
}

/// Private set intersection sender.
pub struct Sender {
    opprf: KmprtSender,
    opprf_payload: KmprtSender,
}

/// State of the sender.
pub struct SenderState {
    opprf_ids: Vec<Block512>,
    opprf_payloads: Vec<Block512>,
    table: Vec<Vec<Block>>,
    payload: Vec<Vec<Block512>>,
}

/// Private set intersection receiver.
pub struct Receiver {
    opprf: KmprtReceiver,
    opprf_payload: KmprtReceiver,
}

// /// State of the receiver.
// pub struct ReceiverState {
//     cuckoo: CuckooHashLarge,
//     table: Vec<Vec<Block>>,
//     payload: Vec<Vec<Block512>>,
// }

/// State of the receiver.
pub struct ReceiverState{
    opprf_ids: Vec<Block512>,
    opprf_payloads: Vec<Block512>,
    table: Vec<Block>,
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

    pub fn compute_payload_large<C: AbstractChannel , RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>>(
        &mut self,
        inputs: &[Msg],
        payloads: &[Block512],
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<(), Error> {
        let key = channel.read_block()?;
        let megasize = channel.read_usize()?;
        let nmegabins = channel.read_usize()?;
        let nbins = channel.read_usize()?;
        let last_bin = nbins % megasize;

        let state = self.bucketize_data(inputs, payloads, nbins, key, rng)?;

        let mut ts_id: Vec<&[Block512]>= state.opprf_ids.chunks(megasize).collect();
        let mut ts_payload: Vec<&[Block512]>= state.opprf_payloads.chunks(megasize).collect();
        let mut table:Vec<&[Vec<Block>]> = state.table.chunks(megasize).collect();
        let mut payload: Vec<&[Vec<Block512>]>= state.payload.chunks(megasize).collect();

        let mut gb = Garbler::<C, RNG, OtSender>::new(channel.clone(), RNG::from_seed(rng.gen()))?;

        let qs = fancy_garbling::util::primes_with_width(PAYLOAD_SIZE as u32 * 8);
        let q = fancy_garbling::util::product(&qs);
        let mut acc = gb.crt_constant_bundle(0, q)?;

        for i in 0..nmegabins{
            let nbins = ts_id[i].len();
            let mut state = SenderState{
                opprf_ids: ts_id[i].to_vec(),
                opprf_payloads: ts_payload[i].to_vec(),
                table: table[i].to_vec(),
                payload: payload[i].to_vec(),
            };

            self.send_data(&mut state, nbins, channel, rng);
            let partial: CrtBundle<fancy_garbling::Wire> = state.build_compute_circuit(&mut gb, channel, rng)?;

            acc = gb.crt_add(&acc, &partial)?;
            channel.flush()?;
        }
        gb.outputs(&acc.wires().to_vec())?;
        println!("sender done");
        Ok(())
    }

    pub fn bucketize_data<RNG: RngCore + CryptoRng + SeedableRng>(
        &mut self,
        inputs: &[Msg],
        payloads: &[Block512],
        nbins: usize,
        key: Block,
        rng: &mut RNG,
    ) -> Result<SenderState,
            Error>{
                // receive cuckoo hash info from sender
       let hashes = utils::compress_and_hash_inputs(inputs, key);
       let total = hashes.len();

       let mut table = vec![Vec::new(); nbins];
       let mut payload = vec![Vec::new(); nbins];

       let ts_id = (0..nbins).map(|_| rng.gen::<Block512>()).collect_vec();
       let ts_payload = (0..nbins).map(|_| rng.gen::<Block512>()).collect_vec();

       for (x, p) in hashes.into_iter().zip_eq(payloads.into_iter()){
           let mut bins = Vec::with_capacity(NHASHES);
           for h in 0..NHASHES {
               let bin = CuckooHash::bin(x, h, nbins);
               table[bin].push(x ^ Block::from(h as u128));
               payload[bin].push(mask_payload_crt(*p, ts_payload[bin], rng));
               bins.push(bin);
           }
           // if j = H1(y) = H2(y) for some y, then P2 adds a uniformly random element to
           // table2[j].
           if bins.iter().skip(1).all(|&x| x == bins[0]) {
               table[bins[0]].push(rng.gen());
               payload[bins[0]].push(rng.gen());
           }
       }

       Ok(SenderState {
           opprf_ids: ts_id,
           opprf_payloads: ts_payload,
           table,
           payload,
       })
    }

    /// Run the PSI protocol over `inputs`.
    pub fn send_data<C: AbstractChannel, RNG: RngCore + CryptoRng + SeedableRng>(
        &mut self,
        state:&mut SenderState,
        nbins: usize,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<(), Error>{

        let points_id = state.table.clone()
            .into_iter()
            .zip_eq(state.opprf_ids.iter())
            .flat_map(|(bin, t)| {
                // map all the points in a bin to the same tag
                bin.into_iter().map(move |item| (item, *t))
            })
            .collect_vec();

        let mut points_data = Vec::new();
        for (row, bin) in state.table.iter().enumerate() {
            for (col, item) in bin.iter().enumerate() {
                points_data.push((*item, state.payload[row][col]));
            }
        }

        self.opprf.send(channel, &points_id, nbins, rng)?;
        self.opprf_payload.send(channel, &points_data, nbins, rng)?;
        Ok(())
    }
}
//
impl SenderState {

    pub fn encode_circuit_inputs<C, RNG>(
        &mut self,
        gb: &mut Garbler<C, RNG, OtSender>,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<(Vec<Wire>, Vec<Wire>, Vec<Wire>, Vec<Wire>, Vec<Wire>), Error>
    where
        C: AbstractChannel,
        RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>,
    {
        let my_input_bits = encode_inputs(&self.opprf_ids);
        let my_payload_bits = encode_payloads(&self.opprf_payloads);

        let mods_bits = vec![2; my_input_bits.len()];
        let sender_inputs = gb.encode_many(&my_input_bits, &mods_bits)?;
        let receiver_inputs = gb.receive_many(&mods_bits)?;

        let qs = fancy_garbling::util::primes_with_width(PAYLOAD_SIZE as u32 * 8);
        let mut mods_crt = Vec::new();
        for _i in 0..self.opprf_payloads.len(){
            mods_crt.append(&mut qs.clone());
        }

        let sender_payloads = gb.encode_many(&my_payload_bits, &mods_crt)?;
        let receiver_payloads = gb.receive_many(&mods_crt)?;
        let receiver_masks = gb.receive_many(&mods_crt)?;

        Ok((sender_inputs, receiver_inputs, sender_payloads, receiver_payloads, receiver_masks))
    }

    pub fn build_compute_circuit<C, RNG>(
        &mut self,
        gb: &mut Garbler<C, RNG, OtSender>,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<CrtBundle<fancy_garbling::Wire>, Error>
    where
        C: AbstractChannel,
        RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>,
    {
        let (x, y, x_payload, y_payload, masks) = self.encode_circuit_inputs(gb, channel, rng)?;
        let outs = fancy_compute_payload_aggregate(gb, &x, &y, &x_payload, &y_payload, &masks)?;
        Ok((outs))
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

        pub fn compute_payload_large<C: AbstractChannel, RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>>(
            &mut self,
            inputs: &[Msg],
            payloads: &[Block512],
            channel: &mut C,
            rng: &mut RNG,
        ) -> Result<(), Error> {
            let key = rng.gen();
            let (cuckoo, table, payload) = self.bucketize_data(inputs, payloads, key, rng)?;
            // Send cuckoo hash info to receiver.
            channel.write_block(&key)?;
            channel.write_usize(cuckoo.megasize)?;
            channel.write_usize(cuckoo.nmegabins)?;
            channel.write_usize(cuckoo.nbins)?;
            channel.flush()?;

            // println!("cuckoo {:?}", cuckoo);
            // // Build `table` to include a cuckoo hash entry xored with its hash
            // // index, if such a entry exists, or a random value.
            // println!("number of mega{:?}", cuckoo.nmegabins);
            let mut ev =
                Evaluator::<C, RNG, OtReceiver>::new(channel.clone(), RNG::from_seed(rng.gen()))?;
            let qs = fancy_garbling::util::primes_with_width(PAYLOAD_SIZE as u32 * 8);
            let q = fancy_garbling::util::product(&qs);
            let mut acc = ev.crt_constant_bundle(0, q)?;

            for i in 0..cuckoo.nmegabins{
                let mut state =  ReceiverState{
                    opprf_ids: Vec::new(),
                    opprf_payloads: Vec::new(),
                    table: table[i].clone(),
                    payload: payload[i].clone(),
                };

                self.receive_data(&mut state, channel, rng);
                let partial: CrtBundle<fancy_garbling::Wire> = state.build_compute_circuit(&mut ev, channel, rng).unwrap();
                acc = ev.crt_add(&acc, &partial)?;
                channel.flush()?;
            }
            let mpc_outs = ev
                .outputs(&acc.wires().to_vec())?
                .expect("evaluator should produce outputs");
            let aggregate = fancy_garbling::util::crt_inv(&mpc_outs, &qs);
            println!("aggregate {:?}", aggregate as usize);
            Ok(())
        }
    pub(crate) fn bucketize_data<RNG: RngCore + CryptoRng + SeedableRng>(
        &mut self,
        inputs: &[Msg],
        payloads: &[Block512],
        key: Block,
        rng: &mut RNG,
    ) -> Result<(CuckooHashLarge, Vec<Vec<Block>>, Vec<Vec<Block512>>), Error>{

        let hashed_inputs = utils::compress_and_hash_inputs(inputs, key);
        let cuckoo_large = CuckooHashLarge::new(&hashed_inputs, NHASHES, 10)?;

        let table = cuckoo_large
                    .items
                    .iter()
                    .map(|cuckoo|
                        cuckoo
                            .items
                            .iter()
                            .map(|opt_item| match opt_item {
                                Some(item) => item.entry,
                                None => rng.gen::<Block>(),
                            })
                            .collect::<Vec<Block>>()).collect();

        let payload = cuckoo_large
                    .items
                    .iter()
                    .map(|cuckoo|
                        cuckoo
                            .items
                            .iter()
                            .map(|opt_item| match opt_item {
                                Some(item) => payloads[item.input_index],
                                None => rng.gen::<Block512>(),
                            })
                            .collect::<Vec<Block512>>()).collect();


        Ok((
            cuckoo_large,
            table,
            payload,
        ))
    }
    // Run the PSI protocol over `inputs`.
    pub(crate) fn receive_data<C: AbstractChannel, RNG: RngCore + CryptoRng + SeedableRng>(
        &mut self,
        state:&mut ReceiverState,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<(), Error>{
        state.opprf_ids = self.opprf.receive(channel, &state.table, rng)?;
        state.opprf_payloads = self.opprf_payload.receive(channel, &state.table, rng)?;
        Ok(())
    }

}
//
impl ReceiverState {

    pub fn encode_circuit_inputs<C, RNG>(
        &mut self,
        ev: &mut Evaluator<C, RNG, OtReceiver>,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<(Vec<Wire>, Vec<Wire>, Vec<Wire>, Vec<Wire>, Vec<Wire>), Error>
    where
        C: AbstractChannel,
        RNG: CryptoRng + RngCore + SeedableRng<Seed = Block>,
    {

        let my_input_bits = encode_inputs(&self.opprf_ids);
        let my_opprf_output = encode_opprf_payload(&self.opprf_payloads);
        let my_payload_bits = encode_payloads(&self.payload);

        let mods_bits = vec![2; my_input_bits.len()];
        let sender_inputs = ev.receive_many(&mods_bits)?;
        let receiver_inputs = ev.encode_many(&my_input_bits, &mods_bits)?;

        let qs = fancy_garbling::util::primes_with_width(PAYLOAD_SIZE as u32 * 8);
        let mut mods_crt = Vec::new();
        for _i in 0..self.payload.len(){
            mods_crt.append(&mut qs.clone());
        }

        let sender_payloads = ev.receive_many(&mods_crt)?;

        let receiver_payloads = ev.encode_many(&my_payload_bits, &mods_crt)?;
        let receiver_masks = ev.encode_many(&my_opprf_output, &mods_crt)?;
        Ok((sender_inputs, receiver_inputs, sender_payloads, receiver_payloads, receiver_masks))
    }

    pub fn build_compute_circuit<C, RNG>(
        &mut self,
        ev: &mut Evaluator<C, RNG, OtReceiver>,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<CrtBundle<fancy_garbling::Wire>, Error>
    where
        C: AbstractChannel,
        RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>,
    {
        channel.flush()?;
        let (x, y, x_payload, y_payload, masks) = self.encode_circuit_inputs(ev, channel, rng)?;

        let outs = fancy_compute_payload_aggregate(ev, &x, &y, &x_payload, &y_payload, &masks)?;
        Ok(outs)
    }
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
) -> Result<CrtBundle<F::Item>, F::Error> {
    println!("reached circuit");
    assert_eq!(sender_inputs.len(), receiver_inputs.len());
    assert_eq!(sender_payloads.len(), receiver_payloads.len());
    assert_eq!(receiver_payloads.len(), receiver_masks.len());

    let qs = fancy_garbling::util::primes_with_width(PAYLOAD_SIZE as u32 * 8);
    let q = fancy_garbling::util::product(&qs);

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
    println!("equality done");
    let reconstructed_payload = sender_payloads
        .chunks(PAYLOAD_PRIME_SIZE)
        .zip_eq(receiver_masks.chunks(PAYLOAD_PRIME_SIZE))
        .map(|(xp, tp)| {
            let b_x = Bundle::new(xp.to_vec());
            let b_t = Bundle::new(tp.to_vec());
            f.crt_sub(
                &CrtBundle::from(b_t),
                &CrtBundle::from(b_x),
            )
        })
        .collect::<Result<Vec<CrtBundle<F::Item>>, F::Error>>()?;

    println!("reconstructed sender payload done");


    let mut weighted_payloads = Vec::new();
    for it in reconstructed_payload.into_iter().zip_eq(receiver_payloads.chunks(PAYLOAD_PRIME_SIZE)){
        let (ps, pr) = it;
        let weighted = f.crt_mul(&ps, &CrtBundle::new(pr.to_vec()))?;
        weighted_payloads.push(weighted);
    }
    //
    //
    println!("weighted payloads done");
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
    println!("done with circuit");
    Ok(acc)
}

fn encode_inputs(opprf_ids: &[Block512]) -> Vec<u16> {
    opprf_ids
        .iter()
        .flat_map(|blk| {
            blk.prefix(HASH_SIZE)
                .iter()
                .flat_map(|byte| (0..8).map(|i| u16::from((byte >> i) & 1_u8)).collect_vec())
        })
        .collect()
}

fn encode_payloads(payload: &[Block512]) -> Vec<u16> {
    let q = fancy_garbling::util::primes_with_width(PAYLOAD_SIZE as u32 * 8);
    payload
        .iter()
        .flat_map(|blk| {
             let b = blk.prefix(PAYLOAD_SIZE);
             let mut b_8 = [0 as u8; 16];
             for i in 0..PAYLOAD_SIZE{
                 b_8[i] = b[i];
             }
             fancy_garbling::util::crt(u128::from_le_bytes(b_8), &q)
        })
        .collect()
}

fn encode_opprf_payload(opprf_ids: &[Block512]) -> Vec<u16> {
let q = fancy_garbling::util::primes_with_width(PAYLOAD_SIZE as u32 * 8);
    opprf_ids
        .iter()
        .flat_map(|blk| {
             let b = blk.prefix(PAYLOAD_PRIME_SIZE);
             let mut b_8 = [0 as u8; 16];
             for i in 0..PAYLOAD_PRIME_SIZE{
                 b_8[i] = b[i];
             }
             fancy_garbling::util::crt(u128::from_le_bytes(b_8), &q)
        })
        .collect()
}


fn mask_payload_crt<RNG>(x: Block512, y: Block512, rng:&mut RNG) -> Block512
                        where RNG: RngCore + CryptoRng{

    let x_crt = block512_to_crt(x);
    let y_crt = block512_to_crt(y);
    let q = fancy_garbling::util::primes_with_width(PAYLOAD_SIZE as u32 * 8);
    let mut res_crt = Vec::new();
    for i in 0..q.len(){
        res_crt.push((x_crt[i]+y_crt[i]) % q[i]);
    }
    let res = fancy_garbling::util::crt_inv(&res_crt, &q).to_le_bytes();
    let mut block = [0 as u8; 64];
    for i in 0..64{
        if i < res.len(){
            block[i] = res[i];
        }else{
            block[i] = rng.gen::<u8>();
        }
    }
    Block512::from(block)
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
