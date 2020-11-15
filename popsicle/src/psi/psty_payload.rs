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

use itertools::Itertools;
use ocelot::{
    oprf::{KmprtReceiver, KmprtSender},
    ot::{AlszReceiver as OtReceiver, AlszSender as OtSender},
};

use std::time::SystemTime;
use std::process::{exit};
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use scuttlebutt::{AbstractChannel, Block, Block512};

use serde_json;


const NHASHES: usize = 3;
// How many bytes of the hash to use for the equality tests. This affects
// correctness, with a lower value increasing the likelihood of a false
// positive.
const HASH_SIZE: usize = 4;

// How many bytes are used for payloads
const PAYLOAD_SIZE: usize = 8;
// How many u16's are used for the CRT representation
const PAYLOAD_PRIME_SIZE: usize = 16;

// How many bytes to use to determine whether decryption succeeded in the send/recv
// payload methods.

/// The type of values in the sender and receiver's sets.
pub type Msg = Vec<u8>;

/// Private set intersection sender.
pub struct Sender {
    key: Block,
    opprf: KmprtSender,
    opprf_payload: KmprtSender,
}

/// State of the sender.
pub struct SenderState {
    pub opprf_ids: Vec<Block512>,
    pub opprf_payloads: Vec<Block512>,
    pub table: Vec<Vec<Block>>,
    pub payload: Vec<Vec<Block512>>,
}

/// Private set intersection receiver.
pub struct Receiver {
    key: Block,
    opprf: KmprtReceiver,
    opprf_payload: KmprtReceiver,
}


/// State of the receiver.
pub struct ReceiverState{
    pub opprf_ids: Vec<Block512>,
    pub opprf_payloads: Vec<Block512>,
    pub table: Vec<Block>,
    pub payload: Vec<Block512>,
}


impl Sender {
    /// Initialize the PSI sender.
    pub fn init<C: AbstractChannel, RNG: RngCore + CryptoRng + SeedableRng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        println!("yo01");
        let key = channel.read_block()?;
        println!("yo31");
        let opprf = KmprtSender::init(channel, rng)?;
        println!("yo21");
        let opprf_payload = KmprtSender::init(channel, rng)?;
        Ok(Self { key, opprf, opprf_payload })
    }

    pub fn full_protocol<C: AbstractChannel , RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>>(
        &mut self,
        table: &[Msg],
        payloads: &[Block512],
        channel: &mut C,
        rng: &mut RNG,
    )-> Result<(), Error> {
        let mut gb = Garbler::<C, RNG, OtSender>::new(channel.clone(), RNG::from_seed(rng.gen())).unwrap();

        let qs = fancy_garbling::util::primes_with_width(PAYLOAD_SIZE as u32 * 8);
        let q = fancy_garbling::util::product(&qs);

        let deltas = utils::generate_deltas(&qs);
        let deltas_json = serde_json::to_string(&deltas).unwrap();
        let _ = gb.load_deltas(&deltas_json);

        let (mut state, nbins, _, _) = self.bucketize_data(table, payloads, channel, rng)?;

        self.send_data(&mut state, nbins, channel, rng)?;
        let aggregate = state.build_and_compute_circuit(&mut gb).unwrap();

        gb.outputs(&aggregate.wires().to_vec()).unwrap();
        channel.flush()?;

        Ok(())
    }

    pub fn full_protocol_large<C: AbstractChannel , RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>>(
        &mut self,
        table: &[Msg],
        payloads: &[Block512],
        path_deltas: &str,
        channel: &mut C,
        rng: &mut RNG,
    )-> Result<(), Error> {
        let mut gb = Garbler::<C, RNG, OtSender>::new(channel.clone(), RNG::from_seed(rng.gen())).unwrap();
        let _ = gb.load_deltas(path_deltas);

        let (mut state, nbins, nmegabins, megasize) = self.bucketize_data(table, payloads, channel, rng)?;

        let ts_id: Vec<Vec<Block512>>= state.opprf_ids.chunks(megasize).map(|x| x.to_vec()).collect();
        let ts_payload: Vec<Vec<Block512>>= state.opprf_payloads.chunks(megasize).map(|x| x.to_vec()).collect();
        let table:Vec<Vec<Vec<Block>>> = state.table.chunks(megasize).map(|x| x.to_vec()).collect();
        let payload: Vec<Vec<Vec<Block512>>>= state.payload.chunks(megasize).map(|x| x.to_vec()).collect();

        let aggregate = self.compute_payload(ts_id, ts_payload, table, payload, &path_deltas, channel, rng).unwrap();

        gb.outputs(&aggregate.wires().to_vec()).unwrap();
        Ok(())
    }

    // PSI computation designed sepecifically for very large sets. Assumes the bucketization stage
    // has already been done, bins were seperated into megabins and that deltas for the circuit
    // were precomputed.
    // Returns a garbled output over given megabins that the user can open or join with other
    // threads results using compute_aggregate.
    pub fn compute_payload<C: AbstractChannel , RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>>(
        &mut self,
        ts_id: Vec<Vec<Block512>>,
        ts_payload: Vec<Vec<Block512>>,
        table: Vec<Vec<Vec<Block>>>,
        payload: Vec<Vec<Vec<Block512>>>,
        path_deltas: &str,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<CrtBundle<fancy_garbling::Wire>, Error> {
        let mut gb = Garbler::<C, RNG, OtSender>::new(channel.clone(), RNG::from_seed(rng.gen())).unwrap();
        let _ = gb.load_deltas(path_deltas);

        let qs = fancy_garbling::util::primes_with_width(PAYLOAD_SIZE as u32 * 8);
        let q = fancy_garbling::util::product(&qs);

        let mut acc = gb.crt_constant_bundle(0, q).unwrap();
        let nmegabins = ts_id.len();
        for i in 0..nmegabins{
            let start = SystemTime::now();
            println!("Starting megabin number:{}", i);
            let nbins = ts_id[i].len();
            let mut state = SenderState {
                opprf_ids: ts_id[i].clone(),
                opprf_payloads: ts_payload[i].clone(),
                table: table[i].clone(),
                payload: payload[i].clone(),
            };

            self.send_data(&mut state, nbins, channel, rng)?;
            let partial: CrtBundle<fancy_garbling::Wire> = state.build_and_compute_circuit(&mut gb).unwrap();

            acc = gb.crt_add(&acc, &partial).unwrap();

            println!(
                "Sender :: Computation time: {} ms",
                start.elapsed().unwrap().as_millis()
            );
            gb.outputs(&acc.wires().to_vec()).unwrap();
            channel.flush()?;
        }
        println!("sender done");
        Ok(acc)
    }

    // Aggregates partial grabled outputs encoded as CRTs. Uses the same deltas used by partial
    // circuits.
    pub fn compute_aggregates<C: AbstractChannel , RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>>(
        &mut self,
        aggregates: Vec<Vec<Wire>>,
        path_deltas: &str,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<(), Error> {
        let mut gb = Garbler::<C, RNG, OtSender>::new(channel.clone(), RNG::from_seed(rng.gen())).unwrap();
        let _ = gb.load_deltas(path_deltas);

        let mut acc = CrtBundle::new(aggregates[0].clone());
        for i in 1..aggregates.len(){
            let partial = CrtBundle::new(aggregates[i].clone());
            acc = gb.crt_add(&acc, &partial).unwrap();
        }
        gb.outputs(&acc.wires().to_vec()).unwrap();
        Ok(())
    }

    // Bucketizes data according to the number of bins specified by the Receiver
    pub fn bucketize_data<C: AbstractChannel, RNG: RngCore + CryptoRng + SeedableRng>(
        &mut self,
        inputs: &[Msg],
        payloads: &[Block512],
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<(SenderState, usize, usize, usize),
            Error>{
                // receive cuckoo hash info from sender
       let megasize = channel.read_usize()?;
       let nmegabins = channel.read_usize()?;
       let nbins = channel.read_usize()?;
       let hashes = utils::compress_and_hash_inputs(inputs, self.key);

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
       println!("done bucketizing");
       let state = SenderState {
                   opprf_ids: ts_id,
                   opprf_payloads: ts_payload,
                   table,
                   payload,
               };

       Ok((state,
        nbins,
        nmegabins,
        megasize))
    }

    /// Perform OPPRF on ID's & associated payloads
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

    // Encodes circuit inputs as CRT
    pub fn encode_circuit_inputs<C, RNG>(
        &mut self,
        gb: &mut Garbler<C, RNG, OtSender>,
    ) -> Result<(Vec<Wire>, Vec<Wire>, Vec<Wire>, Vec<Wire>, Vec<Wire>), Error>
    where
        C: AbstractChannel,
        RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>,
    {
        let my_input_bits = encode_inputs(&self.opprf_ids);
        let my_payload_bits = encode_payloads(&self.opprf_payloads);

        let mods_bits = vec![2; my_input_bits.len()];
        let sender_inputs = gb.encode_many(&my_input_bits, &mods_bits).unwrap();
        let receiver_inputs = gb.receive_many(&mods_bits).unwrap();

        let qs = fancy_garbling::util::primes_with_width(PAYLOAD_SIZE as u32 * 8);
        let mut mods_crt = Vec::new();
        for _i in 0..self.opprf_payloads.len(){
            mods_crt.append(&mut qs.clone());
        }

        let sender_payloads = gb.encode_many(&my_payload_bits, &mods_crt).unwrap();
        let receiver_payloads = gb.receive_many(&mods_crt).unwrap();
        let receiver_masks = gb.receive_many(&mods_crt).unwrap();

        Ok((sender_inputs, receiver_inputs, sender_payloads, receiver_payloads, receiver_masks))
    }

    //Encode inputs & compute weighted aggregates circuit
    pub fn build_and_compute_circuit<C, RNG>(
        &mut self,
        gb: &mut Garbler<C, RNG, OtSender>,
    ) -> Result<CrtBundle<fancy_garbling::Wire>, Error>
    where
        C: AbstractChannel,
        RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>,
    {
        let (x, y, x_payload, y_payload, masks) = self.encode_circuit_inputs(gb).unwrap();
        let outs = fancy_compute_payload_aggregate(gb, &x, &y, &x_payload, &y_payload, &masks).unwrap();
        Ok(outs)
    }
}

impl Receiver {
    /// Initialize the PSI receiver.
    pub fn init<C: AbstractChannel, RNG: RngCore + CryptoRng + SeedableRng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        println!("yorx0");
        let key = rng.gen();
        channel.write_block(&key)?;
        println!("yorx");
        let opprf = KmprtReceiver::init(channel, rng)?;
        println!("yorx1");
        let opprf_payload = KmprtReceiver::init(channel, rng)?;
        println!("hala");
        Ok(Self { key, opprf, opprf_payload })
    }

    pub fn full_protocol<C: AbstractChannel, RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>>(
        &mut self,
        table: &[Msg],
        payloads: &[Block512],
        channel: &mut C,
        rng: &mut RNG,
    )-> Result<u64, Error> {
        let mut ev =
            Evaluator::<C, RNG, OtReceiver>::new(channel.clone(), RNG::from_seed(rng.gen())).unwrap();
        let qs = fancy_garbling::util::primes_with_width(PAYLOAD_SIZE as u32 * 8);
        let q = fancy_garbling::util::product(&qs);

        let (mut table, mut payload) = self.bucketize_data(table, payloads, channel, rng)?;
        let mut state = ReceiverState{
                opprf_ids: Vec::new(),
                opprf_payloads: Vec::new(),
                table: table.clone(),
                payload: payload.clone(),
        };

        self.receive_data(&mut state, channel, rng)?;

        let aggregate = state.build_and_compute_circuit(&mut ev, channel).unwrap();

        let mpc_outs = ev
            .outputs(&aggregate.wires().to_vec()).unwrap()
            .expect("evaluator should produce outputs");
        let aggregate = fancy_garbling::util::crt_inv(&mpc_outs, &qs);

        println!("Output = {:?}", aggregate);
        channel.flush()?;

        Ok(aggregate as u64)
    }

    pub fn full_protocol_large<C: AbstractChannel, RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>>(
        &mut self,
        table: &[Msg],
        payloads: &[Block512],
        megasize: usize,
        channel: &mut C,
        rng: &mut RNG,
    )-> Result<u64, Error> {
        let mut ev =
            Evaluator::<C, RNG, OtReceiver>::new(channel.clone(), RNG::from_seed(rng.gen())).unwrap();
        let qs = fancy_garbling::util::primes_with_width(PAYLOAD_SIZE as u32 * 8);
        let q = fancy_garbling::util::product(&qs);

        let (mut table, mut payload) = self.bucketize_data_large(table, payloads, megasize, channel, rng)?;


        let aggregate = self.compute_payload(table, payload, 0, channel, rng).unwrap();

        let mpc_outs = ev
            .outputs(&aggregate.wires().to_vec()).unwrap()
            .expect("evaluator should produce outputs");
        let aggregate = fancy_garbling::util::crt_inv(&mpc_outs, &qs);

        println!("Output = {:?}", aggregate);
        channel.flush()?;

        Ok(aggregate as u64)
    }


    pub fn compute_payload<C: AbstractChannel, RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>>(
        &mut self,
        table: Vec<Vec<Block>>,
        payload: Vec<Vec<Block512>>,
        thread_id: usize,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<CrtBundle<fancy_garbling::Wire>, Error> {

        let mut ev =
            Evaluator::<C, RNG, OtReceiver>::new(channel.clone(), RNG::from_seed(rng.gen())).unwrap();
        let qs = fancy_garbling::util::primes_with_width(PAYLOAD_SIZE as u32 * 8);
        let q = fancy_garbling::util::product(&qs);
        let mut acc = ev.crt_constant_bundle(0, q).unwrap();

        let nmegabins = table.len();
        for i in 0..nmegabins{
            let start = SystemTime::now();
            println!("Starting megabin number:{}", i);
            let mut state =  ReceiverState{
                opprf_ids: Vec::new(),
                opprf_payloads: Vec::new(),
                table: table[i].clone(),
                payload: payload[i].clone(),
            };

            self.receive_data(&mut state, channel, rng)?;
            let partial: CrtBundle<fancy_garbling::Wire> = state.build_and_compute_circuit(&mut ev, channel).unwrap();
            acc = ev.crt_add(&acc, &partial).unwrap();

            let mpc_outs = ev
                .outputs(&acc.wires().to_vec()).unwrap()
                .expect("evaluator should produce outputs");
            let aggregate = fancy_garbling::util::crt_inv(&mpc_outs, &qs);
            if(aggregate as u64 > u64::pow(2,63)){
                println!("megabin{:?}", i);
                println!("bad thread {:?}", thread_id);
            }
            println!("Partial output = {:?}", aggregate);
            channel.flush()?;
            println!(
                "Receiver :: Computation time: {} ms",
                start.elapsed().unwrap().as_millis()
            );

        }
        Ok(acc)
    }

    pub fn compute_aggregates<C: AbstractChannel , RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>>(
        &mut self,
        aggregates: Vec<Vec<Wire>>,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<u64, Error> {
        let mut ev =
            Evaluator::<C, RNG, OtReceiver>::new(channel.clone(), RNG::from_seed(rng.gen())).unwrap();
        let qs = fancy_garbling::util::primes_with_width(PAYLOAD_SIZE as u32 * 8);

        let mut acc = CrtBundle::new(aggregates[0].clone());
        for i in 1..aggregates.len(){
            let partial = CrtBundle::new(aggregates[i].clone());
            acc = ev.crt_add(&acc, &partial).unwrap();
        }
        let mpc_outs = ev
            .outputs(&acc.wires().to_vec()).unwrap()
            .expect("evaluator should produce outputs");
        let aggregate = fancy_garbling::util::crt_inv(&mpc_outs, &qs);
        Ok(aggregate as u64)
    }

    pub fn bucketize_data<C: AbstractChannel, RNG: RngCore + CryptoRng + SeedableRng>(
        &mut self,
        inputs: &[Msg],
        payloads: &[Block512],
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<(Vec<Block>, Vec<Block512>), Error>{

        let hashed_inputs = utils::compress_and_hash_inputs(inputs, self.key);
        let cuckoo = CuckooHash::new(&hashed_inputs, NHASHES)?;
        channel.write_usize(0)?;
        channel.write_usize(0)?;
        channel.write_usize(cuckoo.nbins)?;
        channel.flush()?;

        let table = cuckoo
            .items
            .iter()
            .map(|opt_item| match opt_item {
                Some(item) => item.entry,
                None => rng.gen(),
            })
            .collect::<Vec<Block>>();

        let payload = cuckoo
            .items
            .iter()
            .map(|opt_item| match opt_item {
                Some(item) => payloads[item.input_index],
                None => rng.gen::<Block512>(),
            })

            .collect::<Vec<Block512>>();

        Ok((
            table,
            payload,
        ))
    }

    pub fn bucketize_data_large<C: AbstractChannel, RNG: RngCore + CryptoRng + SeedableRng>(
        &mut self,
        inputs: &[Msg],
        payloads: &[Block512],
        megasize: usize,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<(Vec<Vec<Block>>, Vec<Vec<Block512>>), Error>{

        let hashed_inputs = utils::compress_and_hash_inputs(inputs, self.key);
        let cuckoo_large = CuckooHashLarge::new(&hashed_inputs, NHASHES, megasize)?;
        channel.write_usize(cuckoo_large.megasize)?;
        channel.write_usize(cuckoo_large.nmegabins)?;
        channel.write_usize(cuckoo_large.nbins)?;
        channel.flush()?;

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
            table,
            payload,
        ))
    }
    // Run the PSI protocol over `inputs`.
    pub fn receive_data<C: AbstractChannel, RNG: RngCore + CryptoRng + SeedableRng>(
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
    ) -> Result<(Vec<Wire>, Vec<Wire>, Vec<Wire>, Vec<Wire>, Vec<Wire>), Error>
    where
        C: AbstractChannel,
        RNG: CryptoRng + RngCore + SeedableRng<Seed = Block>,
    {

        let my_input_bits = encode_inputs(&self.opprf_ids);
        let my_opprf_output = encode_opprf_payload(&self.opprf_payloads);
        let my_payload_bits = encode_payloads(&self.payload);

        let mods_bits = vec![2; my_input_bits.len()];
        let sender_inputs = ev.receive_many(&mods_bits).unwrap();
        let receiver_inputs = ev.encode_many(&my_input_bits, &mods_bits).unwrap();

        let qs = fancy_garbling::util::primes_with_width(PAYLOAD_SIZE as u32 * 8);
        let mut mods_crt = Vec::new();
        for _i in 0..self.payload.len(){
            mods_crt.append(&mut qs.clone());
        }

        let sender_payloads = ev.receive_many(&mods_crt).unwrap();

        let receiver_payloads = ev.encode_many(&my_payload_bits, &mods_crt).unwrap();
        let receiver_masks = ev.encode_many(&my_opprf_output, &mods_crt).unwrap();
        Ok((sender_inputs, receiver_inputs, sender_payloads, receiver_payloads, receiver_masks))
    }

    pub fn build_and_compute_circuit<C, RNG>(
        &mut self,
        ev: &mut Evaluator<C, RNG, OtReceiver>,
        channel: &mut C,
    ) -> Result<CrtBundle<fancy_garbling::Wire>, Error>
    where
        C: AbstractChannel,
        RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>,
    {
        channel.flush()?;
        let (x, y, x_payload, y_payload, masks) = self.encode_circuit_inputs(ev)?;

        let outs = fancy_compute_payload_aggregate(ev, &x, &y, &x_payload, &y_payload, &masks).unwrap();
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
