//! Implementation of the Pinkas-Schneider-Tkachenko-Yanai "extended" private
//! set intersection protocol (cf. <https://eprint.iacr.org/2019/241>).

// What’s the difference with the regular psty:
// - Implements PSTY19's protocol for computation on associated payloads with the intersection,
//   currently the regular psty.rs only revelas the payloads associated with the intersection.
// - Extends the protocol to larger sets via megabins. Now a regular machine can handle extra-large sets
// - Factors and splits out the psty protocol more in-order to expose methods to seperate threads and make parallelization simpler

// Assumption::
//
// - Inputs and outputs are 64bit long. Otherwise the CRT padding and encoding could leak the padded sub-string.
//   This is already an assumption in swanky since it can only generate and handle primes with width up to 64bit long.
// - The receiver sends out the number of bins, mega bins and the size of a megabin to the receiver.
// - The receiver’s set is bigger than the senders (otherwise the code, even without this extension, complains)
// - The megabin size is smaller than the larger set.
// - The receiver gets the output of the computation.
//
// TODO:
//
// (1) Use ocelot's cuckoo hash (ch) instead of popsicle's: popsicle's current ch has a bug where
//     it is always full and fails for certain numbers like 100,000 and larger powers of 10.
//          -- Cuckoo hash is fixed - BC 4/2/21
// (2) Once (1) is complete, revert handling megabins after the ch is done instead of during (and
//     effectively get rid of the ch large structure and methods currently in popsicle/src/cuckoo)
//     the current megabin handling is an artifact of older bugs that stalled the system for large sets
// (3) Extend the size of generated primes beyond 64bits
//

use crate::{
    cuckoo::{CuckooHash, CuckooItem},
    errors::Error,
    utils,
};
use fancy_garbling::{
    twopac::semihonest::{Evaluator, Garbler},
    AllWire, ArithmeticBundleGadgets, BinaryBundle, Bundle, CrtBundle, CrtGadgets, Fancy,
    FancyBinary, FancyInput,
};

use itertools::Itertools;
use ocelot::{
    oprf::{KmprtReceiver, KmprtSender},
    ot::{AlszReceiver as OtReceiver, AlszSender as OtSender},
};

use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use scuttlebutt::{AbstractChannel, Block, Block512, SemiHonest};
use std::time::SystemTime;

use std::{
    fs::File,
    io::{BufRead, BufReader},
};

const NHASHES: usize = 3;
// How many bytes of the hash to use for the equality tests. This affects
// correctness, with a lower value increasing the likelihood of a false
// positive.
const HASH_SIZE: usize = 4;

// How many bytes are used for payloads
const PAYLOAD_SIZE: usize = 8;

// How many u16's are used for the CRT representation
const PAYLOAD_PRIME_SIZE: usize = 16;
const PAYLOAD_PRIME_SIZE_EXPANDED: usize = PAYLOAD_PRIME_SIZE + 1;

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
    opprf_ids: Vec<Block512>,
    opprf_payloads: Vec<Block512>,
    table: Vec<Vec<Block>>,
    payload: Vec<Vec<Block512>>,
}

/// Private set intersection receiver.
pub struct Receiver {
    key: Block,
    opprf: KmprtReceiver,
    opprf_payload: KmprtReceiver,
}

/// State of the receiver.
pub struct ReceiverState {
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
        let key = channel.read_block()?;
        let opprf = KmprtSender::init(channel, rng)?;
        let opprf_payload = KmprtSender::init(channel, rng)?;
        Ok(Self {
            key,
            opprf,
            opprf_payload,
        })
    }

    /// PSI with associated payloads for small to moderately sized sets without any
    /// parallelization features.
    pub fn full_protocol<
        C: AbstractChannel,
        RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>,
    >(
        &mut self,
        table: &[Msg],
        payloads: &[Block512],
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<(), Error> {
        let mut gb =
            Garbler::<C, RNG, OtSender, AllWire>::new(channel.clone(), RNG::from_seed(rng.gen()))
                .unwrap();

        let (mut state, nbins, _, _) = self.bucketize_data(table, payloads, channel, rng)?;

        channel.flush()?;
        self.send_data(&mut state, nbins, channel, rng)?;
        channel.flush()?;

        let (aggregate, sum_weights) = state.build_and_compute_circuit(&mut gb).unwrap();
        let weighted_mean = gb.crt_div(&aggregate, &sum_weights).unwrap();

        gb.outputs(&weighted_mean.wires().to_vec()).unwrap();
        channel.flush()?;

        Ok(())
    }

    /// PSI with associated payloads for large sized sets. Batched OPPRF + GC computation is performed
    /// on a Megabin instead of the entirety of the hashed data. The number of Megabin is pre-agreed
    /// on during the bucketization. Users have to specify the GC deltas. If the computation is run
    /// in parallel, the deltas must be synced accross threads.
    pub fn full_protocol_large<
        C: AbstractChannel,
        RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>,
    >(
        &mut self,
        table: &[Msg],
        payloads: &[Block512],
        path_deltas: &str,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<(), Error> {
        let mut gb =
            Garbler::<C, RNG, OtSender, AllWire>::new(channel.clone(), RNG::from_seed(rng.gen()))
                .unwrap();
        let _ = gb.load_deltas(path_deltas);

        let (state, _nbins, _nmegabins, megasize) =
            self.bucketize_data(table, payloads, channel, rng)?;

        let ts_id: Vec<Vec<Block512>> = state
            .opprf_ids
            .chunks(megasize)
            .map(|x| x.to_vec())
            .collect();
        let ts_payload: Vec<Vec<Block512>> = state
            .opprf_payloads
            .chunks(megasize)
            .map(|x| x.to_vec())
            .collect();
        let table: Vec<Vec<Vec<Block>>> =
            state.table.chunks(megasize).map(|x| x.to_vec()).collect();
        let payload: Vec<Vec<Vec<Block512>>> =
            state.payload.chunks(megasize).map(|x| x.to_vec()).collect();

        let (aggregate, sum_weights) = self
            .compute_payload(
                ts_id,
                ts_payload,
                table,
                payload,
                &path_deltas,
                channel,
                rng,
            )
            .unwrap();
        let weighted_mean = gb.crt_div(&aggregate, &sum_weights).unwrap();
        println!("Done");
        gb.outputs(&weighted_mean.wires().to_vec()).unwrap();
        Ok(())
    }

    /// PSI computation designed sepecifically for large sets. Assumes the bucketization stage
    /// has already been done, bins were seperated into megabins and that deltas for the circuit
    /// were precomputed.
    /// Returns a garbled output over given megabins that the user can open or join with other
    /// threads results using compute_aggregate.
    pub fn compute_payload<
        C: AbstractChannel,
        RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>,
    >(
        &mut self,
        ts_id: Vec<Vec<Block512>>,
        ts_payload: Vec<Vec<Block512>>,
        table: Vec<Vec<Vec<Block>>>,
        payload: Vec<Vec<Vec<Block512>>>,
        path_deltas: &str,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<(CrtBundle<AllWire>, CrtBundle<AllWire>), Error> {
        let mut gb =
            Garbler::<C, RNG, OtSender, AllWire>::new(channel.clone(), RNG::from_seed(rng.gen()))
                .unwrap();
        let _ = gb.load_deltas(path_deltas);

        let qs = &fancy_garbling::util::PRIMES[..PAYLOAD_PRIME_SIZE_EXPANDED];
        let q = fancy_garbling::util::product(&qs);

        let mut acc = gb.crt_constant_bundle(0, q).unwrap();
        let mut sum_weights = gb.crt_constant_bundle(0, q).unwrap();

        let nmegabins = ts_id.len();
        for i in 0..nmegabins {
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
            let (partial, partial_sum_weights) = state.build_and_compute_circuit(&mut gb).unwrap();

            acc = gb.crt_add(&acc, &partial).unwrap();
            sum_weights = gb.crt_add(&sum_weights, &partial_sum_weights).unwrap();

            println!(
                "Sender :: Computation time: {} ms",
                start.elapsed().unwrap().as_millis()
            );

            channel.flush()?;
        }
        Ok((acc, sum_weights))
    }

    /// Aggregates partial grabled outputs encoded as CRTs. Uses the same deltas used by partial
    /// circuits.
    pub fn compute_aggregates<
        C: AbstractChannel,
        RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>,
    >(
        &mut self,
        aggregates: Vec<Vec<AllWire>>,
        sum_of_weights: Vec<Vec<AllWire>>,
        path_deltas: &str,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<(), Error> {
        let mut gb =
            Garbler::<C, RNG, OtSender, AllWire>::new(channel.clone(), RNG::from_seed(rng.gen()))
                .unwrap();
        let _ = gb.load_deltas(path_deltas);

        let mut acc = CrtBundle::new(aggregates[0].clone());
        let mut sum_weights = CrtBundle::new(sum_of_weights[0].clone());

        for i in 1..aggregates.len() {
            let partial_aggregate = CrtBundle::new(aggregates[i].clone());
            let partial_sum_weight = CrtBundle::new(sum_of_weights[i].clone());

            acc = gb.crt_add(&acc, &partial_aggregate).unwrap();
            sum_weights = gb.crt_add(&sum_weights, &partial_sum_weight).unwrap();
        }

        let weighted_mean = gb.crt_div(&acc, &sum_weights).unwrap();
        gb.outputs(&weighted_mean.wires().to_vec()).unwrap();
        Ok(())
    }

    /// Bucketizes data according to the number of bins specified by the Receiver
    pub fn bucketize_data<C: AbstractChannel, RNG: RngCore + CryptoRng + SeedableRng>(
        &mut self,
        inputs: &[Msg],
        payloads: &[Block512],
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<(SenderState, usize, usize, usize), Error> {
        // receive cuckoo hash info from sender
        let megasize = channel.read_usize()?;
        let nmegabins = channel.read_usize()?;
        let nbins = channel.read_usize()?;
        let hashes = utils::compress_and_hash_inputs(inputs, self.key);

        let mut table = vec![Vec::new(); nbins];
        let mut payload = vec![Vec::new(); nbins];

        let ts_id = (0..nbins).map(|_| rng.gen::<Block512>()).collect_vec();
        let ts_payload = (0..nbins).map(|_| rng.gen::<Block512>()).collect_vec();

        for (x, p) in hashes.iter().zip_eq(payloads.iter()) {
            let mut bins = Vec::with_capacity(NHASHES);
            for h in 0..NHASHES {
                let bin = CuckooHash::bin(*x, h, nbins);
                table[bin].push(*x ^ Block::from(h as u128));
                // In the case of CRT representations: the payload must be appropriately
                // added to the target vector according to the CRT moduluses. The result
                // is randomly padded to get a Block512.
                // Note: mask_payload_crt assumes that inputs and outputs of GC are 64bit
                // long.
                // In the case of a binary representation: the payload can be simply XORed
                // with the target vector, the appropriately padded if need be.
                payload[bin].push(mask_payload_crt(*p, ts_payload[bin], rng));
                bins.push(bin);
            }
            // if j = H1(y) = H2(y) for some y, then P2 adds a uniformly random element to
            // table2[j] & payload[j]
            if bins.iter().skip(1).all(|&x| x == bins[0]) {
                table[bins[0]].push(rng.gen());
                payload[bins[0]].push(rng.gen());
            }
        }

        let state = SenderState {
            opprf_ids: ts_id,
            opprf_payloads: ts_payload,
            table,
            payload,
        };

        Ok((state, nbins, nmegabins, megasize))
    }

    /// Perform OPPRF on ID's & associated payloads
    pub fn send_data<C: AbstractChannel, RNG: RngCore + CryptoRng + SeedableRng>(
        &mut self,
        state: &mut SenderState,
        nbins: usize,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<(), Error> {
        let points_id = state
            .table
            .clone()
            .into_iter()
            .zip_eq(state.opprf_ids.iter())
            .flat_map(|(bin, t)| {
                // map all the points in a bin to the same tag
                bin.into_iter().map(move |item| (item, *t))
            })
            .collect_vec();

        // Orders payload data similarly to how ID's were hashed into bins
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
    /// Encodes circuit inputs before passing them to GC
    pub fn encode_circuit_inputs<C, RNG>(
        &mut self,
        gb: &mut Garbler<C, RNG, OtSender, AllWire>,
    ) -> Result<
        (
            Vec<AllWire>,
            Vec<AllWire>,
            Vec<AllWire>,
            Vec<AllWire>,
            Vec<AllWire>,
        ),
        Error,
    >
    where
        C: AbstractChannel,
        RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>,
    {
        let my_input_bits = encode_inputs(&self.opprf_ids);
        let my_payload_bits = encode_payloads(&self.opprf_payloads);

        let mods_bits = vec![2; my_input_bits.len()];
        let sender_inputs = gb.encode_many(&my_input_bits, &mods_bits).unwrap();
        let receiver_inputs = gb.receive_many(&mods_bits).unwrap();

        // Build appropriate modulus in order to encode as CRT.
        // CRT representation assumes that inputs and outputs of the
        // circuit are PAYLOAD_SIZE bytes long: this helps avoid carry
        // handling in GC computation.
        let qs = &fancy_garbling::util::PRIMES[..PAYLOAD_PRIME_SIZE_EXPANDED].to_vec();
        // let nprimes = qs.len();
        // qs.push(fancy_garbling::util::PRIMES[nprimes]);

        let mut mods_crt = Vec::new();
        for _i in 0..self.opprf_payloads.len() {
            mods_crt.append(&mut qs.clone());
        }

        let sender_payloads = gb.encode_many(&my_payload_bits, &mods_crt).unwrap();
        let receiver_payloads = gb.receive_many(&mods_crt).unwrap();
        let receiver_masks = gb.receive_many(&mods_crt).unwrap();
        Ok((
            sender_inputs,
            receiver_inputs,
            sender_payloads,
            receiver_payloads,
            receiver_masks,
        ))
    }

    /// Encode inputs & compute weighted aggregates circuit
    pub fn build_and_compute_circuit<C, RNG>(
        &mut self,
        gb: &mut Garbler<C, RNG, OtSender, AllWire>,
    ) -> Result<(CrtBundle<AllWire>, CrtBundle<AllWire>), Error>
    where
        C: AbstractChannel,
        RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>,
    {
        let (x, y, x_payload, y_payload, masks) = self.encode_circuit_inputs(gb).unwrap();
        let (outs, sum_weights) =
            fancy_compute_payload_aggregate(gb, &x, &y, &x_payload, &y_payload, &masks).unwrap();
        Ok((outs, sum_weights))
    }
}

impl Receiver {
    /// Initialize the PSI receiver.
    pub fn init<C: AbstractChannel, RNG: RngCore + CryptoRng + SeedableRng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let key = rng.gen();
        channel.write_block(&key)?;
        channel.flush()?;

        let opprf = KmprtReceiver::init(channel, rng)?;
        let opprf_payload = KmprtReceiver::init(channel, rng)?;
        Ok(Self {
            key,
            opprf,
            opprf_payload,
        })
    }

    /// PSI with associated payloads for small to moderately sized sets without any
    /// parallelization features.
    pub fn full_protocol<
        C: AbstractChannel,
        RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>,
    >(
        &mut self,
        table: &[Msg],
        payloads: &[Block512],
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<u128, Error> {
        let mut ev = Evaluator::<C, RNG, OtReceiver, AllWire>::new(
            channel.clone(),
            RNG::from_seed(rng.gen()),
        )
        .unwrap();
        let qs = &fancy_garbling::util::PRIMES[..PAYLOAD_PRIME_SIZE_EXPANDED];

        let (table, payload) = self.bucketize_data(table, payloads, channel, rng)?;

        let mut state = ReceiverState {
            opprf_ids: Vec::new(),
            opprf_payloads: Vec::new(),
            table,
            payload,
        };

        self.receive_data(&mut state, channel, rng)?;
        let (aggregate, sum_weights) = state.build_and_compute_circuit(&mut ev, channel).unwrap();
        let weighted_mean = ev.crt_div(&aggregate, &sum_weights).unwrap();

        let weighted_mean_outs = ev
            .outputs(&weighted_mean.wires().to_vec())
            .unwrap()
            .expect("evaluator should produce outputs");

        let weighted_mean = fancy_garbling::util::crt_inv(&weighted_mean_outs, &qs);
        channel.flush()?;

        Ok(weighted_mean)
    }

    /// PSI with associated payloads for large sized sets. Batched OPPRF + GC computation is performed
    /// on a Megabin instead of the entirety of the hashed data. The number of Megabin is pre-agreed
    /// on during the bucketization. Users have to specify the GC deltas. If the computation is run
    /// in parallel, the deltas must be synced accross threads.
    pub fn full_protocol_large<
        C: AbstractChannel,
        RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>,
    >(
        &mut self,
        table: &[Msg],
        payloads: &[Block512],
        megasize: usize,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<u128, Error> {
        let mut ev = Evaluator::<C, RNG, OtReceiver, AllWire>::new(
            channel.clone(),
            RNG::from_seed(rng.gen()),
        )
        .unwrap();
        let qs = &fancy_garbling::util::PRIMES[..PAYLOAD_PRIME_SIZE_EXPANDED];

        let (table, payload, _) =
            self.bucketize_data_large(table, payloads, megasize, channel, rng)?;

        let (aggregate, sum_weights) = self.compute_payload(table, payload, channel, rng).unwrap();

        let weighted_mean = ev.crt_div(&aggregate, &sum_weights).unwrap();
        let weighted_mean_outs = ev
            .outputs(&weighted_mean.wires().to_vec())
            .unwrap()
            .expect("evaluator should produce outputs");
        let weighted_mean = fancy_garbling::util::crt_inv(&weighted_mean_outs, &qs);

        channel.flush()?;

        Ok(weighted_mean)
    }

    /// PSI computation designed sepecifically for large sets. Assumes the bucketization stage
    /// has already been done, bins were seperated into megabins and that deltas for the circuit
    /// were precomputed.
    /// Returns a garbled output over given megabins that the user can open or join with other
    /// threads results using compute_aggregate.
    pub fn compute_payload<
        C: AbstractChannel,
        RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>,
    >(
        &mut self,
        table: Vec<Vec<Block>>,
        payload: Vec<Vec<Block512>>,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<(CrtBundle<AllWire>, CrtBundle<AllWire>), Error> {
        let mut ev = Evaluator::<C, RNG, OtReceiver, AllWire>::new(
            channel.clone(),
            RNG::from_seed(rng.gen()),
        )
        .unwrap();
        let qs = &fancy_garbling::util::PRIMES[..PAYLOAD_PRIME_SIZE_EXPANDED];
        let q = fancy_garbling::util::product(&qs);

        let mut acc = ev.crt_constant_bundle(0, q).unwrap();
        let mut sum_weights = ev.crt_constant_bundle(0, q).unwrap();

        let nmegabins = table.len();
        println!("nmegabins: {:?}", nmegabins);
        for i in 0..nmegabins {
            let start = SystemTime::now();
            println!("Starting megabin number:{}", i);
            let mut state = ReceiverState {
                opprf_ids: Vec::new(),
                opprf_payloads: Vec::new(),
                table: table[i].clone(),
                payload: payload[i].clone(),
            };
            self.receive_data(&mut state, channel, rng)?;
            let (partial, partial_sum_weights) =
                state.build_and_compute_circuit(&mut ev, channel).unwrap();

            acc = ev.crt_add(&acc, &partial).unwrap();
            sum_weights = ev.crt_add(&sum_weights, &partial_sum_weights).unwrap();

            channel.flush()?;
            println!(
                "Receiver :: Computation time: {} ms",
                start.elapsed().unwrap().as_millis()
            );
        }
        Ok((acc, sum_weights))
    }

    /// Aggregates partial grabled outputs encoded as CRTs. Uses the same deltas used by partial
    /// circuits.
    pub fn compute_aggregates<
        C: AbstractChannel,
        RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>,
    >(
        &mut self,
        aggregates: Vec<Vec<AllWire>>,
        sum_of_weights: Vec<Vec<AllWire>>,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<u128, Error> {
        let mut ev = Evaluator::<C, RNG, OtReceiver, AllWire>::new(
            channel.clone(),
            RNG::from_seed(rng.gen()),
        )
        .unwrap();

        let qs = &fancy_garbling::util::PRIMES[..PAYLOAD_PRIME_SIZE_EXPANDED];
        let _q = fancy_garbling::util::product(&qs);

        let mut acc = CrtBundle::new(aggregates[0].clone());
        let mut sum_weights = CrtBundle::new(sum_of_weights[0].clone());

        for i in 1..aggregates.len() {
            let partial_aggregate = CrtBundle::new(aggregates[i].clone());
            let partial_sum_weights = CrtBundle::new(sum_of_weights[i].clone());

            acc = ev.crt_add(&acc, &partial_aggregate).unwrap();
            sum_weights = ev.crt_add(&sum_weights, &partial_sum_weights).unwrap();
        }

        let weighted_mean = ev.crt_div(&acc, &sum_weights).unwrap();

        let weighted_mean_outs = ev
            .outputs(&weighted_mean.wires().to_vec())
            .unwrap()
            .expect("evaluator should produce outputs");
        let weighted_mean = fancy_garbling::util::crt_inv(&weighted_mean_outs, &qs);

        println!("weighted_mean{}", weighted_mean);

        Ok(weighted_mean)
    }

    /// For small to moderate sized sets, bucketizes using Cuckoo Hashing
    pub fn bucketize_data<C: AbstractChannel, RNG: RngCore + CryptoRng + SeedableRng>(
        &mut self,
        inputs: &[Msg],
        payloads: &[Block512],
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<(Vec<Block>, Vec<Block512>), Error> {
        let hashed_inputs = utils::compress_and_hash_inputs(inputs, self.key);
        let cuckoo = CuckooHash::new(&hashed_inputs, NHASHES)?;

        channel.write_usize(0)?;
        channel.write_usize(0)?;
        channel.write_usize(cuckoo.nbins)?; // The number of bins is sent out to the sender
        channel.flush()?;
        let table = cuckoo
            .items
            .iter()
            .map(|opt_item| match opt_item {
                Some(item) => item.entry_with_hindex(),
                None => rng.gen(),
            })
            .collect::<Vec<Block>>();

        // Bucketizes payloads similarly to IDs
        let payload = cuckoo
            .items
            .iter()
            .map(|opt_item| match opt_item {
                Some(item) => payloads[item.input_index],
                None => rng.gen::<Block512>(),
            })
            .collect::<Vec<Block512>>();

        Ok((table, payload))
    }

    /// For Large sets, bucketizes using Cuckoo Hashing while mapping to Megabins. The Megabin index
    /// is computed from the regular CH index:
    ///            new_bin_id = ch_id % megabin_size; // the bin within the megabin
    ///            megabin_id =  ch_id / megabin_size;
    /// A megabin is a collection of bins, typically specified by the total number of elements that
    /// can be handled at a time (megabin_size).
    pub fn bucketize_data_large<C: AbstractChannel, RNG: RngCore + CryptoRng + SeedableRng>(
        &mut self,
        inputs: &[Msg],
        payloads: &[Block512],
        megasize: usize,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<(Vec<Vec<Block>>, Vec<Vec<Block512>>, usize), Error> {
        let hashed_inputs = utils::compress_and_hash_inputs(inputs, self.key);

        let cuckoo = CuckooHash::new(&hashed_inputs, NHASHES)?;
        let cuckoo_large: Vec<&[Option<CuckooItem>]> = cuckoo.items.chunks(megasize).collect();
        let nmegabins = cuckoo_large.len();

        channel.write_usize(megasize)?; // The megabin size is sent out to the sender
        channel.write_usize(nmegabins)?; // The number of megabins is sent out to the sender
        channel.write_usize(cuckoo.nbins)?; // The number of bins is sent out to the sender
        channel.flush()?;

        let table = cuckoo_large
            .iter()
            .map(|cuckoo| {
                cuckoo
                    .iter()
                    .map(|opt_item| match opt_item {
                        Some(item) => item.entry_with_hindex(),
                        None => rng.gen::<Block>(),
                    })
                    .collect::<Vec<Block>>()
            })
            .collect();

        let payload = cuckoo_large
            .iter()
            .map(|cuckoo| {
                cuckoo
                    .iter()
                    .map(|opt_item| match opt_item {
                        Some(item) => payloads[item.input_index],
                        None => rng.gen::<Block512>(),
                    })
                    .collect::<Vec<Block512>>()
            })
            .collect();

        Ok((table, payload, nmegabins))
    }

    /// Receive outputs of the OPPRF
    pub fn receive_data<C: AbstractChannel, RNG: RngCore + CryptoRng + SeedableRng>(
        &mut self,
        state: &mut ReceiverState,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<(), Error> {
        state.opprf_ids = self.opprf.receive(channel, &state.table, rng)?;
        state.opprf_payloads = self.opprf_payload.receive(channel, &state.table, rng)?;
        Ok(())
    }
}

impl ReceiverState {
    /// Encodes circuit inputs before passing them to GC
    pub fn encode_circuit_inputs<C, RNG>(
        &mut self,
        ev: &mut Evaluator<C, RNG, OtReceiver, AllWire>,
    ) -> Result<
        (
            Vec<AllWire>,
            Vec<AllWire>,
            Vec<AllWire>,
            Vec<AllWire>,
            Vec<AllWire>,
        ),
        Error,
    >
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

        let qs = &fancy_garbling::util::PRIMES[..PAYLOAD_PRIME_SIZE_EXPANDED].to_vec();

        let mut mods_crt = Vec::new();
        for _i in 0..self.payload.len() {
            mods_crt.append(&mut qs.clone());
        }

        let sender_payloads = ev.receive_many(&mods_crt).unwrap();

        let receiver_payloads = ev.encode_many(&my_payload_bits, &mods_crt).unwrap();
        let receiver_masks = ev.encode_many(&my_opprf_output, &mods_crt).unwrap();
        Ok((
            sender_inputs,
            receiver_inputs,
            sender_payloads,
            receiver_payloads,
            receiver_masks,
        ))
    }

    /// Encode inputs & compute weighted aggregates circuit
    pub fn build_and_compute_circuit<C, RNG>(
        &mut self,
        ev: &mut Evaluator<C, RNG, OtReceiver, AllWire>,
        channel: &mut C,
    ) -> Result<(CrtBundle<AllWire>, CrtBundle<AllWire>), Error>
    where
        C: AbstractChannel,
        RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>,
    {
        channel.flush()?;
        let (x, y, x_payload, y_payload, masks) = self.encode_circuit_inputs(ev)?;

        let (outs, sum_weights) =
            fancy_compute_payload_aggregate(ev, &x, &y, &x_payload, &y_payload, &masks).unwrap();
        Ok((outs, sum_weights))
    }
}

// Encoding ID's before passing them to GC.
// Note that we are only looking at HASH_SIZE bytes
// of the IDs.
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

// Encoding Payloads's before passing them to GC.
// Note that we are only looking at PAYLOAD_SIZE bytes
// of the payloads.
// + similar comment to encode_opprf_payload
fn encode_payloads(payload: &[Block512]) -> Vec<u16> {
    let q = &fancy_garbling::util::PRIMES[..PAYLOAD_PRIME_SIZE_EXPANDED];
    payload
        .iter()
        .flat_map(|blk| {
            let b = blk.prefix(PAYLOAD_SIZE);
            let mut b_8 = [0_u8; 16]; // beyond 64 bits padded with 0s
            b_8[..PAYLOAD_SIZE].clone_from_slice(&b[..PAYLOAD_SIZE]);
            fancy_garbling::util::crt(u128::from_le_bytes(b_8), &q)
        })
        .collect()
}

// Encoding OPPRF output associated with the payloads's before passing them to GC.
// Note that we are only looking at PAYLOAD_PRIME_SIZE bytes of the opprf_payload:
// the size we get after masking the payloads with the target vectors as CRT
//
// Assumes payloads are up to 64bit long:
// The padding is not similarly generated to
// the actual data: Notice how the masked data
// is % with the correct modulus, while the
// padded values are 0.
// When swanky starts supporting larger primes,
// the padded value should be random and modded with the
// appropriate prime at its position
fn encode_opprf_payload(opprf_ids: &[Block512]) -> Vec<u16> {
    let q = &fancy_garbling::util::PRIMES[..PAYLOAD_PRIME_SIZE_EXPANDED];
    opprf_ids
        .iter()
        .flat_map(|blk| {
            let b = blk.prefix(PAYLOAD_PRIME_SIZE);
            let mut b_8 = [0_u8; 16];
            b_8[..PAYLOAD_SIZE].clone_from_slice(&b[..PAYLOAD_SIZE]);
            fancy_garbling::util::crt(u128::from_le_bytes(b_8), &q)
        })
        .collect()
}
/// Fancy function to compute a weighted average for matching ID's
/// where one party provides the weights and the other
//  the values
fn fancy_compute_payload_aggregate<
    F: fancy_garbling::FancyReveal + Fancy + ArithmeticBundleGadgets + FancyBinary,
>(
    f: &mut F,
    sender_inputs: &[F::Item],
    receiver_inputs: &[F::Item],
    sender_payloads: &[F::Item],
    receiver_payloads: &[F::Item],
    receiver_masks: &[F::Item],
) -> Result<(CrtBundle<F::Item>, CrtBundle<F::Item>), F::Error> {
    assert_eq!(sender_inputs.len(), receiver_inputs.len());
    assert_eq!(sender_payloads.len(), receiver_payloads.len());
    assert_eq!(receiver_payloads.len(), receiver_masks.len());

    let qs = &fancy_garbling::util::PRIMES[..PAYLOAD_PRIME_SIZE_EXPANDED];
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

    let reconstructed_payload = sender_payloads
        .chunks(PAYLOAD_PRIME_SIZE_EXPANDED)
        .zip_eq(receiver_masks.chunks(PAYLOAD_PRIME_SIZE_EXPANDED))
        .map(|(xp, tp)| {
            let b_x = Bundle::new(xp.to_vec());
            let b_t = Bundle::new(tp.to_vec());
            f.crt_sub(&CrtBundle::from(b_t), &CrtBundle::from(b_x))
        })
        .collect::<Result<Vec<CrtBundle<F::Item>>, F::Error>>()?;

    let mut weighted_payloads = Vec::new();
    for it in reconstructed_payload
        .clone()
        .into_iter()
        .zip_eq(receiver_payloads.chunks(PAYLOAD_PRIME_SIZE_EXPANDED))
    {
        let (ps, pr) = it;
        let weighted = f.crt_mul(&ps, &CrtBundle::new(pr.to_vec()))?;
        weighted_payloads.push(weighted);
    }

    assert_eq!(eqs.len(), weighted_payloads.len());

    let mut acc = f.crt_constant_bundle(0, q)?;
    let mut sum_weights = f.crt_constant_bundle(0, q)?;
    let one = f.crt_constant_bundle(1, q)?;

    for (i, b) in eqs.iter().enumerate() {
        let b_ws = one
            .iter()
            .map(|w| f.mul(w, &b))
            .collect::<Result<Vec<F::Item>, F::Error>>()?;
        let b_crt = CrtBundle::new(b_ws);

        let mux = f.crt_mul(&b_crt, &weighted_payloads[i])?;
        let mux_sum_weights = f.crt_mul(&b_crt, &reconstructed_payload[i])?;
        acc = f.crt_add(&acc, &mux)?;
        sum_weights = f.crt_add(&sum_weights, &mux_sum_weights)?;
    }
    Ok((acc, sum_weights))
}

// Assumes payloads are up to 64bit long i.e 8 bytes
fn block512_to_crt(b: Block512) -> Vec<u16> {
    let b_val = b.prefix(8);

    let mut b_128 = [0_u8; 16];
    b_128[..8].clone_from_slice(&b_val[..8]);

    let q = fancy_garbling::util::primes_with_width(64);
    fancy_garbling::util::crt(u128::from_le_bytes(b_128), &q)
}

// Assumes payloads are up to 64bit long
// WRITE assumption more
fn mask_payload_crt<RNG: rand::Rng + Sized>(x: Block512, y: Block512, rng: &mut RNG) -> Block512 {
    let x_crt = block512_to_crt(x);
    let y_crt = block512_to_crt(y);
    let q = fancy_garbling::util::primes_with_width(64);
    let mut res_crt = Vec::new();
    for i in 0..q.len() {
        res_crt.push((x_crt[i] + y_crt[i]) % q[i]);
    }
    let res = fancy_garbling::util::crt_inv(&res_crt, &q).to_le_bytes();
    let mut block = [0_u8; 64];
    for i in 0..64 {
        if i < res.len() {
            block[i] = res[i];
        } else {
            block[i] = rng.gen::<u8>(); // TODO: mod rest of prime
        }
    }
    Block512::from(block)
}

/// Parse files for PSTY Payload computation.
pub fn parse_files(
    id_position: usize,
    payload_position: usize,
    path: &str,
) -> (Vec<Vec<u8>>, Vec<Block512>) {
    let data = File::open(path).unwrap();

    let buffer = BufReader::new(data).lines();

    let mut ids = Vec::new();
    let mut payloads = Vec::new();

    let mut cnt = 0;
    for line in buffer.enumerate() {
        let line_split = line
            .1
            .unwrap()
            .split(',')
            .map(|item| item.to_string())
            .collect::<Vec<String>>();
        if cnt == 0 {
            cnt += 1;
        } else {
            ids.push(
                line_split[id_position]
                    .parse::<u64>()
                    .unwrap()
                    .to_le_bytes()
                    .to_vec(),
            );
            payloads.push(line_split[payload_position].parse::<u64>().unwrap());
        }
    }
    (ids, int_vec_block512(payloads))
}

fn int_vec_block512(values: Vec<u64>) -> Vec<Block512> {
    values
        .into_iter()
        .map(|item| {
            let value_bytes = item.to_le_bytes();
            let mut res_block = [0_u8; 64];
            res_block[0..8].clone_from_slice(&value_bytes[..8]);
            Block512::from(res_block)
        })
        .collect()
}

impl SemiHonest for Sender {}
impl SemiHonest for Receiver {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::rand_u64_vec;
    use fancy_garbling::util::generate_deltas;
    use rand::{prelude::SliceRandom, thread_rng};
    use scuttlebutt::{AesRng, Block512, Channel, SymChannel};
    use std::{
        collections::HashMap,
        fs::File,
        io::{BufReader, BufWriter, Write},
        net::{TcpListener, TcpStream},
        os::unix::net::UnixStream,
    };

    const ITEM_SIZE: usize = 8;

    fn enum_ids_shuffled(n: usize, id_size: usize) -> Vec<Vec<u8>> {
        let mut vec: Vec<u64> = (0..n as u64).collect();
        vec.shuffle(&mut thread_rng());
        let mut ids = Vec::with_capacity(n);
        for i in 0..n {
            let v: Vec<u8> = vec[i].to_le_bytes().iter().take(id_size).cloned().collect();
            ids.push(v);
        }
        ids
    }

    fn weighted_mean_clear(
        ids_client: &[Vec<u8>],
        ids_server: &[Vec<u8>],
        payloads_client: &[Block512],
        payloads_server: &[Block512],
    ) -> u128 {
        let client_len = ids_client.len();
        let server_len = ids_server.len();
        let mut weighted_payload = 0;
        let mut sum_weights = 0;

        let mut sever_elements = HashMap::new();
        for i in 0..server_len {
            let id_server: &[u8] = &ids_server[i];
            let id_server: [u8; 8] = id_server.try_into().unwrap();
            let id_server = u64::from_le_bytes(id_server);
            let server_val = u64::from_le_bytes(payloads_server[i].prefix(8).try_into().unwrap());
            sever_elements.insert(id_server, server_val);
        }

        for i in 0..client_len {
            let id_client: &[u8] = &ids_client[i];
            let id_client: [u8; 8] = id_client.try_into().unwrap();
            let id_client = u64::from_le_bytes(id_client);
            if sever_elements.contains_key(&id_client) {
                // Assumes values are 64 bit long
                let client_val =
                    u64::from_le_bytes(payloads_client[i].prefix(8).try_into().unwrap());
                weighted_payload =
                    weighted_payload + client_val * sever_elements.get(&id_client).unwrap();
                sum_weights = sum_weights + sever_elements.get(&id_client).unwrap();
            }
        }
        weighted_payload as u128 / sum_weights as u128
    }

    #[test]
    fn test_psty_payload() {
        let set_size_sx: usize = 1 << 10;
        let set_size_rx: usize = 1 << 10;

        let weight_max: u64 = 100000;
        let payload_max: u64 = 100000;

        let mut rng = AesRng::new();

        let (sender, receiver) = UnixStream::pair().unwrap();

        let sender_inputs = enum_ids_shuffled(set_size_sx, ITEM_SIZE);
        let receiver_inputs = enum_ids_shuffled(set_size_rx, ITEM_SIZE);
        let weights = int_vec_block512(rand_u64_vec(set_size_sx, weight_max, &mut rng));
        let payloads = int_vec_block512(rand_u64_vec(set_size_rx, payload_max, &mut rng));

        let result_in_clear = weighted_mean_clear(
            &receiver_inputs.clone(),
            &sender_inputs.clone(),
            &payloads.clone(),
            &weights.clone(),
        );

        std::thread::spawn(move || {
            let mut rng = AesRng::new();

            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);

            let mut psi = Sender::init(&mut channel, &mut rng).unwrap();

            // For small to medium sized sets where batching can occur accross all bins
            let _ = psi
                .full_protocol(&sender_inputs, &weights, &mut channel, &mut rng)
                .unwrap();
        });

        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);

        let mut psi = Receiver::init(&mut channel, &mut rng).unwrap();
        // For small to medium sized sets where batching can occur accross all bins
        let weighted_mean = psi
            .full_protocol(&receiver_inputs, &payloads, &mut channel, &mut rng)
            .unwrap();

        assert_eq!(result_in_clear, weighted_mean);
    }

    #[test]
    fn test_psty_payload_large() {
        let set_size_sx: usize = 1 << 11;
        let set_size_rx: usize = 1 << 11;

        let weight_max: u64 = 100000;
        let payload_max: u64 = 100000;
        let megasize = 1 << 10;

        let mut rng = AesRng::new();

        let sender_inputs = enum_ids_shuffled(set_size_sx, ITEM_SIZE);
        let receiver_inputs = enum_ids_shuffled(set_size_rx, ITEM_SIZE);
        let weights = int_vec_block512(rand_u64_vec(set_size_sx, weight_max, &mut rng));
        let payloads = int_vec_block512(rand_u64_vec(set_size_rx, payload_max, &mut rng));

        let result_in_clear = weighted_mean_clear(
            &receiver_inputs.clone(),
            &sender_inputs.clone(),
            &payloads.clone(),
            &weights.clone(),
        );

        let qs = fancy_garbling::util::primes_with_width(65);
        let deltas = generate_deltas::<AllWire>(&qs);
        let deltas_json = serde_json::to_string(&deltas).unwrap();

        let path_delta = "./.deltas.txt".to_owned();
        let mut file_deltas = File::create(&path_delta).unwrap();
        file_deltas.write(deltas_json.as_bytes()).unwrap();

        std::thread::spawn(move || {
            let listener = TcpListener::bind("127.0.0.1:3000").unwrap();
            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        let mut channel = SymChannel::new(stream);
                        let mut rng = AesRng::new();

                        let mut psi = Sender::init(&mut channel, &mut rng).unwrap();
                        let _ = psi
                            .full_protocol_large(
                                &sender_inputs,
                                &weights,
                                &path_delta,
                                &mut channel,
                                &mut rng,
                            )
                            .unwrap();
                        println!("Done");
                        return;
                    }
                    Err(e) => {
                        println!("Error: {}", e);
                    }
                }
            }
            drop(listener);
        });
        match TcpStream::connect("127.0.0.1:3000") {
            Ok(stream) => {
                let mut channel = SymChannel::new(stream);
                let mut rng = AesRng::new();
                let mut psi = Receiver::init(&mut channel, &mut rng).unwrap();

                // For large examples where computation should be batched per-megabin instead of accross all bins.
                let weighted_mean = psi
                    .full_protocol_large(
                        &receiver_inputs,
                        &payloads,
                        megasize,
                        &mut channel,
                        &mut rng,
                    )
                    .unwrap();
                assert_eq!(result_in_clear, weighted_mean);
            }
            Err(e) => {
                println!("Failed to connect: {}", e);
            }
        }
    }
}
