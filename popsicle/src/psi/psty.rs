//! Implementation of the Pinkas-Schneider-Tkachenko-Yanai "extended" private
//! set intersection protocol (cf. <https://eprint.iacr.org/2019/241>).

use crate::{cuckoo::CuckooHash, errors::Error, utils};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};

use fancy_garbling::{
    twopac::semihonest::{Evaluator, Garbler},
    AllWire, BinaryBundle, BinaryBundleGadgets, BinaryGadgets, Fancy, FancyBinary, FancyInput,
};
use itertools::Itertools;
use ocelot::{
    oprf::{KmprtReceiver, KmprtSender},
    ot::{AlszReceiver as OtReceiver, AlszSender as OtSender},
};
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use scuttlebutt::{AbstractChannel, Block, Block512, SemiHonest};

const NHASHES: usize = 3;
// How many bytes of the hash to use for the equality tests. This affects
// correctness, with a lower value increasing the likelihood of a false
// positive.
const HASH_SIZE: usize = 4;

// How many bytes to use to determine whether decryption succeeded in the send/recv
// payload methods.
const PAD_LEN: usize = 16;

// This is the size of the authentication tag that is append to AES GCM
const TAG_SIZE: usize = 16;

// This is the size of the key used by AES GCM
const KEY_SIZE: usize = 32;

// This is the size of the nonce used by AES GCM
const NONCE_SIZE: usize = 12;

/// The type of values in the sender and receiver's sets.
pub type Msg = Vec<u8>;

/// Private set intersection sender.
pub struct Sender {
    opprf: KmprtSender,
}

/// State of the sender.
pub struct SenderState {
    opprf_outputs: Vec<Block512>,
}

/// Private set intersection receiver.
pub struct Receiver {
    opprf: KmprtReceiver,
}

/// State of the receiver.
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
        inputs: &[Msg],
        channel: &mut C,
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
                bin.into_iter().map(move |item| (item, *t))
            })
            .collect_vec();

        self.opprf.send(channel, &points, nbins, rng)?;

        Ok(SenderState { opprf_outputs: ts })
    }
}

impl SenderState {
    /// Run the setup phase, producing a garbler for the next stage.
    pub fn compute_setup<C, RNG>(
        &self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<
        (
            Garbler<C, RNG, OtSender, AllWire>,
            Vec<AllWire>,
            Vec<AllWire>,
        ),
        Error,
    >
    where
        C: AbstractChannel + Clone,
        RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>,
    {
        let mut gb =
            Garbler::<C, RNG, OtSender, AllWire>::new(channel.clone(), RNG::from_seed(rng.gen()))?;
        let my_input_bits = encode_inputs(&self.opprf_outputs);
        let mods = vec![2; my_input_bits.len()]; // all binary moduli
        let sender_inputs = gb.encode_many(&my_input_bits, &mods)?;
        let receiver_inputs = gb.receive_many(&mods)?;
        Ok((gb, sender_inputs, receiver_inputs))
    }

    /// Compute the intersection.
    pub fn compute_intersection<C, RNG>(&self, channel: &mut C, rng: &mut RNG) -> Result<(), Error>
    where
        C: AbstractChannel + Clone,
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
        C: AbstractChannel + Clone,
        RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>,
    {
        let (mut gb, x, y) = self.compute_setup(channel, rng)?;
        let result = fancy_compute_cardinality(&mut gb, &x, &y)?;
        gb.outputs(&result.wires().to_vec())?;
        Ok(())
    }

    /// Receive encrypted payloads from the Sender.
    pub fn receive_payloads<C>(
        &self,
        payload_len: usize,
        channel: &mut C,
    ) -> Result<Vec<Vec<u8>>, Error>
    where
        C: AbstractChannel + Clone,
    {
        let mut payloads = Vec::new();
        for opprf_output in self.opprf_outputs.iter() {
            let nonce_bytes = channel.read_vec(NONCE_SIZE)?;
            let ciphertext = channel.read_vec(payload_len + PAD_LEN + TAG_SIZE)?;

            let key = opprf_output.prefix(KEY_SIZE);
            let key: &Key<Aes256Gcm> = key.into();
            let cipher = Aes256Gcm::new(&key);

            let nonce = Nonce::from_slice(&nonce_bytes);
            match cipher.decrypt(&nonce, ciphertext.as_ref()) {
                Ok(dec) => {
                    let payload = dec.to_owned().split_off(PAD_LEN);
                    payloads.push(payload)
                }
                Err(_e) => println!("Unable to decrypt, this item doesn't match!"),
            }
        }
        Ok(payloads)
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
                Some(item) => item.entry_with_hindex(),
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
}

impl ReceiverState {
    /// Run the setup phase, producing an evaluator for the next stage.
    pub fn compute_setup<C, RNG>(
        &self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<
        (
            Evaluator<C, RNG, OtReceiver, AllWire>,
            Vec<AllWire>,
            Vec<AllWire>,
        ),
        Error,
    >
    where
        C: AbstractChannel + Clone,
        RNG: CryptoRng + RngCore + SeedableRng<Seed = Block>,
    {
        let nbins = self.cuckoo.nbins;
        let my_input_bits = encode_inputs(&self.opprf_outputs);

        let mut ev = Evaluator::<C, RNG, OtReceiver, AllWire>::new(
            channel.clone(),
            RNG::from_seed(rng.gen()),
        )?;

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
        C: AbstractChannel + Clone,
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
        C: AbstractChannel + Clone,
        RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>,
    {
        let (mut ev, x, y) = self.compute_setup(channel, rng)?;
        let result = fancy_compute_cardinality(&mut ev, &x, &y)?;
        let cardinality_outs = ev
            .outputs(&result.wires().to_vec())?
            .expect("evaluator should produce outputs");

        let mut cardinality: u128 = 0;
        for (i, s) in cardinality_outs.into_iter().enumerate() {
            cardinality += (s as u128) << i;
        }
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
        C: AbstractChannel + Clone,
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
            let key = opprf_output.prefix(KEY_SIZE);
            let key: &Key<Aes256Gcm> = key.into();

            let mut nonce_bytes = [0u8; NONCE_SIZE];
            rng.fill_bytes(&mut nonce_bytes);
            let nonce = Nonce::from_slice(&nonce_bytes);

            let cipher = Aes256Gcm::new(&key);
            let ciphertext = cipher.encrypt(&nonce, payload.as_ref())?;

            channel.write_bytes(&nonce)?;
            channel.write_bytes(&ciphertext)?;
        }
        channel.flush()?;
        Ok(())
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

/// Fancy function to compute the intersection and return encoded vector of 0/1 masks.
fn fancy_compute_intersection<F: Fancy + BinaryBundleGadgets>(
    f: &mut F,
    sender_inputs: &[F::Item],
    receiver_inputs: &[F::Item],
) -> Result<Vec<F::Item>, F::Error> {
    assert_eq!(sender_inputs.len(), receiver_inputs.len());
    sender_inputs
        .chunks(HASH_SIZE * 8)
        .zip_eq(receiver_inputs.chunks(HASH_SIZE * 8))
        .map(|(xs, ys)| {
            f.bin_eq_bundles(
                &BinaryBundle::new(xs.to_vec()),
                &BinaryBundle::new(ys.to_vec()),
            )
        })
        .collect()
}

/// Fancy function to compute the cardinality
fn fancy_compute_cardinality<F: Fancy + BinaryBundleGadgets + FancyBinary>(
    f: &mut F,
    sender_inputs: &[F::Item],
    receiver_inputs: &[F::Item],
) -> Result<BinaryBundle<F::Item>, F::Error> {
    assert_eq!(sender_inputs.len(), receiver_inputs.len());

    let eqs = sender_inputs
        .chunks(HASH_SIZE * 8)
        .zip_eq(receiver_inputs.chunks(HASH_SIZE * 8))
        .map(|(xs, ys)| {
            f.bin_eq_bundles(
                &BinaryBundle::new(xs.to_vec()),
                &BinaryBundle::new(ys.to_vec()),
            )
        })
        .collect::<Result<Vec<F::Item>, F::Error>>()?;

    let mut acc = f.bin_constant_bundle(0, HASH_SIZE * 8)?;

    for b in eqs.into_iter() {
        let one = f.bin_constant_bundle(1, HASH_SIZE * 8)?;
        let b_ws = one
            .iter()
            .map(|w| f.and(w, &b))
            .collect::<Result<Vec<_>, _>>()?;
        let b_binary = BinaryBundle::new(b_ws);

        acc = f.bin_addition_no_carry(&acc, &b_binary)?;
    }

    Ok(acc)
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
    const SET_SIZE: usize = 1 << 6;
    const NUM_DIFF: usize = 10;

    fn psty_cardinality(sender_inputs: Vec<Vec<u8>>, receiver_inputs: Vec<Vec<u8>>) -> usize {
        let (sender, receiver) = UnixStream::pair().unwrap();
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
        state.compute_cardinality(&mut channel, &mut rng).unwrap()
    }

    #[test]
    fn psty_test_cardinality_same_sets() {
        let mut rng = AesRng::new();

        let sender_inputs = rand_vec_vec(SET_SIZE, ITEM_SIZE, &mut rng);
        let receiver_inputs = sender_inputs.clone();

        let cardinality = psty_cardinality(sender_inputs, receiver_inputs);
        assert_eq!(cardinality, SET_SIZE);
    }

    #[test]
    fn psty_test_cardinality_disjoint_sets() {
        let sender_inputs: Vec<Vec<u8>> = (0..SET_SIZE)
            .map(|i: usize| i.to_le_bytes().to_vec())
            .collect_vec();

        // We are assuming here that the set sizes are not too big
        // and that we can represent two disjoint sets using the
        // available bits of precisions. This is okay because sets
        // larger than that would need to be handle differently at
        // the level of the psi protocol.
        let receiver_inputs = (0..SET_SIZE)
            .map(|i: usize| (i + SET_SIZE).to_le_bytes().to_vec())
            .collect_vec();

        let cardinality = psty_cardinality(sender_inputs, receiver_inputs);

        assert_eq!(cardinality, 0);
    }

    #[test]
    fn psty_test_cardinality_subsets_different_set_size() {
        if SET_SIZE >= NUM_DIFF {
            let mut rng = AesRng::new();
            let sender_inputs: Vec<Vec<u8>> = rand_vec_vec(SET_SIZE, ITEM_SIZE, &mut rng);
            let mut receiver_inputs = vec![vec![0; ITEM_SIZE]; SET_SIZE - NUM_DIFF];
            receiver_inputs.clone_from_slice(&sender_inputs[NUM_DIFF..]);

            let cardinality = psty_cardinality(sender_inputs, receiver_inputs);

            assert_eq!(cardinality, SET_SIZE - NUM_DIFF);
        }
    }

    #[test]
    // test fancy cardinality for sets that only differ in a few elements
    fn psty_test_cardinality_few_elements_diff() {
        let mut rng = AesRng::new();
        let sender_inputs: Vec<Vec<u8>> = rand_vec_vec(SET_SIZE, ITEM_SIZE, &mut rng);
        let mut receiver_inputs = sender_inputs.clone();

        for i in 0..NUM_DIFF {
            // change the value of the first byte at that index,
            // if its above 0, set it to 0, otherwise set it to 1.
            // this ensures that
            // receiver_inputs[differing_index] != sender_inputs[differing_index]
            receiver_inputs[i][0] = if receiver_inputs[i][0] > 0 { 0 } else { 1 };
        }

        let cardinality = psty_cardinality(sender_inputs, receiver_inputs);
        assert_eq!(cardinality, SET_SIZE - NUM_DIFF);
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
