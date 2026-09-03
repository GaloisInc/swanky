//! Implementation of the Pinkas-Schneider-Tkachenko-Yanai "extended" private
//! set intersection protocol (cf. <https://eprint.iacr.org/2019/241>).

use crate::{cuckoo::CuckooHash, utils};
use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit},
};
use fancy_circuits::{
    BinaryBundle,
    binary::{BinaryAdditionNoCarry, BinaryConstant, BinaryEquality},
};
use fancy_garbling::AllWire;
use fancy_traits::{Circuit, FancyBinary, FancyBinaryConstant, FancyEncode, FancyOutput};
use itertools::Itertools;
use rand::{CryptoRng, Rng, RngExt, SeedableRng};
use swanky_adversary::SemiHonest;
use swanky_block::{Block, Block512};
use swanky_channel::Channel;
use swanky_error::{ErrorKind, WrapErr};
use swanky_oprf_kmprt::{Receiver as KmprtReceiver, Sender as KmprtSender};
use swanky_ot_alsz_kos::alsz::{Receiver as OtReceiver, Sender as OtSender};
use swanky_twopac::semihonest::{Evaluator, Garbler};

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
    pub fn init<RNG: Rng + CryptoRng + SeedableRng>(
        channel: &mut Channel,
        rng: &mut RNG,
    ) -> swanky_error::Result<Self> {
        let opprf = KmprtSender::init(channel, rng).wrap_err(
            ErrorKind::InitializationError,
            "Failed to initialize KMPRT sender.",
        )?;
        Ok(Self { opprf })
    }

    /// Run the PSI protocol over `inputs`.
    pub fn send<RNG: Rng + CryptoRng + SeedableRng>(
        &mut self,
        inputs: &[Msg],
        channel: &mut Channel,
        rng: &mut RNG,
    ) -> swanky_error::Result<SenderState> {
        // receive cuckoo hash info from sender
        let key = channel.read::<Block>()?;
        let hashes = utils::compress_and_hash_inputs(inputs, key);

        // map inputs to table using all hash functions
        let nbins = channel.read::<usize>()?;
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
                table[bins[0]].push(rng.random());
            }
        }

        // select the target values
        let ts = (0..nbins).map(|_| rng.random::<Block512>()).collect_vec();

        let points = table
            .into_iter()
            .zip_eq(ts.iter())
            .flat_map(|(bin, t)| {
                // map all the points in a bin to the same tag
                bin.into_iter().map(move |item| (item, *t))
            })
            .collect_vec();

        self.opprf
            .send(channel, &points, nbins, rng)
            .wrap_err(ErrorKind::OtherError, "Failed to run PSI as sender.")?;

        Ok(SenderState { opprf_outputs: ts })
    }
}

impl SenderState {
    /// Run the setup phase, producing a garbler for the next stage.
    pub fn compute_setup<RNG>(
        &self,
        channel: &mut Channel,
        rng: &mut RNG,
    ) -> swanky_error::Result<(Garbler<RNG, OtSender, AllWire>, Vec<AllWire>, Vec<AllWire>)>
    where
        RNG: Rng + CryptoRng + SeedableRng<Seed = Block>,
    {
        let mut gb = Garbler::<RNG, OtSender, AllWire>::new(channel, RNG::from_seed(rng.random()))
            .wrap_err(
                ErrorKind::InitializationError,
                "Failed to initialize garbler during setup.",
            )?;
        let my_input_bits = encode_inputs(&self.opprf_outputs);
        let mods = vec![2; my_input_bits.len()]; // all binary moduli
        let sender_inputs = gb.encode_many(&my_input_bits, &mods, channel)?;
        let receiver_inputs = gb.receive_many(&mods, channel)?;
        Ok((gb, sender_inputs, receiver_inputs))
    }

    /// Compute the intersection.
    pub fn compute_intersection<RNG>(
        &self,
        channel: &mut Channel,
        rng: &mut RNG,
    ) -> swanky_error::Result<()>
    where
        RNG: Rng + CryptoRng + SeedableRng<Seed = Block>,
    {
        let (mut gb, x, y) = self.compute_setup(channel, rng)?;
        let outs = fancy_compute_intersection(&mut gb, &x, &y, channel)?;
        gb.outputs(&outs, channel)?;
        Ok(())
    }

    /// Compute the cardinality of the intersection.
    pub fn compute_cardinality<RNG>(
        &self,
        channel: &mut Channel,
        rng: &mut RNG,
    ) -> swanky_error::Result<()>
    where
        RNG: Rng + CryptoRng + SeedableRng<Seed = Block>,
    {
        let (mut gb, x, y) = self.compute_setup(channel, rng)?;
        let result = fancy_compute_cardinality(&mut gb, &x, &y, channel)?;
        gb.outputs(result.wires(), channel)?;
        Ok(())
    }

    /// Receive encrypted payloads from the Sender.
    pub fn receive_payloads(
        &self,
        payload_len: usize,
        channel: &mut Channel,
    ) -> swanky_error::Result<Vec<Vec<u8>>> {
        let mut payloads = Vec::new();
        for opprf_output in self.opprf_outputs.iter() {
            let mut nonce_bytes = [0u8; NONCE_SIZE];
            let mut ciphertext = vec![0u8; payload_len + PAD_LEN + TAG_SIZE];
            channel.read_bytes(&mut nonce_bytes)?;
            channel.read_bytes(&mut ciphertext)?;

            let key = opprf_output.prefix(KEY_SIZE);
            let key: &Key<Aes256Gcm> = key.try_into().unwrap();
            let cipher = Aes256Gcm::new(key);

            let nonce = Nonce::from(nonce_bytes);
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
    pub fn init<RNG: Rng + CryptoRng + SeedableRng>(
        channel: &mut Channel,
        rng: &mut RNG,
    ) -> swanky_error::Result<Self> {
        let opprf = KmprtReceiver::init(channel, rng).wrap_err(
            ErrorKind::InitializationError,
            "Failed to initialize KMPRT receiver.",
        )?;
        Ok(Self { opprf })
    }

    /// Run the PSI protocol over `inputs`.
    pub fn receive<RNG: Rng + CryptoRng + SeedableRng>(
        &mut self,
        inputs: &[Msg],
        channel: &mut Channel,
        rng: &mut RNG,
    ) -> swanky_error::Result<ReceiverState> {
        let key = rng.random();
        let hashed_inputs = utils::compress_and_hash_inputs(inputs, key);
        let cuckoo = CuckooHash::new(&hashed_inputs, NHASHES).wrap_err(
            ErrorKind::InitializationError,
            "Failed to create new Cuckoo hash.",
        )?;

        // Send cuckoo hash info to receiver.
        channel.write(&key)?;
        channel.write(&cuckoo.nbins)?;

        // Build `table` to include a cuckoo hash entry xored with its hash
        // index, if such a entry exists, or a random value.
        let table = cuckoo
            .items
            .iter()
            .map(|opt_item| match opt_item {
                Some(item) => item.entry_with_hindex(),
                None => rng.random(),
            })
            .collect::<Vec<Block>>();

        let opprf_outputs = self
            .opprf
            .receive(channel, &table, rng)
            .wrap_err(ErrorKind::OtherError, "Failed to receive OPPRF outputs.")?;

        Ok(ReceiverState {
            opprf_outputs,
            cuckoo,
            inputs: inputs.to_vec(),
        })
    }
}

impl ReceiverState {
    /// Run the setup phase, producing an evaluator for the next stage.
    pub fn compute_setup<RNG>(
        &self,
        channel: &mut Channel,
        rng: &mut RNG,
    ) -> swanky_error::Result<(
        Evaluator<RNG, OtReceiver, AllWire>,
        Vec<AllWire>,
        Vec<AllWire>,
    )>
    where
        RNG: CryptoRng + Rng + SeedableRng<Seed = Block>,
    {
        let nbins = self.cuckoo.nbins;
        let my_input_bits = encode_inputs(&self.opprf_outputs);

        let mut ev =
            Evaluator::<RNG, OtReceiver, AllWire>::new(channel, RNG::from_seed(rng.random()))
                .wrap_err(
                    ErrorKind::InitializationError,
                    "Failed to initialize receiver during setup.",
                )?;

        let mods = vec![2; nbins * HASH_SIZE * 8];
        let sender_inputs = ev.receive_many(&mods, channel)?;
        let receiver_inputs = ev.encode_many(&my_input_bits, &mods, channel)?;
        Ok((ev, sender_inputs, receiver_inputs))
    }

    /// Compute the intersection.
    pub fn compute_intersection<RNG>(
        &self,
        channel: &mut Channel,
        rng: &mut RNG,
    ) -> swanky_error::Result<Vec<Msg>>
    where
        RNG: Rng + CryptoRng + SeedableRng<Seed = Block>,
    {
        let (mut ev, x, y) = self.compute_setup(channel, rng)?;
        let outs = fancy_compute_intersection(&mut ev, &x, &y, channel)?;
        let mpc_outs = ev
            .outputs(&outs, channel)?
            .expect("evaluator should produce outputs");

        let mut intersection = Vec::new();
        for (opt_item, in_intersection) in self.cuckoo.items.iter().zip_eq(mpc_outs) {
            if let Some(item) = opt_item
                && in_intersection == 1_u16
            {
                intersection.push(self.inputs[item.input_index].clone());
            }
        }
        Ok(intersection)
    }

    /// Compute the cardinality of the intersection.
    pub fn compute_cardinality<RNG>(
        &self,
        channel: &mut Channel,
        rng: &mut RNG,
    ) -> swanky_error::Result<usize>
    where
        RNG: Rng + CryptoRng + SeedableRng<Seed = Block>,
    {
        let (mut ev, x, y) = self.compute_setup(channel, rng)?;
        let result = fancy_compute_cardinality(&mut ev, &x, &y, channel)?;
        let cardinality_outs = ev
            .outputs(result.wires(), channel)?
            .expect("evaluator should produce outputs");

        let mut cardinality = 0;
        for (i, s) in cardinality_outs.into_iter().enumerate() {
            cardinality += (s as usize) << i;
        }
        Ok(cardinality)
    }

    /// Send encrypted payloads to the Receiver, who can only decrypt a payload if they
    /// share the associated element in the intersection.
    pub fn send_payloads<RNG>(
        &self,
        payloads: &[Vec<u8>],
        channel: &mut Channel,
        rng: &mut RNG,
    ) -> swanky_error::Result<()>
    where
        RNG: Rng + CryptoRng + SeedableRng<Seed = Block>,
    {
        let payload_len = payloads[0].len();
        if !(payloads.iter().all(|p| p.len() == payload_len)) {
            swanky_error::bail!(ErrorKind::OtherError, "Invalid payloads length");
        }
        let dummy_payload = vec![0; payload_len];

        for (opt_item, opprf_output) in self.cuckoo.items.iter().zip_eq(self.opprf_outputs.iter()) {
            let mut payload = vec![0; PAD_LEN];
            if let Some(item) = opt_item {
                if item.input_index >= payloads.len() {
                    swanky_error::bail!(ErrorKind::OtherError, "Invalid payloads length");
                }
                payload.extend_from_slice(&payloads[item.input_index]);
            } else {
                payload.extend_from_slice(&dummy_payload);
            };
            let key = opprf_output.prefix(KEY_SIZE);
            let key: &Key<Aes256Gcm> = key.try_into().unwrap();

            let mut nonce_bytes = [0u8; NONCE_SIZE];
            rng.fill_bytes(&mut nonce_bytes);
            let nonce = Nonce::from(nonce_bytes);

            let cipher = Aes256Gcm::new(key);
            let ciphertext = cipher.encrypt(&nonce, payload.as_ref()).map_err(|_| {
                swanky_error::Error::new(
                    ErrorKind::OtherError,
                    "Failed to encrypt payload.",
                    None, // aes_gcm::Error does not implement std::error::Error
                )
            })?;

            channel.write_bytes(&nonce)?;
            channel.write_bytes(&ciphertext)?;
        }
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
fn fancy_compute_intersection<F: FancyBinary>(
    f: &mut F,
    sender_inputs: &[F::Item],
    receiver_inputs: &[F::Item],
    channel: &mut Channel,
) -> swanky_error::Result<Vec<F::Item>> {
    assert_eq!(sender_inputs.len(), receiver_inputs.len());
    sender_inputs
        .chunks(HASH_SIZE * 8)
        .zip_eq(receiver_inputs.chunks(HASH_SIZE * 8))
        .map(|(xs, ys)| {
            BinaryEquality::new().execute(
                f,
                (
                    &BinaryBundle::new(xs.to_vec()),
                    &BinaryBundle::new(ys.to_vec()),
                ),
                channel,
            )
        })
        .collect()
}

/// Fancy function to compute the cardinality
fn fancy_compute_cardinality<F: FancyBinary + FancyBinaryConstant>(
    f: &mut F,
    sender_inputs: &[F::Item],
    receiver_inputs: &[F::Item],
    channel: &mut Channel,
) -> swanky_error::Result<BinaryBundle<F::Item>> {
    assert_eq!(sender_inputs.len(), receiver_inputs.len());

    let eqs = sender_inputs
        .chunks(HASH_SIZE * 8)
        .zip_eq(receiver_inputs.chunks(HASH_SIZE * 8))
        .map(|(xs, ys)| {
            BinaryEquality::new().execute(
                f,
                (
                    &BinaryBundle::new(xs.to_vec()),
                    &BinaryBundle::new(ys.to_vec()),
                ),
                channel,
            )
        })
        .collect::<swanky_error::Result<Vec<F::Item>>>()?;

    let mut acc = BinaryConstant::new(0, HASH_SIZE * 8).execute(f, (), channel)?;
    let one = BinaryConstant::new(1, HASH_SIZE * 8).execute(f, (), channel)?;

    for b in eqs.into_iter() {
        let b_ws = one
            .iter()
            .map(|w| f.and(w, &b, channel))
            .collect::<Result<Vec<_>, _>>()?;
        let b_binary = BinaryBundle::new(b_ws);
        acc = BinaryAdditionNoCarry::new().execute(f, (&acc, &b_binary), channel)?;
    }

    Ok(acc)
}

impl SemiHonest for Sender {}
impl SemiHonest for Receiver {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::rand_vec_vec;
    use swanky_rng::SwankyRng;

    const ITEM_SIZE: usize = 8;
    const SET_SIZE: usize = 1 << 6;
    const NUM_DIFF: usize = 10;

    fn psty_cardinality(sender_inputs: Vec<Vec<u8>>, receiver_inputs: Vec<Vec<u8>>) -> usize {
        let (_, output) = swanky_channel::local::local_channel_pair(
            |channel| {
                let mut rng = SwankyRng::new();
                let mut psi = Sender::init(channel, &mut rng).unwrap();

                let state = psi.send(&sender_inputs, channel, &mut rng).unwrap();
                state.compute_cardinality(channel, &mut rng).unwrap();
                Ok(())
            },
            |channel| {
                let mut rng = SwankyRng::new();
                let mut psi = Receiver::init(channel, &mut rng).unwrap();

                let state = psi.receive(&receiver_inputs, channel, &mut rng).unwrap();
                Ok(state.compute_cardinality(channel, &mut rng).unwrap())
            },
        )
        .unwrap();
        output
    }

    #[test]
    fn psty_test_cardinality_same_sets() {
        let mut rng = SwankyRng::new();

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
            let mut rng = SwankyRng::new();
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
        let mut rng = SwankyRng::new();
        let sender_inputs: Vec<Vec<u8>> = rand_vec_vec(SET_SIZE, ITEM_SIZE, &mut rng);
        let mut receiver_inputs = sender_inputs.clone();

        for receiver_input in receiver_inputs.iter_mut().take(NUM_DIFF) {
            // change the value of the first byte at that index,
            // if its above 0, set it to 0, otherwise set it to 1.
            // this ensures that
            // receiver_inputs[differing_index] != sender_inputs[differing_index]
            receiver_input[0] = if receiver_input[0] > 0 { 0 } else { 1 };
        }

        let cardinality = psty_cardinality(sender_inputs, receiver_inputs);
        assert_eq!(cardinality, SET_SIZE - NUM_DIFF);
    }

    #[test]
    fn psty_test_cardinality_random_sets() {
        let mut rng = SwankyRng::new();

        let sender_inputs = rand_vec_vec(SET_SIZE, ITEM_SIZE, &mut rng);
        let receiver_inputs = rand_vec_vec(SET_SIZE, ITEM_SIZE, &mut rng);

        let cardinality = psty_cardinality(sender_inputs.clone(), receiver_inputs.clone());

        let mut true_cardinality = 0;
        for (s, r) in sender_inputs.iter().zip(receiver_inputs) {
            let mut s_buf = [0u8; 8];
            s_buf[..8].copy_from_slice(&s[..8]);
            let s_64 = u64::from_le_bytes(s_buf);

            let mut r_buf = [0u8; 8];
            r_buf[..8].copy_from_slice(&r[..8]);
            let r_64 = u64::from_le_bytes(r_buf);

            true_cardinality += if s_64 == r_64 { 1 } else { 0 };
        }
        assert_eq!(cardinality, true_cardinality);
    }

    #[test]
    fn payloads() {
        let payload_size = 16;
        let mut rng = SwankyRng::new();
        let sender_inputs = rand_vec_vec(SET_SIZE, ITEM_SIZE, &mut rng);
        let receiver_inputs = sender_inputs.clone();
        let payloads = rand_vec_vec(SET_SIZE, payload_size, &mut rng);

        let (received_payloads, _) = swanky_channel::local::local_channel_pair(
            |channel| {
                let mut rng = SwankyRng::new();
                let mut psi = Sender::init(channel, &mut rng).unwrap();
                let state = psi.send(&sender_inputs, channel, &mut rng).unwrap();
                Ok(state.receive_payloads(payload_size, channel).unwrap())
            },
            |channel| {
                let mut rng = SwankyRng::new();
                let mut psi = Receiver::init(channel, &mut rng).unwrap();

                let state = psi.receive(&receiver_inputs, channel, &mut rng).unwrap();
                state.send_payloads(&payloads, channel, &mut rng).unwrap();
                Ok(())
            },
        )
        .unwrap();

        for payload in payloads.iter() {
            assert!(received_payloads.contains(payload));
        }
    }
}
