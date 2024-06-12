use crate::{
    circuit_psi::{base_psi::*, utils::*, *},
    cuckoo::CuckooHash,
    utils::*,
};

use ocelot::oprf::KmprtReceiver;
use scuttlebutt::{Block, Block512};

/// A strut defining the receiver in the base circuit PSI computation.
/// A receiver here refers to the party which queries the OPPRF in this
/// computation.
pub struct OpprfReceiver {
    /// The hashing key
    pub key: Block,
    /// The opprf for primary keys
    pub opprf_primary_keys: KmprtReceiver,
    /// The opprf for payloads
    pub opprf_payload: Option<KmprtReceiver>,
    /// The opprf queries and outputs
    pub state: ReceiverState,
}

/// A strut defining the `OpprfReceiver`'s State
///
/// Specifically, the `ReceiverState` describes how the OPPRF is
/// queried by the `OpprfReceiver` and what output they receiver:
/// - `opprf_primary_keys_in` and `opprf_payloads_in` input queries to the OPPRF.
/// - `opprf_primary_keys_out` and `opprf_payloads_out` are the results of
/// the OPPRF on those respective queries.
/// When the OPPRF is called on a programmed input, it returns a
/// programmed output. When the OPPRF is called on any other value,
/// it returns a value that is sampled uniformly random. The OPPRF
/// guarantees that all its outputs, programmed or random, are indistinguishable
/// from one another.
#[derive(Default)]
pub struct ReceiverState {
    /// The opprf query for primary keys
    pub opprf_primary_keys_in: Vec<Block>,
    /// The opprf output for primary keys
    pub opprf_primary_keys_out: Vec<Block512>,
    /// The opprf query for payloads
    pub opprf_payloads_in: Vec<Block512>,
    /// The opprf output for payloads
    pub opprf_payloads_out: Vec<Block512>,
}

impl BasePsi for OpprfReceiver {
    /// Initialize the `OpprfReceiver` with their own channel and key.
    ///
    /// If the payloads are not needed for the computation, `payload_existence`
    /// should be set to false.
    fn init<C, RNG>(channel: &mut C, rng: &mut RNG, has_payload: bool) -> Result<Self, Error>
    where
        C: AbstractChannel,
        RNG: RngCore + CryptoRng + SeedableRng,
    {
        // The key used during hashing is known to both
        // parties and allows them to hash the same inputs
        // to the same outputs.
        let key = rng.gen();
        channel.write_block(&key)?;
        channel.flush()?;

        let opprf_primary_keys = KmprtReceiver::init(channel, rng)?;
        channel.flush()?;

        let mut opprf_payload = None;
        if has_payload {
            opprf_payload = Some(KmprtReceiver::init(channel, rng)?);
            channel.flush()?;
        }

        Ok(Self {
            key,
            opprf_primary_keys,
            opprf_payload,
            state: Default::default(),
        })
    }
    /// Hash the data using cuckoo hashing
    fn hash_data<C, RNG>(
        &mut self,
        primary_keys: &[PrimaryKey],
        payloads: Option<&[Payload]>,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<(), Error>
    where
        C: AbstractChannel,
        RNG: RngCore + CryptoRng + SeedableRng,
    {
        let mut hashed_inputs = compress_and_hash_inputs(primary_keys, self.key);

        // refresh the key until the cuckoo hash is not full
        let cuckoo = loop {
            match CuckooHash::new(&hashed_inputs, NHASHES) {
                Ok(res) => break res,
                Err(_e) => {
                    self.key = rng.gen();
                    hashed_inputs = compress_and_hash_inputs(primary_keys, self.key);
                }
            }
        };

        channel.write_block(&self.key)?;
        channel.write_usize(cuckoo.nbins)?; // The number of bins is sent out to the sender
        channel.flush()?;

        let opprf_primary_keys_in = cuckoo_place_ids(&cuckoo.items, rng);

        let mut opprf_payloads_in = vec![];
        if payloads.is_some() {
            opprf_payloads_in = cuckoo_place_payloads(&cuckoo.items, payloads.unwrap(), rng);
        }
        self.state = ReceiverState {
            opprf_primary_keys_in,
            opprf_primary_keys_out: vec![],
            opprf_payloads_in,
            opprf_payloads_out: vec![],
        };
        Ok(())
    }

    fn opprf_exchange<C, RNG>(&mut self, channel: &mut C, rng: &mut RNG) -> Result<(), Error>
    where
        C: AbstractChannel,
        RNG: RngCore + CryptoRng + SeedableRng,
    {
        // The receiver queries the opprf with their inputs if the receiver
        // and sender's inputs match, the receiver gets the same programmed
        // output as the sender, otherwise, they receive a random value.
        self.state.opprf_primary_keys_out =
            self.opprf_primary_keys
                .receive(channel, &self.state.opprf_primary_keys_in, rng)?;
        if !self.state.opprf_payloads_in.is_empty() {
            self.state.opprf_payloads_out = self.opprf_payload.as_mut().unwrap().receive(
                channel,
                &self.state.opprf_primary_keys_in,
                rng,
            )?;
        }
        Ok(())
    }
    fn encode_circuit_inputs<F, E>(
        &mut self,
        gc_party: &mut F,
    ) -> Result<CircuitInputs<F::Item>, Error>
    where
        F: FancyInput<Item = WireMod2, Error = E>,
        E: Debug,
        Error: From<E>,
    {
        // We compute the number of wires that the receivers should
        // expect from the sender by taking the size of an element in
        // bytes, turning it into bits, and then multiplying it by the
        // number of primary keys the parties are intersecting.
        // Note that PSTY expects parties to have the same set sizes.
        let primary_keys_binary_len = PRIMARY_KEY_SIZE * 8 * self.state.opprf_primary_keys_in.len();

        // First receive encoded inputs from the `OpprfSender`
        let sender_primary_keys: Vec<F::Item> =
            bin_receive_many_block512(gc_party, primary_keys_binary_len)?;

        // Then send encoded inputs
        let receiver_primary_keys: Vec<F::Item> = bin_encode_many_block512(
            gc_party,
            &self.state.opprf_primary_keys_out,
            PRIMARY_KEY_SIZE,
        )?;

        let mut result = CircuitInputs {
            sender_primary_keys,
            receiver_primary_keys,
            sender_payloads_masked: vec![],
            receiver_payloads: vec![],
            masks: vec![],
        };
        // If payloads exist, then encode them
        if !&self.state.opprf_payloads_in.is_empty() {
            // We compute the number of wires that the receivers should
            // expect from the sender by taking the size of a payload in
            // bytes, turning it into bits, and then multiplying it by the
            // number of primary keys the parties are intersecting.
            // Note that PSTY expects parties to have the same set sizes.
            let payloads_binary_len = PAYLOAD_SIZE * 8 * self.state.opprf_payloads_in.len();

            let sender_payloads: Vec<F::Item> =
                bin_receive_many_block512(gc_party, payloads_binary_len)?;
            let receiver_payloads: Vec<F::Item> =
                bin_encode_many_block512(gc_party, &self.state.opprf_payloads_in, PAYLOAD_SIZE)?;
            let masks: Vec<F::Item> =
                bin_encode_many_block512(gc_party, &self.state.opprf_payloads_out, PAYLOAD_SIZE)?;

            result.sender_payloads_masked = sender_payloads;
            result.receiver_payloads = receiver_payloads;
            result.masks = masks;
        }

        Ok(result)
    }
}
