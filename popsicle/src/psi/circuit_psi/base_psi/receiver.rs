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
    pub(crate) key: Block,
    pub(crate) opprf_set: KmprtReceiver,
    pub(crate) opprf_payload: Option<KmprtReceiver>,
    pub(crate) state: Option<ReceiverState>,
}

/// A strut defining the `OpprfReceiver`'s State
///
/// Specifically, the `ReceiverState` describes how the OPPRF is
/// queried by the `OpprfReceiver` and what output they receiver:
/// - `opprf_set_in` and `opprf_payloads_in` input queries to the OPPRF.
/// - `opprf_set_out` and `opprf_payloads_out` are the results of
/// the OPPRF on those respective queries.
/// When the OPPRF is called on a programmed input, it returns a
/// programmed output. When the OPPRF is called on any other value,
/// it returns a value that is sampled uniformly random. The OPPRF
/// guarantees that all its outputs, programmed or random, are indistinguishable
/// from one another.
pub struct ReceiverState {
    pub(crate) opprf_set_in: Vec<Block>,
    pub(crate) opprf_set_out: Option<Vec<Block512>>,
    pub(crate) opprf_payloads_in: Option<Vec<Block512>>,
    pub(crate) opprf_payloads_out: Option<Vec<Block512>>,
}

impl BasePsi for OpprfReceiver {
    /// Initialize the `OpprfReceiver` with their own channel and key.
    ///
    /// If the payloads are not needed for the computation, `payload_existence`
    /// should be set to false.
    fn init<C, RNG>(channel: &mut C, rng: &mut RNG, payload_existence: bool) -> Result<Self, Error>
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

        let opprf_set = KmprtReceiver::init(channel, rng)?;
        channel.flush()?;

        let mut opprf_payload = None;
        if payload_existence {
            opprf_payload = Some(KmprtReceiver::init(channel, rng)?);
            channel.flush()?;
        }

        Ok(Self {
            key,
            opprf_set,
            opprf_payload,
            state: None,
        })
    }
    /// Hash the data using cuckoo hashing
    fn hash_data<C, RNG>(
        &mut self,
        set: &[Vec<u8>],
        payloads: Option<&[Block512]>,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<(), Error>
    where
        C: AbstractChannel,
        RNG: RngCore + CryptoRng + SeedableRng,
    {
        let mut hashed_inputs = compress_and_hash_inputs(set, self.key);

        // refresh the key until the cuckoo hash is not full
        let cuckoo = loop {
            match CuckooHash::new(&hashed_inputs, NHASHES) {
                Ok(res) => break res,
                Err(_e) => {
                    self.key = rng.gen();
                    hashed_inputs = compress_and_hash_inputs(set, self.key);
                }
            }
        };

        channel.write_block(&self.key)?;
        channel.flush()?;
        channel.write_usize(cuckoo.nbins)?; // The number of bins is sent out to the sender
        channel.flush()?;

        let opprf_set_in = cuckoo_place_ids(&cuckoo.items, rng);

        let mut opprf_payloads_in = None;
        if let Some(p) = payloads {
            opprf_payloads_in = Some(cuckoo_place_payloads(&cuckoo.items, p, rng));
        }
        self.state = Some(ReceiverState {
            opprf_set_in,
            opprf_set_out: None,
            opprf_payloads_in,
            opprf_payloads_out: None,
        });
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
        self.state.as_mut().unwrap().opprf_set_out = Some(self.opprf_set.receive(
            channel,
            &self.state.as_ref().unwrap().opprf_set_in,
            rng,
        )?);
        if let Some(opprf_p) = self.opprf_payload.as_mut() {
            self.state.as_mut().unwrap().opprf_payloads_out =
                Some(opprf_p.receive(channel, &self.state.as_ref().unwrap().opprf_set_in, rng)?);
        }
        Ok(())
    }
    fn encode_circuit_inputs<F, E>(
        &mut self,
        gc_party: &mut F,
    ) -> Result<CircuitInputs<F::Item>, Error>
    where
        F: FancyInput<Item = AllWire, Error = E>,
        E: Debug,
        Error: From<E>,
    {
        // We compute the number of wires that the receivers should
        // expect from the sender by taking the size of an element in
        // bytes, turning it into bits, and then multiplying it by the
        // number of elements the parties are intersecting.
        // Note that PSTY expects parties to have the same set sizes.
        let elements_binary_len =
            ELEMENT_SIZE * 8 * self.state.as_ref().unwrap().opprf_set_in.len();

        // First receive encoded inputs from the `OpprfSender`
        let sender_set_elements: Vec<F::Item> =
            bin_receive_many_block512(gc_party, elements_binary_len)?;

        // Then send encoded inputs
        let receiver_set_elements: Vec<F::Item> = bin_encode_many_block512(
            gc_party,
            &self.state.as_ref().unwrap().opprf_set_out.as_ref().unwrap(),
            ELEMENT_SIZE,
        )?;

        let mut result = CircuitInputs {
            sender_set_elements,
            receiver_set_elements,
            sender_payloads_masked: None,
            receiver_payloads: None,
            masks: None,
        };
        // If payloads exist, then encode them
        if let Some(p) = &self.state.as_ref().unwrap().opprf_payloads_in {
            // We compute the number of wires that the receivers should
            // expect from the sender by taking the size of a payload in
            // bytes, turning it into bits, and then multiplying it by the
            // number of elements the parties are intersecting.
            // Note that PSTY expects parties to have the same set sizes.
            let payloads_binary_len = PAYLOAD_SIZE
                * 8
                * self
                    .state
                    .as_ref()
                    .unwrap()
                    .opprf_payloads_in
                    .as_ref()
                    .unwrap()
                    .len();

            let sender_payloads: Vec<F::Item> =
                bin_receive_many_block512(gc_party, payloads_binary_len)?;
            let receiver_payloads: Vec<F::Item> = bin_encode_many_block512(
                gc_party,
                &self
                    .state
                    .as_ref()
                    .unwrap()
                    .opprf_payloads_in
                    .as_ref()
                    .unwrap(),
                PAYLOAD_SIZE,
            )?;
            let masks: Vec<F::Item> = bin_encode_many_block512(
                gc_party,
                &self
                    .state
                    .as_ref()
                    .unwrap()
                    .opprf_payloads_out
                    .as_ref()
                    .unwrap(),
                PAYLOAD_SIZE,
            )?;

            result.sender_payloads_masked = Some(sender_payloads);
            result.receiver_payloads = Some(receiver_payloads);
            result.masks = Some(masks);
        }

        Ok(result)
    }
}
