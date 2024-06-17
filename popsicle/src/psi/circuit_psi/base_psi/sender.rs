use crate::{
    circuit_psi::{base_psi::*, utils::*, *},
    cuckoo::CuckooHash,
    utils,
};

use ocelot::oprf::KmprtSender;
use scuttlebutt::{Block, Block512};

/// A struct defining the sender in the base circuit PSI computation.
/// A sender here refers to the party which programs the OPPRF in this
/// computation.
pub struct OpprfSender {
    /// The hashing key
    pub key: Block,
    /// The number of hashing bins
    pub nbins: Option<usize>,
    /// The opprf for set primary keys
    pub opprf_primary_keys: KmprtSender,
    /// The opprf for payloads
    pub opprf_payload: Option<KmprtSender>,
    /// The opprf programming
    pub state: SenderState,
}

/// A strut defining the `OpprfSender`'s State
///
/// Specifically, the `SenderState` describes how the OPPRF is
/// programmed by the `OpprfSender`:
/// - `opprf_primary_keys_in` and `opprf_payloads_in` are the programmed
/// inputs of the OPPRF.
/// - `opprf_primary_keys_out` and `opprf_payloads_out` are their respective
/// programmed outputs.
/// When the OPPRF is called on a programmed input, it returns a
/// programmed output. When the OPPRF is called on any other value,
/// it returns a value that is sampled uniformly random.
#[derive(Default)]
pub struct SenderState {
    /// The opprf programmed inputs for the set primary keys
    pub opprf_primary_keys_in: Vec<Vec<Block>>,
    /// The opprf programmed output for the set primary keys
    pub opprf_primary_keys_out: Vec<Block512>,
    /// The opprf programmed inputs for the payloads
    pub opprf_payloads_in: Vec<Vec<Block512>>,
    /// The opprf programmed outputs for the payloads
    pub opprf_payloads_out: Vec<Block512>,
}

impl BasePsi for OpprfSender {
    /// Initialize the `OpprfSender` with their own channel and key.
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
        let key = channel.read_block()?;
        let opprf_primary_keys = KmprtSender::init(channel, rng)?;
        let mut opprf_payload = None;
        if has_payload {
            opprf_payload = Some(KmprtSender::init(channel, rng)?);
        }

        Ok(Self {
            key,
            nbins: None,
            opprf_primary_keys,
            opprf_payload,
            state: Default::default(),
        })
    }
    /// Hash the data using simple hashing
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
        // refresh key if cuckoo hash is full
        self.key = channel.read_block()?;

        // Receive cuckoo hash info from sender
        // The receiver determines the number of bins
        // to be used by the sender.
        let nbins = channel.read_usize()?;

        self.nbins = Some(nbins);

        let hashes = utils::compress_and_hash_inputs(primary_keys, self.key);

        let mut opprf_primary_keys_in = vec![Vec::new(); nbins];
        let opprf_primary_keys_out = (0..nbins).map(|_| rng.gen::<Block512>()).collect();

        let mut opprf_payloads_in = vec![];
        let mut opprf_payloads_out = vec![];
        if payloads.is_some() {
            opprf_payloads_in = vec![Vec::new(); nbins];
            opprf_payloads_out = (0..nbins).map(|_| rng.gen::<Block512>()).collect();
        }

        for (i, x) in hashes.iter().enumerate() {
            let mut bins = Vec::with_capacity(NHASHES);
            for h in 0..NHASHES {
                // First find the bin where the item will be placed
                let bin = CuckooHash::bin(*x, h, nbins);
                // Then place the item in that bin while keeping track
                // of the index of the hash function used in the process
                opprf_primary_keys_in[bin].push(*x ^ Block::from(h as u128));
                if payloads.is_some() {
                    // The payload values are masked before being sent out
                    // and placed in the same bin index as the primary key they
                    // are associated with.
                    opprf_payloads_in[bin].push(payloads.unwrap()[i] ^ opprf_payloads_out[bin]);
                }
                bins.push(bin);
            }
            // if j = H1(y) = H2(y) for some y, then P2 adds a uniformly random primary key to
            // table2[j] & payload[j]. This avoid possible leakage
            if bins.iter().skip(1).all(|&x| x == bins[0]) {
                opprf_primary_keys_in[bins[0]].push(rng.gen());
                if payloads.is_some() {
                    opprf_payloads_in[bins[0]].push(rng.gen());
                }
            }
        }

        self.state = SenderState {
            opprf_primary_keys_in,
            opprf_primary_keys_out,
            opprf_payloads_in,
            opprf_payloads_out,
        };

        Ok(())
    }

    fn opprf_exchange<C, RNG>(&mut self, channel: &mut C, rng: &mut RNG) -> Result<(), Error>
    where
        C: AbstractChannel,
        RNG: RngCore + CryptoRng + SeedableRng,
    {
        // The Opprf in swanky expects the programmed input and outputs
        // to be passed as pairs

        let opprf_program = flatten_bin_tags(
            &self.state.opprf_primary_keys_in,
            &self.state.opprf_primary_keys_out,
        );
        self.opprf_primary_keys
            .send(channel, &opprf_program, self.nbins.unwrap(), rng)?;
        if !&self.state.opprf_payloads_in.is_empty() {
            let points_data = flatten_bins_payloads(
                &self.state.opprf_primary_keys_in,
                &self.state.opprf_payloads_in,
            );
            self.opprf_payload.as_mut().unwrap().send(
                channel,
                &points_data,
                self.nbins.unwrap(),
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
        let sender_primary_keys = bin_encode_many_block512(
            gc_party,
            &self.state.opprf_primary_keys_out,
            PRIMARY_KEY_SIZE,
        )?;

        let receiver_primary_keys = bin_receive_many_block512(gc_party, sender_primary_keys.len())?;

        let mut result = CircuitInputs {
            sender_primary_keys,
            receiver_primary_keys,
            sender_payloads_masked: vec![],
            receiver_payloads: vec![],
            masks: vec![],
        };

        // If payloads exist, then encode them
        if !&self.state.opprf_payloads_out.is_empty() {
            let sender_payloads_masked: Vec<F::Item> =
                bin_encode_many_block512(gc_party, &self.state.opprf_payloads_out, PAYLOAD_SIZE)?;
            let receiver_payloads: Vec<F::Item> =
                bin_receive_many_block512(gc_party, sender_payloads_masked.len())?;

            let masks: Vec<F::Item> =
                bin_receive_many_block512(gc_party, sender_payloads_masked.len())?;

            result.sender_payloads_masked = sender_payloads_masked;
            result.receiver_payloads = receiver_payloads;
            result.masks = masks;
        }

        Ok(result)
    }
}
