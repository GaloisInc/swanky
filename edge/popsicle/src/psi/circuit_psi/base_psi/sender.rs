use rand::RngExt;

use crate::{
    circuit_psi::{base_psi::*, utils::*},
    cuckoo::CuckooHash,
    utils,
};

use fancy_traits::FancyEncode;
use swanky_block::{Block, Block512};
use swanky_error::{ErrorKind, WrapErr};
use swanky_oprf_kmprt::Sender as KmprtSender;

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
///   inputs of the OPPRF.
/// - `opprf_primary_keys_out` and `opprf_payloads_out` are their respective
///   programmed outputs.
///
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
    fn init<RNG>(
        channel: &mut Channel,
        rng: &mut RNG,
        has_payload: bool,
    ) -> swanky_error::Result<Self>
    where
        RNG: CryptoRng + SeedableRng,
    {
        // The key used during hashing is known to both
        // parties and allows them to hash the same inputs
        // to the same outputs.
        let key = channel.read()?;
        let opprf_primary_keys = KmprtSender::init(channel, rng).wrap_err(
            ErrorKind::InitializationError,
            "Failed to initialize KMPRT sender for primary keys.",
        )?;
        let mut opprf_payload = None;
        if has_payload {
            opprf_payload = Some(KmprtSender::init(channel, rng).wrap_err(
                ErrorKind::InitializationError,
                "Failed to initialize KMPRT sender for payload.",
            )?);
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
    fn hash_data<RNG>(
        &mut self,
        primary_keys: &[PrimaryKey],
        payloads: Option<&[Payload]>,
        channel: &mut Channel,
        rng: &mut RNG,
    ) -> swanky_error::Result<()>
    where
        RNG: CryptoRng + SeedableRng,
    {
        // refresh key if cuckoo hash is full
        self.key = channel.read::<Block>()?;

        // Receive cuckoo hash info from sender
        // The receiver determines the number of bins
        // to be used by the sender.
        let nbins = channel.read::<usize>()?;

        self.nbins = Some(nbins);

        let hashes = utils::compress_and_hash_inputs(primary_keys, self.key);

        let mut opprf_primary_keys_in = vec![Vec::new(); nbins];
        let opprf_primary_keys_out = (0..nbins).map(|_| rng.random::<Block512>()).collect();

        let mut opprf_payloads_in = vec![];
        let mut opprf_payloads_out = vec![];
        if payloads.is_some() {
            opprf_payloads_in = vec![Vec::new(); nbins];
            opprf_payloads_out = (0..nbins).map(|_| rng.random::<Block512>()).collect();
        }

        for (i, x) in hashes.iter().enumerate() {
            let mut bins = Vec::with_capacity(NHASHES);
            for h in 0..NHASHES {
                // First find the bin where the item will be placed
                let bin = CuckooHash::bin(*x, h, nbins);
                // Then place the item in that bin while keeping track
                // of the index of the hash function used in the process
                opprf_primary_keys_in[bin].push(*x ^ Block::from(h as u128));
                if let Some(payloads) = payloads {
                    // The payload values are masked before being sent out
                    // and placed in the same bin index as the primary key they
                    // are associated with.
                    opprf_payloads_in[bin].push(payloads[i] ^ opprf_payloads_out[bin]);
                }
                bins.push(bin);
            }
            // if j = H1(y) = H2(y) for some y, then P2 adds a uniformly random primary key to
            // table2[j] & payload[j]. This avoid possible leakage
            if bins.iter().skip(1).all(|&x| x == bins[0]) {
                opprf_primary_keys_in[bins[0]].push(rng.random());
                if payloads.is_some() {
                    opprf_payloads_in[bins[0]].push(rng.random());
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

    fn opprf_exchange<RNG>(
        &mut self,
        channel: &mut Channel,
        rng: &mut RNG,
    ) -> swanky_error::Result<()>
    where
        RNG: CryptoRng + SeedableRng,
    {
        // The Opprf in swanky expects the programmed input and outputs
        // to be passed as pairs

        let opprf_program = flatten_bin_tags(
            &self.state.opprf_primary_keys_in,
            &self.state.opprf_primary_keys_out,
        );
        self.opprf_primary_keys
            .send(channel, &opprf_program, self.nbins.unwrap(), rng)
            .wrap_err(
                ErrorKind::OtherError,
                "Failed to send primary keys during exchange.",
            )?;
        if !&self.state.opprf_payloads_in.is_empty() {
            let points_data = flatten_bins_payloads(
                &self.state.opprf_primary_keys_in,
                &self.state.opprf_payloads_in,
            );
            self.opprf_payload
                .as_mut()
                .unwrap()
                .send(channel, &points_data, self.nbins.unwrap(), rng)
                .wrap_err(
                    ErrorKind::OtherError,
                    "Failed to send payload during exchange.",
                )?;
        }
        Ok(())
    }
    fn encode_circuit_inputs<F>(
        &mut self,
        gc_party: &mut F,
        channel: &mut Channel,
    ) -> swanky_error::Result<CircuitInputs<F::Item>>
    where
        F: FancyEncode,
    {
        let sender_primary_keys = bin_encode_many_block512(
            gc_party,
            &self.state.opprf_primary_keys_out,
            PRIMARY_KEY_SIZE,
            channel,
        )?;

        let receiver_primary_keys =
            bin_receive_many_block512(gc_party, sender_primary_keys.len(), channel)?;

        let mut result = CircuitInputs {
            sender_primary_keys,
            receiver_primary_keys,
            sender_payloads_masked: vec![],
            receiver_payloads: vec![],
            masks: vec![],
        };

        // If payloads exist, then encode them
        if !&self.state.opprf_payloads_out.is_empty() {
            let sender_payloads_masked: Vec<F::Item> = bin_encode_many_block512(
                gc_party,
                &self.state.opprf_payloads_out,
                PAYLOAD_SIZE,
                channel,
            )?;
            let receiver_payloads: Vec<F::Item> =
                bin_receive_many_block512(gc_party, sender_payloads_masked.len(), channel)?;

            let masks: Vec<F::Item> =
                bin_receive_many_block512(gc_party, sender_payloads_masked.len(), channel)?;

            result.sender_payloads_masked = sender_payloads_masked;
            result.receiver_payloads = receiver_payloads;
            result.masks = masks;
        }

        Ok(result)
    }
}
