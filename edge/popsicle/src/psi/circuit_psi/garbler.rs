//! Defining the Garbler's behavior in Circuit Psi according to PSTY19
use crate::psi::circuit_psi::*;
use fancy_garbling::WireMod2;
use std::marker::PhantomData;
use swanky_adversary::SemiHonest;
use swanky_block::Block;
use swanky_channel::Channel;
use swanky_error::{ErrorKind, WrapErr};
use swanky_ot_alsz_kos::alsz::Sender as OtSender;
use swanky_twopac::semihonest::Garbler;

use self::sender::OpprfSender;

/// A Garbling party for Circuit PSI that uses OPPRF Base PSI
pub type OpprfPsiGarbler<RNG> = PsiGarbler<RNG, OpprfSender>;

/// A struct defining the Garbling party in Circuit Psi
pub struct PsiGarbler<RNG, B> {
    /// The actual garbler being called during the garbled circuit
    pub gb: Garbler<RNG, OtSender, WireMod2>,
    /// The garbler's dedicated rng
    pub rng: RNG,
    /// A witness for the Base PSI protocol
    _base_psi: PhantomData<B>,
}

impl<RNG, B> PsiGarbler<RNG, B>
where
    RNG: Rng + CryptoRng + Rng + SeedableRng<Seed = Block>,
{
    /// Creates a PsiGarbler from a dedicated channel and rng
    pub fn new(channel: &mut Channel, seed: RNG::Seed) -> swanky_error::Result<Self>
    where
        Self: Sized,
    {
        Ok(PsiGarbler {
            gb: Garbler::<RNG, OtSender, WireMod2>::new(channel, RNG::from_seed(seed))
                .wrap_err(ErrorKind::InitializationError, "Failed to create garbler.")?,
            rng: RNG::from_seed(seed),
            _base_psi: PhantomData,
        })
    }
}

impl<RNG, B> SemiHonest for PsiGarbler<RNG, B> {}

impl<RNG, B> CircuitPsi for PsiGarbler<RNG, B>
where
    RNG: Rng + CryptoRng + Rng + SeedableRng<Seed = Block>,
    B: BasePsi,
{
    /// Computes the Circuit PSI on the garbler's inputs.
    ///
    /// (0) Check that the set of primary keys has the same size as the set of payloads
    /// if the latter is not empty.
    /// (1) Call the Base Psi to create the circuit's input.
    /// The Base Psi effectively constructs the intersection in a hidden form
    /// that only the garbled circuit can read and operate on.
    /// (2) Turns the circuit inputs into bundles that are easier to operate on in swanky's
    /// fancy garbling.
    /// (3) Takes the output of the Base Psi and turns it into a garbled intersection bit
    /// vector which indicates the presence or abscence of a primary key.
    /// (4) Computes the user defined circuit on the parties' inputs.
    fn intersect_with_payloads(
        &mut self,
        primary_keys: &[PrimaryKey],
        payloads: Option<&[Payload]>,
        channel: &mut Channel,
    ) -> swanky_error::Result<Intersection> {
        // (0)
        if let Some(payloads) = payloads
            && primary_keys.len() != payloads.len()
        {
            swanky_error::bail!(
                ErrorKind::OtherError,
                "Failed to intersect due to incomplete payload set: (#payloads := {}) != (#primary keys := {})",
                payloads.len(),
                primary_keys.len(),
            );
        }
        // (1)
        let circuit_inputs =
            B::base_psi(&mut self.gb, primary_keys, payloads, channel, &mut self.rng)?;
        // (2)
        let primary_keys =
            bundle_primary_keys::<Garbler<RNG, OtSender, WireMod2>>(&circuit_inputs)?;
        let (sender_payloads, receiver_payloads) =
            bundle_payloads(&mut self.gb, &circuit_inputs, channel)?;

        // (3)
        let existence_bit_vector = fancy_intersection_bit_vector(
            &mut self.gb,
            &circuit_inputs.sender_primary_keys,
            &circuit_inputs.receiver_primary_keys,
            channel,
        )?;
        let intersection_results = Intersection {
            intersection: PrivateIntersection {
                existence_bit_vector,
                primary_keys,
            },
            payloads: PrivateIntersectionPayloads {
                sender_payloads,
                receiver_payloads,
            },
        };
        Ok(intersection_results)
    }
    fn intersect(
        &mut self,
        primary_keys: &[PrimaryKey],
        channel: &mut Channel,
    ) -> swanky_error::Result<Intersection> {
        self.intersect_with_payloads(primary_keys, None, channel)
    }
}
