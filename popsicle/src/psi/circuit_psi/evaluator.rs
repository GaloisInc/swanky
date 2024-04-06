//! Defining the Evaluator's behavior in Circuit Psi according to PSTY19
use crate::{
    errors::Error,
    psi::circuit_psi::{circuits::*, *},
};
use fancy_garbling::{twopac::semihonest::Evaluator, AllWire};
use ocelot::ot::AlszReceiver as OtReceiver;
use scuttlebutt::{AbstractChannel, Block, SemiHonest};

/// A struct defining the Evaluating party in Circuit Psi
pub struct PsiEvaluator<C, RNG> {
    /// The actual evaluator being called during the garbled circuit
    pub ev: Evaluator<C, RNG, OtReceiver, AllWire>,
    /// The evaluator's dedicated channel
    pub channel: C,
    /// The evaluator's dedicated rng
    pub rng: RNG,
    /// The set and intersection bit vector
    pub intersection: PrivateIntersection<AllWire>,
    /// The unmasked payloads
    pub payloads: PrivateIntersectionPayloads<AllWire>,
}

impl<C, RNG> PsiEvaluator<C, RNG>
where
    C: AbstractChannel + Clone,
    RNG: RngCore + CryptoRng + Rng + SeedableRng<Seed = Block>,
{
    /// Creates a PsiEvaluator from a dedicated channel and rng
    pub fn new(channel: &mut C, seed: RNG::Seed) -> Result<Self, Error>
    where
        Self: Sized,
    {
        Ok(PsiEvaluator {
            ev: Evaluator::<C, RNG, OtReceiver, AllWire>::new(
                channel.clone(),
                RNG::from_seed(seed),
            )?,
            channel: channel.clone(),
            rng: RNG::from_seed(seed),
            intersection: Default::default(),
            payloads: Default::default(),
        })
    }
}

impl<C, RNG> SemiHonest for PsiEvaluator<C, RNG> {}

impl<C, RNG> CircuitPsi for PsiEvaluator<C, RNG>
where
    C: AbstractChannel + Clone,
    RNG: RngCore + CryptoRng + Rng + SeedableRng<Seed = Block>,
{
    type Wire = AllWire;
    type F = Evaluator<C, RNG, OtReceiver, Self::Wire>;
    /// Computes the Circuit PSI on the evaluator's inputs.
    ///
    /// (1) Call the Base Psi to create the circuit's input.
    /// The Base Psi effectively constructs the intersection in a hidden form
    /// that only the garbled circuit can read and operate on.
    /// (2) Turns the circuit inputs into bundles that are easier to operate on in swanky's
    /// fancy garbling.
    /// (3) Takes the output of the Base Psi and turns it into a garbled intersection bit
    /// vector which indicates the presence or abscence of a set element.
    /// (4) Computes the user defined circuit on the parties' inputs.
    fn intersect<Party>(&mut self, set: &[Element], payloads: &[Payload]) -> Result<(), Error>
    where
        Party: BasePsi,
        Self: Sized,
    {
        // (1)
        let circuit_inputs = Party::base_psi(
            &mut self.ev,
            set,
            payloads,
            &mut self.channel,
            &mut self.rng,
        )?;
        // (2)
        self.intersection.set = bundle_set::<Self::F, _>(&circuit_inputs)?;
        (
            self.payloads.sender_payloads,
            self.payloads.receiver_payloads,
        ) = bundle_payloads(&mut self.ev, &circuit_inputs)?;

        // (3)
        self.intersection.existence_bit_vector = fancy_intersection_bit_vector(
            &mut self.ev,
            &circuit_inputs.sender_set_elements,
            &circuit_inputs.receiver_set_elements,
        )?;
        Ok(())
    }
}
