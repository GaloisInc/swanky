use crate::{errors::Error, psi::circuit_psi::*};
use fancy_garbling::{twopac::semihonest::Evaluator, AllWire};
use ocelot::ot::AlszReceiver as OtReceiver;

/// A struct defining the Evaluating party in Circuit Psi
pub struct PsiEvaluator<C, RNG> {
    // The actual evaluator being called during the garbled circuit
    pub ev: Evaluator<C, RNG, OtReceiver, AllWire>,
}

impl<C, RNG> PsiEvaluator<C, RNG>
where
    C: AbstractChannel + Clone,
    RNG: RngCore + CryptoRng + Rng + SeedableRng<Seed = Block>,
{
    /// Creates a PsiEvaluator from a dedicated channel and rng
    pub fn new(channel: &mut C, rng: &mut RNG) -> Result<Self, Error>
    where
        Self: Sized,
    {
        Ok(PsiEvaluator {
            ev: Evaluator::<C, RNG, OtReceiver, AllWire>::new(
                channel.clone(),
                RNG::from_seed(rng.gen()),
            )?,
        })
    }
}

impl<C, RNG> CircuitPsi<C, RNG> for PsiEvaluator<C, RNG>
where
    C: AbstractChannel + Clone,
    RNG: RngCore + CryptoRng + Rng + SeedableRng<Seed = Block>,
{
    type Item = AllWire;
    type F = Evaluator<C, RNG, OtReceiver, Self::Item>;
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
    fn circuit_psi_psty<P, Ckt, CktOut>(
        &mut self,
        set: &[Vec<u8>],
        payloads: Option<&[Block512]>,
        channel: &mut C,
        rng: &mut RNG,
        circuit: &mut Ckt,
    ) -> Result<CktOut, Error>
    where
        P: BasePsi,
        C: AbstractChannel,
        RNG: RngCore + CryptoRng + SeedableRng,
        Ckt: FnMut(
            &mut Self::F,
            &[Self::Item],
            &[BinaryBundle<Self::Item>],
            Option<Vec<BinaryBundle<Self::Item>>>,
            Option<Vec<BinaryBundle<Self::Item>>>,
        ) -> Result<CktOut, Error>,
    {
        // (1)
        let circuit_inputs = P::base_psi(&mut self.ev, set, payloads, channel, rng)?;
        // (2)
        let (set, sender_payloads, receiver_payloads) =
            bundle_inputs(&mut self.ev, &circuit_inputs)?;
        // (3)
        let intersection_bit_vector = intersect(&mut self.ev, &circuit_inputs)?;
        // (4)
        circuit(
            &mut self.ev,
            &intersection_bit_vector,
            &set,
            sender_payloads,
            receiver_payloads,
        )
    }
}
