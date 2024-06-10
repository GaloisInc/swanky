//! Defining the Evaluator's behavior in Circuit Psi according to PSTY19
use crate::{
    errors::Error,
    psi::circuit_psi::{circuits::*, *},
};
use fancy_garbling::{twopac::semihonest::Evaluator, WireMod2};
use ocelot::ot::AlszReceiver as OtReceiver;
use scuttlebutt::{AbstractChannel, Block, SemiHonest};
use std::marker::PhantomData;

use self::receiver::OpprfReceiver;

/// An Evaluating party for Circuit PSI that uses OPPRF Base PSI
pub type OpprfPsiEvaluator<C, RNG> = PsiEvaluator<C, RNG, OpprfReceiver>;

/// A struct defining the Evaluating party in Circuit Psi
pub struct PsiEvaluator<C, RNG, B> {
    /// The actual evaluator being called during the garbled circuit
    pub ev: Evaluator<C, RNG, OtReceiver, WireMod2>,
    /// The evaluator's dedicated channel
    pub channel: C,
    /// The evaluator's dedicated rng
    pub rng: RNG,
    /// A witness for the Base PSI protocol
    _base_psi: PhantomData<B>,
}

impl<C, RNG, B> PsiEvaluator<C, RNG, B>
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
            ev: Evaluator::<C, RNG, OtReceiver, WireMod2>::new(
                channel.clone(),
                RNG::from_seed(seed),
            )?,
            channel: channel.clone(),
            rng: RNG::from_seed(seed),
            _base_psi: PhantomData,
        })
    }
}

impl<C, RNG, B> SemiHonest for PsiEvaluator<C, RNG, B> {}

impl<C, RNG, B> CircuitPsi for PsiEvaluator<C, RNG, B>
where
    C: AbstractChannel + Clone,
    RNG: RngCore + CryptoRng + Rng + SeedableRng<Seed = Block>,
    B: BasePsi,
{
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
    fn intersect(
        &mut self,
        set: &[Element],
        payloads: &[Payload],
    ) -> Result<Intersection, Error>
    {
        // (1)
        let circuit_inputs = B::base_psi(
            &mut self.ev,
            set,
            payloads,
            &mut self.channel,
            &mut self.rng,
        )?;
        // (2)
        let set = bundle_set::<Evaluator<C, RNG, OtReceiver, WireMod2>, _>(&circuit_inputs)?;
        let (sender_payloads, receiver_payloads) = bundle_payloads(&mut self.ev, &circuit_inputs)?;

        // (3)
        let existence_bit_vector = fancy_intersection_bit_vector(
            &mut self.ev,
            &circuit_inputs.sender_set_elements,
            &circuit_inputs.receiver_set_elements,
        )?;

        let intersection_results = Intersection {
            intersection: PrivateIntersection {
                existence_bit_vector,
                set,
            },
            payloads: PrivateIntersectionPayloads {
                sender_payloads,
                receiver_payloads,
            },
        };
        Ok(intersection_results)
    }
}
