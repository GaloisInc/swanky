//! Defining the Garbler's behavior in Circuit Psi according to PSTY19
use crate::{
    errors::Error,
    psi::circuit_psi::{circuits::*, *},
};
use fancy_garbling::{twopac::semihonest::Garbler, WireMod2};
use ocelot::ot::AlszSender as OtSender;
use scuttlebutt::{AbstractChannel, Block, SemiHonest};
/// A struct defining the Garbling party in Circuit Psi
pub struct PsiGarbler<C, RNG> {
    /// The actual garbler being called during the garbled circuit
    pub gb: Garbler<C, RNG, OtSender, WireMod2>,
    /// The garbler's dedicated channel
    pub channel: C,
    /// The garbler's dedicated rng
    pub rng: RNG,
}

impl<C, RNG> PsiGarbler<C, RNG>
where
    C: AbstractChannel + Clone,
    RNG: RngCore + CryptoRng + Rng + SeedableRng<Seed = Block>,
{
    /// Creates a PsiGarbler from a dedicated channel and rng
    pub fn new(channel: &mut C, seed: RNG::Seed) -> Result<Self, Error>
    where
        Self: Sized,
    {
        Ok(PsiGarbler {
            gb: Garbler::<C, RNG, OtSender, WireMod2>::new(channel.clone(), RNG::from_seed(seed))?,
            channel: channel.clone(),
            rng: RNG::from_seed(seed),
        })
    }
}

impl<C, RNG> SemiHonest for PsiGarbler<C, RNG> {}

impl<C, RNG> CircuitPsi for PsiGarbler<C, RNG>
where
    C: AbstractChannel + Clone,
    RNG: RngCore + CryptoRng + Rng + SeedableRng<Seed = Block>,
{
    type F = Garbler<C, RNG, OtSender, WireMod2>;
    /// Computes the Circuit PSI on the garbler's inputs.
    ///
    /// (1) Call the Base Psi to create the circuit's input.
    /// The Base Psi effectively constructs the intersection in a hidden form
    /// that only the garbled circuit can read and operate on.
    /// (2) Turns the circuit inputs into bundles that are easier to operate on in swanky's
    /// fancy garbling.
    /// (3) Takes the output of the Base Psi and turns it into a garbled intersection bit
    /// vector which indicates the presence or abscence of a set element.
    /// (4) Computes the user defined circuit on the parties' inputs.
    fn intersect<Party>(
        &mut self,
        set: &[Element],
        payloads: &[Payload],
    ) -> Result<Intersection, Error>
    where
        Party: BasePsi,
        Self: Sized,
    {
        // (1)
        let circuit_inputs = Party::base_psi(
            &mut self.gb,
            set,
            payloads,
            &mut self.channel,
            &mut self.rng,
        )?;
        // (2)
        let set = bundle_set::<Self::F, _>(&circuit_inputs)?;
        let (sender_payloads, receiver_payloads) = bundle_payloads(&mut self.gb, &circuit_inputs)?;

        // (3)
        let existence_bit_vector = fancy_intersection_bit_vector(
            &mut self.gb,
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
