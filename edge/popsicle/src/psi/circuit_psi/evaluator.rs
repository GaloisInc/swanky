//! Defining the Evaluator's behavior in Circuit Psi according to PSTY19
use crate::circuit_psi::base_psi::receiver::OpprfReceiver;
use fancy_garbling::WireMod2;
use rand::{CryptoRng, SeedableRng};
use std::marker::PhantomData;
use swanky_adversary::SemiHonest;
use swanky_channel::Channel;
use swanky_error::{ErrorKind, WrapErr};
use swanky_ot_iknp::IKNP;
use swanky_ot_traits::Receiver;
use swanky_twopac::semihonest::Evaluator;

/// An Evaluating party for Circuit PSI that uses OPPRF Base PSI
pub type OpprfPsiEvaluator<RNG> = PsiEvaluator<RNG, OpprfReceiver>;

/// A struct defining the Evaluating party in Circuit Psi
pub struct PsiEvaluator<RNG, B> {
    /// The actual evaluator being called during the garbled circuit
    pub ev: Evaluator<RNG, IKNP<Receiver>, WireMod2>,
    /// The evaluator's dedicated rng
    pub rng: RNG,
    /// A witness for the Base PSI protocol
    _base_psi: PhantomData<B>,
}

impl<RNG, B> PsiEvaluator<RNG, B>
where
    RNG: CryptoRng + SeedableRng,
{
    /// Creates a PsiEvaluator from a dedicated channel and rng
    pub fn new(channel: &mut Channel, rng: &mut RNG) -> swanky_error::Result<Self>
    where
        Self: Sized,
    {
        Ok(PsiEvaluator {
            ev: Evaluator::<RNG, IKNP<Receiver>, WireMod2>::new(channel, rng.fork()).wrap_err(
                ErrorKind::InitializationError,
                "Failed to create fancy evaluator.",
            )?,
            rng: rng.fork(),
            _base_psi: PhantomData,
        })
    }
}

impl<RNG, B> SemiHonest for PsiEvaluator<RNG, B> {}
