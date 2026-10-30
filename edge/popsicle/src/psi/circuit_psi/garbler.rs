//! Defining the Garbler's behavior in Circuit Psi according to PSTY19
use crate::{
    circuit_psi::intersect_with_payloads,
    psi::circuit_psi::{
        CircuitPsi, Intersection, PrimaryKey,
        base_psi::{BasePsi, sender},
    },
};
use fancy_garbling::WireMod2;
use rand::{CryptoRng, SeedableRng};
use std::marker::PhantomData;
use swanky_adversary::SemiHonest;
use swanky_channel::Channel;
use swanky_error::{ErrorKind, WrapErr};
use swanky_ot_iknp::IKNP;
use swanky_ot_traits::Sender;
use swanky_twopac::semihonest::Garbler;
use vectoreyes::U8x16;

use self::sender::OpprfSender;

/// A Garbling party for Circuit PSI that uses OPPRF Base PSI
pub type OpprfPsiGarbler<RNG> = PsiGarbler<RNG, OpprfSender>;

/// A struct defining the Garbling party in Circuit Psi
pub struct PsiGarbler<RNG, B> {
    /// The actual garbler being called during the garbled circuit
    pub gb: Garbler<RNG, IKNP<Sender>, WireMod2>,
    /// The garbler's dedicated rng
    pub rng: RNG,
    /// A witness for the Base PSI protocol
    _base_psi: PhantomData<B>,
}

impl<RNG, B> PsiGarbler<RNG, B>
where
    RNG: CryptoRng + SeedableRng<Seed = U8x16>,
{
    /// Creates a PsiGarbler from a dedicated channel and rng
    pub fn new(channel: &mut Channel, rng: &mut RNG) -> swanky_error::Result<Self> {
        Ok(PsiGarbler {
            gb: Garbler::<RNG, IKNP<Sender>, WireMod2>::new(channel, rng.fork())
                .wrap_err(ErrorKind::InitializationError, "Failed to create garbler.")?,
            rng: rng.fork(),
            _base_psi: PhantomData,
        })
    }
}

impl<RNG, B> SemiHonest for PsiGarbler<RNG, B> {}

impl<RNG, B> CircuitPsi for PsiGarbler<RNG, B>
where
    RNG: CryptoRng + SeedableRng<Seed = U8x16>,
    B: BasePsi,
{
    fn intersect(
        &mut self,
        primary_keys: &[PrimaryKey],
        channel: &mut Channel,
    ) -> swanky_error::Result<Intersection<WireMod2>> {
        intersect_with_payloads::<_, OpprfSender, _>(
            &mut self.gb,
            primary_keys,
            None,
            channel,
            &mut self.rng,
        )
    }
}
