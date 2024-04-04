//! Helper functions that setsup and runs psty on ANY circuit that return a u128
#[cfg(test)]
use crate::{
    errors::Error,
    psi::circuit_psi::{
        base_psi::{receiver::OpprfReceiver, sender::OpprfSender},
        evaluator::PsiEvaluator,
        garbler::PsiGarbler,
        tests::utils::{type_aliases::*, *},
        utils::*,
        CircuitPsi,
    },
};
#[cfg(test)]
use fancy_garbling::Fancy;
#[cfg(test)]
use rand::{CryptoRng, RngCore, SeedableRng};
#[cfg(test)]
use scuttlebutt::{Block, Block512};
#[cfg(test)]
use std::{os::unix::net::UnixStream, thread};

#[cfg(test)]
pub fn run_psty_u128<CktEv, CktGb>(
    set_a: &[Vec<u8>],
    set_b: &[Vec<u8>],
    payloads_a: &[Block512],
    payloads_b: &[Block512],
    seed_sx: u128,
    seed_rx: u128,
    circuit_ev: &mut CktEv,
    circuit_gb: &mut CktGb,
) -> Result<u128, Error>
where
    CktGb: FnMut(
            &mut Gb,               // implements FancyBinary
            GbIntersectBitVecType, // intersects ?
            GbSetType,             // bits that parties are intersecting on
            GbPayloadType,         // party A's payload
            GbPayloadType,
        ) -> Result<GbCktOut, Error>
        + Send,
    CktEv: FnMut(
        &mut Ev,               // implements FancyBinary
        EvIntersectBitVecType, // intersects ?
        EvSetType,             // bits that parties are intersecting on
        EvPayloadType,         // party A's payload
        EvPayloadType,
    ) -> Result<EvCktOut, Error>,

    RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>,
{
    let (sender, receiver) = UnixStream::pair().unwrap();
    thread::scope(|s| {
        let _ = s.spawn(|| {
            let mut channel = setup(sender);
            let mut gb = PsiGarbler::new(&mut channel, Block::from(seed_sx)).unwrap();

            let res = gb
                .circuit_psi_psty::<OpprfSender, _, _>(set_a, payloads_a, circuit_gb)
                .unwrap();
            gb.gb.outputs(res.wires()).unwrap();
        });
        let mut channel = setup(receiver);
        let mut ev = PsiEvaluator::new(&mut channel, Block::from(seed_rx)).unwrap();

        let res = ev
            .circuit_psi_psty::<OpprfReceiver, _, _>(set_b, payloads_b, circuit_ev)
            .unwrap();
        let res_out = ev
            .ev
            .outputs(&res.wires().to_vec())
            .unwrap()
            .expect("evaluator should produce outputs");
        Ok(binary_to_u128(res_out))
    })
}

#[cfg(test)]
pub fn run_psty_no_payloads_u128<CktEv, CktGb>(
    set_a: &[Vec<u8>],
    set_b: &[Vec<u8>],
    seed_sx: u128,
    seed_rx: u128,
    circuit_ev: &mut CktEv,
    circuit_gb: &mut CktGb,
) -> Result<u128, Error>
where
    CktGb: FnMut(
            &mut Gb,               // implements FancyBinary
            GbIntersectBitVecType, // intersects ?
            GbSetType,             // bits that parties are intersecting on
        ) -> Result<GbCktOut, Error>
        + Send,
    CktEv: FnMut(
        &mut Ev,               // implements FancyBinary
        EvIntersectBitVecType, // intersects ?
        EvSetType,             // bits that parties are intersecting on
    ) -> Result<EvCktOut, Error>,

    RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>,
{
    let (sender, receiver) = UnixStream::pair().unwrap();
    thread::scope(|s| {
        let _ = s.spawn(|| {
            let mut channel = setup(sender);
            let mut gb = PsiGarbler::new(&mut channel, Block::from(seed_sx)).unwrap();

            let res = gb
                .circuit_psi_psty_no_payloads::<OpprfSender, _, _>(set_a, circuit_gb)
                .unwrap();
            gb.gb.outputs(res.wires()).unwrap();
        });
        let mut channel = setup(receiver);
        let mut ev = PsiEvaluator::new(&mut channel, Block::from(seed_rx)).unwrap();

        let res = ev
            .circuit_psi_psty_no_payloads::<OpprfReceiver, _, _>(set_b, circuit_ev)
            .unwrap();
        let res_out = ev
            .ev
            .outputs(&res.wires().to_vec())
            .unwrap()
            .expect("evaluator should produce outputs");
        Ok(binary_to_u128(res_out))
    })
}
