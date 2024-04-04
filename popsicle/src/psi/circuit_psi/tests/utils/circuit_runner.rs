//! Helper functions that setsup and runs psty on circuits that return a u128
#[cfg(test)]
use crate::{
    errors::Error,
    psi::circuit_psi::{
        base_psi::{receiver::OpprfReceiver, sender::OpprfSender},
        evaluator::PsiEvaluator,
        garbler::PsiGarbler,
        tests::utils::*,
        CircuitPsi,
    },
};
#[cfg(test)]
use fancy_garbling::Fancy;
#[cfg(test)]
use rand::{CryptoRng, RngCore, SeedableRng};
#[cfg(test)]
use scuttlebutt::{AesRng, Block, Block512};
#[cfg(test)]
use std::{os::unix::net::UnixStream, thread};

#[cfg(test)]
pub fn run_psty_u128<CktEv, CktGb>(
    set: &[Vec<u8>],
    payloads: Option<&[Block512]>,
    seed_sx: u64,
    seed_rx: u64,
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
            let mut rng = AesRng::seed_from_u64(seed_sx);
            let mut channel = setup(sender);
            let mut gb = PsiGarbler::new(&mut channel, &mut rng).unwrap();

            let res = gb
                .circuit_psi_psty::<OpprfSender, _, _>(
                    set,
                    payloads,
                    &mut channel,
                    &mut rng,
                    circuit_gb,
                )
                .unwrap();
            gb.gb.outputs(res.wires()).unwrap();
        });
        let mut rng = AesRng::seed_from_u64(seed_rx);
        let mut channel = setup(receiver);
        let mut ev = PsiEvaluator::new(&mut channel, &mut rng).unwrap();

        let res = ev
            .circuit_psi_psty::<OpprfReceiver, _, _>(
                set,
                payloads,
                &mut channel,
                &mut rng,
                circuit_ev,
            )
            .unwrap();
        let res_out = ev
            .ev
            .outputs(&res.wires().to_vec())
            .unwrap()
            .expect("evaluator should produce outputs");
        Ok(binary_to_u128(res_out))
    })
}
