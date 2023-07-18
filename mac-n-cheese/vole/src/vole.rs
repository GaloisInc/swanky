use arrayvec::ArrayVec;
use bytemuck::TransparentWrapper;
use eyre::Context;
use generic_array::{typenum::Unsigned, GenericArray};
use keyed_arena::{AllocationKey, KeyedArena};
use mac_n_cheese_party as party;
use ocelot::ot::explicit_round::{KosReceiver, KosReceiverStage2, KosSender, KosSenderStage2};
use ocelot::svole::ggm_utils::*;
use party::{Party, IS_PROVER, IS_VERIFIER};
use rand::prelude::Distribution;
use rand::{distributions::Uniform, CryptoRng, Rng, SeedableRng};
use scuttlebutt::field::DegreeModulo;
use scuttlebutt::{
    field::{Degree, FiniteField},
    generic_array_length::Arr,
    ring::FiniteRing,
    serialization::CanonicalSerialize,
    AbstractChannel, AesRng, Block,
};
use std::{marker::PhantomData, ops::Deref};

mod lpn_params;
mod sizes;

pub use sizes::VoleSizes;
use vectoreyes::{Aes128EncryptOnly, AesBlockCipher, U64x2, U8x16};

use crate::{
    mac::{Mac, MacTypes},
    specialization::FiniteFieldSpecialization,
};

use lpn_params::LpnParams;

trait MacTypesExt: MacTypes {
    const VS: VoleSizes;
    const LPN: LpnParams;
}
impl<T: MacTypes> MacTypesExt for T {
    const VS: VoleSizes = VoleSizes::of::<Self::VF, Self::TF>();
    const LPN: LpnParams = lpn_params::extend_params(Degree::<Self::TF>::USIZE);
}

fn make_ggm_seeds(lpn_seeds: &Aes128EncryptOnly) -> (Aes128EncryptOnly, Aes128EncryptOnly) {
    (
        // lpn_seeds is normally only used with a 64-bit value. Since these seeds have non-zero
        // values for the upper 64 bits of the 128-bit vector, there will be no conflict.
        Aes128EncryptOnly::new_with_key(lpn_seeds.encrypt([255; 16].into())),
        Aes128EncryptOnly::new_with_key(lpn_seeds.encrypt([254; 16].into())),
    )
}

fn lpn_rng_from_seed(selector: u64, lpn_seeds: &Aes128EncryptOnly) -> AesRng {
    AesRng::from_seed(lpn_seeds.encrypt(U64x2::from([selector, 0]).into()).into())
}

/// Generates powers of `FE::GENERATOR`.
#[derive(Clone)]
pub struct Powers<FE: FiniteField> {
    powers: Arr<FE, Degree<FE>>,
}

impl<FE: FiniteField> Default for Powers<FE> {
    fn default() -> Self {
        let mut acc = FE::ONE;
        let mut powers: Arr<FE, Degree<FE>> = Default::default();
        for item in powers.iter_mut() {
            *item = acc;
            acc *= FE::GENERATOR;
        }
        Self { powers }
    }
}

impl<FE: FiniteField> Deref for Powers<FE> {
    type Target = Arr<FE, Degree<FE>>;
    fn deref(&self) -> &Arr<FE, Degree<FE>> {
        &self.powers
    }
}

struct BaseVoles<'a, P: Party, M: MacTypes>(&'a [Mac<P, M>]);

impl<P: Party, M: MacTypes> Deref for BaseVoles<'_, P, M> {
    type Target = [Mac<P, M>];

    fn deref(&self) -> &Self::Target {
        self.0
    }
}
impl<'a, P: Party, M: MacTypes> BaseVoles<'a, P, M> {
    fn new(t: &'a [Mac<P, M>]) -> Self {
        assert_eq!(t.len(), M::VS.base_voles_needed);
        Self(t)
    }
    fn all_sps_base_voles(&self) -> &[Mac<P, M>] {
        &self.0[M::LPN.rows..M::LPN.rows + M::LPN.weight + Degree::<M::TF>::USIZE]
    }
    fn sps_base_voles(&self) -> &[Mac<P, M>] {
        &self.all_sps_base_voles()[0..M::VS.base_uws_size]
    }
    fn sps_base_consistency(&self) -> &[Mac<P, M>] {
        &self.all_sps_base_voles()[M::VS.base_uws_size..]
    }
}

pub struct VoleSender<T: MacTypes> {
    lpn_seeds: Aes128EncryptOnly,
    pows: Powers<T::TF>,
    ot: KosReceiver,
    ggm_seeds: (Aes128EncryptOnly, Aes128EncryptOnly),
    phantom: PhantomData<T>,
}

impl<T: MacTypes> VoleSender<T> {
    pub fn init<C: AbstractChannel, RNG: Rng + CryptoRng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> eyre::Result<Self> {
        let lpn_seeds = Aes128EncryptOnly::new_with_key(
            scuttlebutt::cointoss::send(channel, &[rng.gen::<Block>()])?[0].0,
        );
        let ot = KosReceiver::init(channel, rng)?;
        let ggm_seeds = make_ggm_seeds(&lpn_seeds);
        Ok(VoleSender {
            lpn_seeds,
            ot,
            pows: Default::default(),
            ggm_seeds,
            phantom: PhantomData,
        })
    }
    pub fn send(
        &self,
        arena: &KeyedArena,
        selector: u64,
        rng: &mut (impl Rng + CryptoRng),
        base_voles: &[Mac<party::Prover, T>],
        mut outgoing_bytes: &mut [u8],
    ) -> eyre::Result<VoleSenderStep3<T>> {
        assert_eq!(base_voles.len(), T::VS.base_voles_needed);
        eyre::ensure!(
            outgoing_bytes.len() == T::VS.comms_1s,
            "incorrect outgoing buffer size"
        );
        let base_voles = BaseVoles::new(base_voles);
        let mut alphas_and_betas =
            arena.alloc_slice_fill_with(T::VS.base_uws_size, |_| (0, T::VF::ZERO));
        let mut choices = arena.alloc_slice_fill_with(T::VS.ot_num_choices, |_| false);
        debug_assert_eq!(choices.len() % T::LPN.log2m, 0);
        let distribution = Uniform::from(0..T::LPN.m());
        for (((a, _), (alpha, beta)), choices) in base_voles
            .sps_base_voles()
            .iter()
            .copied()
            .map(|mac| mac.prover_extract(IS_PROVER))
            .zip(alphas_and_betas.iter_mut())
            .zip(choices.chunks_exact_mut(T::LPN.log2m))
        {
            *alpha = distribution.sample(rng);
            *beta = T::VF::random_nonzero(rng);
            let a_prime = *beta - a;
            outgoing_bytes[0..<T::VF as CanonicalSerialize>::ByteReprLen::USIZE]
                .copy_from_slice(a_prime.to_bytes().as_slice());
            outgoing_bytes =
                &mut outgoing_bytes[<T::VF as CanonicalSerialize>::ByteReprLen::USIZE..];
            let mut mask = 1 << (T::LPN.log2m - 1);
            for choice in choices.iter_mut() {
                debug_assert_ne!(mask, 0);
                *choice = (*alpha & mask) == 0;
                mask >>= 1;
            }
            debug_assert_eq!(mask, 0);
        }
        debug_assert_eq!(choices.len(), T::VS.ot_num_choices);
        debug_assert_eq!(
            outgoing_bytes.len(),
            KosReceiver::receive_outgoing_bytes(T::VS.ot_num_choices)
        );
        let ot_stage2 = self
            .ot
            .receive(arena, selector, choices, rng, outgoing_bytes)?;
        let mut commitment_key = [0; 32];
        rng.fill_bytes(&mut commitment_key);
        Ok(VoleSenderStep3 {
            ot_stage2,
            alphas_and_betas: alphas_and_betas.key(),
            selector,
            seed: rng.gen(),
            commitment_key,
            phantom: PhantomData,
        })
    }
}
pub struct VoleSenderStep3<T: MacTypes> {
    seed: Block,
    selector: u64,
    commitment_key: [u8; 32],
    ot_stage2: KosReceiverStage2,
    alphas_and_betas: AllocationKey<(usize, T::VF)>,
    phantom: PhantomData<T>,
}
impl<T: MacTypes> VoleSenderStep3<T> {
    // `result` must be zeroed.
    pub fn stage2(
        self,
        sender: &VoleSender<T>,
        arena: &KeyedArena,
        base_voles: &[Mac<party::Prover, T>],
        result: &mut [Mac<party::Prover, T>],
        mut incoming_bytes: &[u8],
        mut outgoing_bytes: &mut [u8],
    ) -> eyre::Result<VoleSenderStep5<T>> {
        assert_eq!(base_voles.len(), T::VS.base_voles_needed);
        let base_voles = BaseVoles::new(base_voles);
        let alphas_and_betas = arena.borrow_mut(self.alphas_and_betas);
        eyre::ensure!(
            outgoing_bytes.len() == T::VS.comms_3s,
            "outgoing buffer is the wrong size"
        );
        eyre::ensure!(
            incoming_bytes.len() == T::VS.comms_2r,
            "incoming buffer is the wrong size"
        );
        let ot_bytes = KosReceiverStage2::incoming_bytes(T::VS.ot_num_choices);
        let keys = self.ot_stage2.stage2(
            arena,
            &incoming_bytes[0..ot_bytes],
            &mut outgoing_bytes[0..KosReceiverStage2::OUTGOING_BYTES],
        )?;
        incoming_bytes = &incoming_bytes[ot_bytes..];
        outgoing_bytes = &mut outgoing_bytes[KosReceiverStage2::OUTGOING_BYTES..];
        let nbits = T::LPN.log2m;
        let m = T::LPN.m();
        assert_eq!(result.len(), T::LPN.total_output_voles());
        debug_assert_eq!(base_voles.sps_base_voles().len() * m, result.len());
        let mut ggm_temporary_storage = arena
            .alloc_slice_fill_with(ggm_prime_temporary_storage_size(nbits), |_| {
                U8x16::default()
            });
        for (i, ((_, w), (alpha, beta))) in base_voles
            .sps_base_voles()
            .iter()
            .copied()
            .map(|mac| mac.prover_extract(IS_PROVER))
            .zip(alphas_and_betas.iter())
            .enumerate()
        {
            let sum = ggm_prime::<T::VF, T::TF, Mac<party::Prover, T>>(
                *alpha,
                bytemuck::cast_slice(&keys[i * nbits..(i + 1) * nbits]),
                &sender.ggm_seeds,
                &mut result[i * m..(i + 1) * m],
                &mut ggm_temporary_storage,
            );
            let mut d: GenericArray<u8, <T::TF as CanonicalSerialize>::ByteReprLen> =
                Default::default();
            d.copy_from_slice(
                &incoming_bytes[0..<T::TF as CanonicalSerialize>::ByteReprLen::USIZE],
            );
            incoming_bytes = &incoming_bytes[d.len()..];
            let d: T::TF = T::TF::from_bytes(&d).context("Failed to read field element")?;
            // TODO: is alpha supposed to be private? If so there's a cache timing attack here.
            result[i * m + alpha] = (*beta, w - (d + sum)).into();
        }
        debug_assert!(incoming_bytes.is_empty());
        // Begin batch consistency check
        // TODO: can we use one of the seeds that we've already agreed upon for this?
        // TODO: is this supposed to be done as part of a cointoss? (I'm just following the
        // original implementation, for now.)
        let mut rng_chi = AesRng::from_seed(self.seed);
        let (mut va, x_stars) = T::S::spsvole_sender_compute_va(
            &mut rng_chi,
            TransparentWrapper::peel_slice(TransparentWrapper::peel_slice(&result)),
        );
        for (pows, (x_star, (u, w))) in sender.pows.iter().zip(
            x_stars.iter().zip(
                base_voles
                    .sps_base_consistency()
                    .iter()
                    .copied()
                    .map(|mac| mac.prover_extract(IS_PROVER)),
            ),
        ) {
            let fe: T::VF = *x_star - u;
            outgoing_bytes[0..<T::VF as CanonicalSerialize>::ByteReprLen::USIZE]
                .copy_from_slice(&fe.to_bytes());
            outgoing_bytes =
                &mut outgoing_bytes[<T::VF as CanonicalSerialize>::ByteReprLen::USIZE..];
            va -= *pows * w;
        }
        outgoing_bytes[0..16].copy_from_slice(bytemuck::bytes_of(&self.seed));
        outgoing_bytes = &mut outgoing_bytes[16..];
        // Run the Eq protocool on va
        outgoing_bytes
            .copy_from_slice(blake3::keyed_hash(&self.commitment_key, &va.to_bytes()).as_bytes());
        Ok(VoleSenderStep5 {
            commitment_key: self.commitment_key,
            va,
            phantom: PhantomData,
            selector: self.selector,
        })
    }
}
pub struct VoleSenderStep5<T: MacTypes> {
    commitment_key: [u8; 32],
    selector: u64,
    va: T::TF,
    phantom: PhantomData<T>,
}
impl<T: MacTypes> VoleSenderStep5<T> {
    pub fn stage3(
        self,
        sender: &VoleSender<T>,
        _arena: &KeyedArena,
        base_voles: &[Mac<party::Prover, T>],
        result: &mut [Mac<party::Prover, T>],
        incoming_bytes: &[u8],
        outgoing_bytes: &mut [u8],
    ) -> eyre::Result<()> {
        assert_eq!(base_voles.len(), T::VS.base_voles_needed);
        eyre::ensure!(
            outgoing_bytes.len() == T::VS.comms_5s,
            "outgoing buffer is the wrong size"
        );
        eyre::ensure!(
            incoming_bytes.len() == T::VS.comms_4r,
            "incoming buffer is the wrong size"
        );
        outgoing_bytes.copy_from_slice(&self.commitment_key);
        eyre::ensure!(
            self.va.to_bytes().as_slice() == incoming_bytes,
            "equality protocol failed"
        );
        T::S::lpn_sender(
            &mut lpn_rng_from_seed(self.selector, &sender.lpn_seeds),
            TransparentWrapper::peel_slice(TransparentWrapper::peel_slice(base_voles)),
            TransparentWrapper::peel_slice_mut(TransparentWrapper::peel_slice_mut(result)),
        );
        Ok(())
    }
}

pub struct VoleReceiver<T: MacTypes> {
    lpn_seeds: Aes128EncryptOnly,
    pows: Powers<T::TF>,
    ot: KosSender,
    delta: T::TF,
    ggm_seeds: (Aes128EncryptOnly, Aes128EncryptOnly),
    phantom: PhantomData<T>,
}
impl<T: MacTypes> VoleReceiver<T> {
    pub fn init<C: AbstractChannel, RNG: Rng + CryptoRng>(
        channel: &mut C,
        rng: &mut RNG,
        delta: T::TF,
    ) -> eyre::Result<Self> {
        let lpn_seeds = Aes128EncryptOnly::new_with_key(
            scuttlebutt::cointoss::receive(channel, &[rng.gen::<Block>()])?[0].0,
        );
        let ot = KosSender::init(channel, rng)?;
        let ggm_seeds = make_ggm_seeds(&lpn_seeds);
        Ok(VoleReceiver {
            lpn_seeds,
            ot,
            pows: Default::default(),
            ggm_seeds,
            delta,
            phantom: PhantomData,
        })
    }
    pub fn receive(
        &self,
        arena: &KeyedArena,
        selector: u64,
        rng: &mut (impl Rng + CryptoRng),
        base_voles: &[Mac<party::Verifier, T>],
        output_voles: &mut [Mac<party::Verifier, T>],
        mut incoming_bytes: &[u8],
        mut outgoing_bytes: &mut [u8],
    ) -> eyre::Result<VoleReceiverStep4<T>> {
        assert_eq!(base_voles.len(), T::VS.base_voles_needed);
        assert_eq!(output_voles.len(), T::VS.voles_outputted);
        eyre::ensure!(
            outgoing_bytes.len() == T::VS.comms_2r,
            "outgoing buffer wrong size. Got {}. Expected {}",
            outgoing_bytes.len(),
            T::VS.comms_2r
        );
        eyre::ensure!(
            incoming_bytes.len() == T::VS.comms_1s,
            "incoming buffer wrong size"
        );
        let base_voles = BaseVoles::new(base_voles);
        let mut gammas = [T::TF::ZERO; lpn_params::LPN_EXTEND_PARAMS_WEIGHT];
        assert_eq!(T::LPN.weight, lpn_params::LPN_EXTEND_PARAMS_WEIGHT);
        debug_assert_eq!(gammas.len(), T::VS.base_uws_size);
        for (gamma, v) in gammas.iter_mut().zip(base_voles.sps_base_voles().iter()) {
            let mut bytes: GenericArray<u8, <T::VF as CanonicalSerialize>::ByteReprLen> =
                Default::default();
            bytes.copy_from_slice(
                &incoming_bytes[0..<T::VF as CanonicalSerialize>::ByteReprLen::USIZE],
            );
            incoming_bytes = &incoming_bytes[<T::VF as CanonicalSerialize>::ByteReprLen::USIZE..];
            let a_prime = T::VF::from_bytes(&bytes)?;
            *gamma = v.tag(IS_VERIFIER) - a_prime * self.delta;
        }
        assert_eq!(T::LPN.weight, lpn_params::LPN_EXTEND_PARAMS_WEIGHT);
        assert_eq!(T::LPN.log2m, lpn_params::LPN_EXTEND_PARAMS_LOG_M);
        let mut keys = ArrayVec::<
            _,
            { lpn_params::LPN_EXTEND_PARAMS_WEIGHT * lpn_params::LPN_EXTEND_PARAMS_LOG_M },
        >::new();
        debug_assert_eq!(keys.capacity(), T::VS.ot_num_choices);
        // This is called n in some places in the original spsvole code, and m in others.
        let m = T::LPN.m();
        let result = output_voles;
        debug_assert_eq!(base_voles.sps_base_voles().len() * m, result.len());
        let mut ggm_temporary_storage = arena
            .alloc_slice_fill_with(ggm_temporary_storage_size(T::LPN.log2m), |_| {
                U8x16::default()
            });
        for i in 0..base_voles.sps_base_voles().len() {
            let seed = rng.gen::<Block>().0;
            ggm(
                T::LPN.log2m,
                seed,
                &self.ggm_seeds,
                TransparentWrapper::peel_slice_mut(TransparentWrapper::peel_slice_mut(
                    &mut result[i * m..(i + 1) * m],
                )),
                &mut keys,
                &mut ggm_temporary_storage,
            );
        }
        let ot_outgoing_size = KosSender::send_outgoing_bytes(T::VS.ot_num_choices);
        let ot_stage2 = self.ot.send(
            arena,
            selector,
            &keys,
            rng,
            incoming_bytes,
            &mut outgoing_bytes[0..ot_outgoing_size],
        )?;
        outgoing_bytes = &mut outgoing_bytes[ot_outgoing_size..];
        // This is true by construction. But it's a good reminder of this property.
        debug_assert_eq!(gammas.len() * m, result.len());
        debug_assert_eq!(result.len() % m, 0);
        for (gamma, results) in IntoIterator::into_iter(gammas).zip(result.chunks_exact(m)) {
            let d = gamma - results.iter().map(|mac| mac.tag(IS_VERIFIER)).sum();
            outgoing_bytes[0..<T::TF as CanonicalSerialize>::ByteReprLen::USIZE]
                .copy_from_slice(&d.to_bytes());
            outgoing_bytes =
                &mut outgoing_bytes[<T::TF as CanonicalSerialize>::ByteReprLen::USIZE..];
        }
        debug_assert!(outgoing_bytes.is_empty());
        Ok(VoleReceiverStep4 {
            ot_stage2,
            selector,
            phantom: PhantomData,
        })
    }
}
pub struct VoleReceiverStep4<T: MacTypes> {
    ot_stage2: KosSenderStage2,
    selector: u64,
    phantom: PhantomData<T>,
}
impl<'a, T: MacTypes> VoleReceiverStep4<T> {
    pub fn stage2(
        self,
        receiver: &VoleReceiver<T>,
        arena: &KeyedArena,
        base_voles: &[Mac<party::Verifier, T>],
        output_voles: &mut [Mac<party::Verifier, T>],
        mut incoming_bytes: &[u8],
        outgoing_bytes: &mut [u8],
    ) -> eyre::Result<VoleReceiverStep6<T>> {
        assert_eq!(base_voles.len(), T::VS.base_voles_needed);
        assert_eq!(output_voles.len(), T::VS.voles_outputted);
        let base_voles = BaseVoles::new(base_voles);
        let spsvole_result = output_voles;
        eyre::ensure!(
            outgoing_bytes.len() == T::VS.comms_4r,
            "wrong outgoing buffer size"
        );
        eyre::ensure!(
            incoming_bytes.len() == T::VS.comms_3s,
            "wrong outgoing buffer size"
        );
        self.ot_stage2
            .stage2(arena, &incoming_bytes[0..KosSenderStage2::INCOMING_BYTES])?;
        incoming_bytes = &incoming_bytes[KosSenderStage2::INCOMING_BYTES..];
        let mut x_stars: Arr<T::VF, DegreeModulo<T::VF, T::TF>> = Default::default();
        for x_star in x_stars.iter_mut() {
            let mut bytes: GenericArray<u8, <T::VF as CanonicalSerialize>::ByteReprLen> =
                Default::default();
            bytes.copy_from_slice(
                &incoming_bytes[0..<T::VF as CanonicalSerialize>::ByteReprLen::USIZE],
            );
            incoming_bytes = &incoming_bytes[bytes.len()..];
            *x_star = T::VF::from_bytes(&bytes)?;
        }
        let delta = receiver.delta;
        let seed = *<&[u8; 16]>::try_from(&incoming_bytes[0..16]).unwrap();
        incoming_bytes = &incoming_bytes[16..];
        let mut rng_chi = AesRng::from_seed(Block::from(seed));
        let y: T::TF = receiver
            .pows
            .iter()
            .zip(x_stars.iter().zip(base_voles.sps_base_consistency().iter()))
            .map(|(pow, (x, y))| (y.tag(IS_VERIFIER) - *x * delta) * *pow)
            .sum();
        let vb: T::TF = T::S::spsvole_receiver_consistency_check_compute_vb(
            &mut rng_chi,
            y,
            TransparentWrapper::peel_slice(TransparentWrapper::peel_slice(&spsvole_result)),
        );
        // Now run the eq protocol on vb
        let mut commitment = [0; 32];
        commitment.copy_from_slice(incoming_bytes);
        outgoing_bytes.copy_from_slice(&vb.to_bytes());
        Ok(VoleReceiverStep6 {
            commitment,
            vb,
            selector: self.selector,
            phantom: PhantomData,
        })
    }
}
pub struct VoleReceiverStep6<T: MacTypes> {
    commitment: [u8; 32],
    vb: T::TF,
    selector: u64,
    phantom: PhantomData<T>,
}
impl<'a, T: MacTypes> VoleReceiverStep6<T> {
    pub fn stage3(
        self,
        receiver: &VoleReceiver<T>,
        _arena: &KeyedArena,
        base_voles: &[Mac<party::Verifier, T>],
        output_voles: &mut [Mac<party::Verifier, T>],
        incoming_bytes: &[u8],
    ) -> eyre::Result<()> {
        assert_eq!(base_voles.len(), T::VS.base_voles_needed);
        assert_eq!(output_voles.len(), T::VS.voles_outputted);
        eyre::ensure!(
            incoming_bytes.len() == T::VS.comms_5s,
            "invalid incoming bytes size"
        );
        let mut commitment_key = [0; 32];
        commitment_key.copy_from_slice(incoming_bytes);
        // TODO: We don't care about constant time here. I think?
        eyre::ensure!(
            blake3::keyed_hash(&commitment_key, &self.vb.to_bytes()).as_bytes()
                == self.commitment.as_slice(),
            "sender commitment mismatch"
        );
        T::S::lpn_receiver(
            &mut lpn_rng_from_seed(self.selector, &receiver.lpn_seeds),
            TransparentWrapper::peel_slice(TransparentWrapper::peel_slice(base_voles)),
            TransparentWrapper::peel_slice_mut(TransparentWrapper::peel_slice_mut(output_voles)),
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests;
