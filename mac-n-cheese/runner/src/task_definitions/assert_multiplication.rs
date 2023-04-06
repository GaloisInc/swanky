use crate::task_framework::{GlobalVolesNeeded, NoContinuation, TaskDefinition, TaskResult};
use crate::types::RandomMac;
use generic_array::typenum::Unsigned;
use generic_array::GenericArray;
use mac_n_cheese_ir::compilation_format::wire_format::{
    AssertMultiplyPrototypeNoSpecWireFormat, AssertMultiplyPrototypeSmallBinaryWireFormat,
};
use mac_n_cheese_ir::compilation_format::FieldMacType;
use mac_n_cheese_party as party;
use mac_n_cheese_vole::mac::{Mac, MacConstantContext, MacTypes};
use mac_n_cheese_vole::specialization::SmallBinaryFieldSpecialization;
use parking_lot::Mutex;
use party::either::PartyEitherCopy;
use party::{IsParty, Party, WhichParty};
use rand::SeedableRng;
use scuttlebutt::field::{Degree, DegreeModulo, FiniteField, IsSubFieldOf, SmallBinaryField, F2};
use scuttlebutt::generic_array_length::Arr;
use scuttlebutt::ring::FiniteRing;
use scuttlebutt::serialization::CanonicalSerialize;
use scuttlebutt::AesRng;

use std::io::Read;
use std::io::Write;
use std::ops::AddAssign;
use vectoreyes::array_utils::ArrayUnrolledExt;
use vectoreyes::{SimdBase, U64x2};
mod vope {
    //! Assert that $`a * \alpha + b = t`$, without revealing them.
    //!
    //! This module operates in the tag field of the MAC. It will automatically lift VOLEs into the
    //! tag field if needed.
    use super::*;

    /// The vector needed to lift `DegreeModulo<T::VF, T::TF>` `T::VF` macs into a single `T::TF`
    /// mac.
    fn lifting_vector<T: MacTypes>() -> Arr<T::TF, DegreeModulo<T::VF, T::TF>> {
        GenericArray::from_exact_iter((0..DegreeModulo::<T::VF, T::TF>::USIZE).map(|i| {
            let mut out = GenericArray::<T::VF, DegreeModulo<T::VF, T::TF>>::default();
            out[i] = T::VF::ONE;
            <T::VF as IsSubFieldOf<T::TF>>::form_superfield(&out)
        }))
        .unwrap()
    }

    pub(super) const fn voles_needed<T: MacTypes>() -> usize {
        DegreeModulo::<T::VF, T::TF>::USIZE
    }
    pub(super) type VopeCommunication<FE> = [FE; 2];
    pub(super) fn vope_prover<P: Party, T: MacTypes>(
        a: T::TF,
        b: T::TF,
        voles: &[RandomMac<P, T>], // Size DegreeModulo<T::VF, T::TF>>
        e: IsParty<P, party::Prover>,
    ) -> VopeCommunication<T::TF> {
        assert_eq!(voles.len(), DegreeModulo::<T::VF, T::TF>::USIZE);
        let mut rnd0 = T::TF::ZERO;
        let mut rnd1 = T::TF::ZERO;
        for (pair, entry) in voles.iter().copied().zip(lifting_vector::<T>().into_iter()) {
            let (x, y) = pair.0.prover_extract(e);
            rnd0 += x * entry;
            rnd1 += y * entry;
        }
        [a + rnd0, b + rnd1]
    }
    pub(super) fn vope_verifier<P: Party, T: MacTypes>(
        alpha: T::TF,
        t: T::TF,
        voles: &[RandomMac<P, T>], // Size DegreeModulo<T::VF, T::TF>>
        e: IsParty<P, party::Verifier>,
        comms: VopeCommunication<T::TF>,
    ) -> eyre::Result<()> {
        assert_eq!(voles.len(), DegreeModulo::<T::VF, T::TF>::USIZE);
        let [u, v] = comms;
        let rnd = voles
            .iter()
            .copied()
            .zip(lifting_vector::<T>().into_iter())
            .map(|(v, entry)| v.0.tag(e) * entry)
            .sum::<T::TF>();
        eyre::ensure!(t + rnd == u * alpha + v, "vope multiplication check failed");
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use mac_n_cheese_ir::compilation_format::{FieldMacType, FieldTypeMacVisitor};
        use mac_n_cheese_vole::{mac::Mac, specialization::FiniteFieldSpecialization};
        use party::{IS_PROVER, IS_VERIFIER};
        use rand::SeedableRng;
        use scuttlebutt::AesRng;

        use super::*;

        fn do_test<T: MacTypes>() {
            eprintln!("Testing {}", std::any::type_name::<T>());
            for i in 1_u128..=256 {
                let mut rng = AesRng::from_seed(scuttlebutt::Block::from(85787 * i));
                let alpha = T::TF::random_nonzero(&mut rng);
                let u = T::TF::random(&mut rng);
                let v = T::TF::random(&mut rng);
                let t_right = u * alpha + v;
                let t_wrong = T::TF::random(&mut rng);
                let mut prover_voles: Vec<RandomMac<party::Prover, T>> = Vec::new();
                let mut verifier_voles: Vec<RandomMac<party::Verifier, T>> = Vec::new();
                for _ in 0..voles_needed::<T>() {
                    let x = T::VF::random(&mut rng);
                    let beta = T::TF::random(&mut rng);
                    let tag = x * alpha + beta;
                    prover_voles.push(RandomMac(Mac::prover_new(IS_PROVER, x, beta)));
                    verifier_voles.push(RandomMac(Mac::verifier_new(IS_VERIFIER, tag)));
                }
                let comms = vope_prover(u, v, &prover_voles, IS_PROVER);
                vope_verifier(alpha, t_right, &verifier_voles, IS_VERIFIER, comms).unwrap();
                assert!(
                    vope_verifier(alpha, t_wrong, &verifier_voles, IS_VERIFIER, comms).is_err()
                );
            }
        }
        #[test]
        fn test_all_field_types() {
            struct V;
            impl FieldTypeMacVisitor for &'_ mut V {
                type Output = ();
                fn visit<
                    VF: FiniteField + IsSubFieldOf<TF>,
                    TF: FiniteField,
                    S: FiniteFieldSpecialization<VF, TF>,
                >(
                    self,
                ) -> Self::Output {
                    do_test::<(VF, TF, S)>()
                }
            }
            FieldMacType::visit_all(V);
        }
    }
}

#[derive(Clone, Copy, Default)]
struct AssertMultiplyState<P: Party, FE: FiniteField>(PartyEitherCopy<P, (FE, FE), FE>);
impl<P: Party, FE: FiniteField> AssertMultiplyState<P, FE> {
    fn multiplication_proof<T: MacTypes<TF = FE>>(
        a: Mac<P, T>,
        b: Mac<P, T>,
        c: Mac<P, T>,
        ctx: &MacConstantContext<P, FE>,
        challenge: FE,
    ) -> Self {
        match P::WHICH {
            WhichParty::Prover(e) => {
                let (a_x, a_beta) = a.prover_extract(e);
                let (b_x, b_beta) = b.prover_extract(e);
                let (_c_x, c_beta) = c.prover_extract(e);
                Self(PartyEitherCopy::prover_new(
                    e,
                    (
                        a_beta * b_beta * challenge,
                        (b_x * a_beta + a_x * b_beta - c_beta) * challenge,
                    ),
                ))
            }
            WhichParty::Verifier(e) => {
                let a = a.tag(e);
                let b = b.tag(e);
                let c = c.tag(e);
                Self(PartyEitherCopy::verifier_new(
                    e,
                    (a * b - ctx.verifier_into(e) * c) * challenge,
                ))
            }
        }
    }
}

impl<P: Party, FE: FiniteField> AddAssign for AssertMultiplyState<P, FE> {
    fn add_assign(&mut self, rhs: Self) {
        match P::WHICH {
            WhichParty::Prover(e) => {
                let (x, y) = self.0.as_mut().prover_into(e);
                let (x2, y2) = rhs.0.prover_into(e);
                *x += x2;
                *y += y2;
            }
            WhichParty::Verifier(e) => {
                let dst = self.0.as_mut().verifier_into(e);
                let new = rhs.0.verifier_into(e);
                *dst += new;
            }
        }
    }
}

#[test]
fn test_assert_multiply_state() {
    use mac_n_cheese_ir::compilation_format::FieldTypeMacVisitor;
    use mac_n_cheese_vole::specialization::FiniteFieldSpecialization;
    use party::{IS_PROVER, IS_VERIFIER};
    fn do_test<T: MacTypes>() {
        eprintln!("Testing {}", std::any::type_name::<T>());
        for i in 1_u128..=256 {
            let mut rng = AesRng::from_seed(scuttlebutt::Block::from(68569425 * i));
            let alpha = T::TF::random_nonzero(&mut rng);
            let challenge = T::TF::random_nonzero(&mut rng);
            let mut prover_right_proof = AssertMultiplyState::<party::Prover, T::TF>::default();
            let mut verifier_right_proof = AssertMultiplyState::<party::Verifier, T::TF>::default();
            for _ in 0..16 {
                let x = T::VF::random(&mut rng);
                let y = T::VF::random(&mut rng);
                let z_right = x * y;
                let x_prover =
                    Mac::<party::Prover, T>::prover_new(IS_PROVER, x, T::TF::random(&mut rng));
                let y_prover =
                    Mac::<party::Prover, T>::prover_new(IS_PROVER, y, T::TF::random(&mut rng));
                let z_right_prover = Mac::<party::Prover, T>::prover_new(
                    IS_PROVER,
                    z_right,
                    T::TF::random(&mut rng),
                );
                prover_right_proof +=
                    AssertMultiplyState::<party::Prover, T::TF>::multiplication_proof::<T>(
                        x_prover,
                        y_prover,
                        z_right_prover,
                        &PartyEitherCopy::prover_new(IS_PROVER, ()),
                        challenge,
                    );
                let x_verifier = Mac::<party::Verifier, T>::verifier_new(
                    IS_VERIFIER,
                    x * alpha + x_prover.beta().into_inner(IS_PROVER),
                );
                let y_verifier = Mac::<party::Verifier, T>::verifier_new(
                    IS_VERIFIER,
                    y * alpha + y_prover.beta().into_inner(IS_PROVER),
                );
                let z_right_verifier = Mac::<party::Verifier, T>::verifier_new(
                    IS_VERIFIER,
                    z_right * alpha + z_right_prover.beta().into_inner(IS_PROVER),
                );
                verifier_right_proof +=
                    AssertMultiplyState::<party::Verifier, T::TF>::multiplication_proof::<T>(
                        x_verifier,
                        y_verifier,
                        z_right_verifier,
                        &PartyEitherCopy::verifier_new(IS_VERIFIER, alpha),
                        challenge,
                    );
                let prover_right_proof = prover_right_proof.0.prover_into(IS_PROVER);
                let verifier_right_proof = verifier_right_proof.0.verifier_into(IS_VERIFIER);
                assert_eq!(
                    prover_right_proof.0 + alpha * prover_right_proof.1,
                    verifier_right_proof
                );
            }
        }
    }
    struct V;
    impl FieldTypeMacVisitor for &'_ mut V {
        type Output = ();
        fn visit<
            VF: FiniteField + IsSubFieldOf<TF>,
            TF: FiniteField,
            S: FiniteFieldSpecialization<VF, TF>,
        >(
            self,
        ) -> Self::Output {
            do_test::<(VF, TF, S)>()
        }
    }
    FieldMacType::visit_all(V);
}

pub struct AssertMultiplyNoSpec<P: Party, T: MacTypes> {
    ctx: MacConstantContext<P, T::TF>,
    voles: Vec<RandomMac<P, T>>,
    state: Vec<Mutex<AssertMultiplyState<P, T::TF>>>,
}

impl<P: Party, T: MacTypes> TaskDefinition<P> for AssertMultiplyNoSpec<P, T> {
    const NEEDS_CHALLENGE: bool = true;

    fn global_vole_support_needed() -> GlobalVolesNeeded {
        let mut out = GlobalVolesNeeded::default();
        out.insert(
            FieldMacType::get::<T::VF, T::TF>(),
            vope::voles_needed::<T>(),
        );
        out
    }

    fn initialize(
        _c: &mut crate::tls::TlsConnection<P>,
        _rng: &mut scuttlebutt::AesRng,
        vc: crate::base_vole::VoleContexts<P>,
        num_runner_threads: usize,
    ) -> eyre::Result<Self> {
        let vc = vc.get::<T>();
        Ok(Self {
            ctx: vc.constant_context,
            voles: vc.base_voles.clone(),
            state: Vec::from_iter((0..num_runner_threads).map(|_| Default::default())),
        })
    }

    type TaskContinuation = NoContinuation;

    fn finalize(
        self,
        conn: &mut crate::tls::TlsConnection<P>,
        _rng: &mut scuttlebutt::AesRng,
    ) -> eyre::Result<()> {
        let mut acu = AssertMultiplyState::<P, T::TF>::default();
        for state in self.state.into_iter() {
            acu += state.into_inner();
        }
        match P::WHICH {
            WhichParty::Prover(e) => {
                let (u, v) = acu.0.prover_into(e);
                let [a, b] = vope::vope_prover(v, u, &self.voles, e);
                conn.write_all(&a.to_bytes())?;
                conn.write_all(&b.to_bytes())?;
            }
            WhichParty::Verifier(e) => {
                let alpha = self.ctx.verifier_into(e);
                let mut buf: GenericArray<u8, <T::TF as CanonicalSerialize>::ByteReprLen> =
                    Default::default();
                conn.read_exact(&mut buf)?;
                let u = T::TF::from_bytes(&buf)?;
                conn.read_exact(&mut buf)?;
                let v = T::TF::from_bytes(&buf)?;
                let t = acu.0.verifier_into(e);
                vope::vope_verifier(alpha, t, &self.voles, e, [u, v])?;
            }
        }
        Ok(())
    }

    fn start_task(
        &self,
        ctx: &mut crate::task_framework::TaskContext,
        input: &crate::task_framework::TaskInput<P>,
        _incoming_data: crate::alloc::OwnedAlignedBytes,
        _outgoing_data: crate::alloc::AlignedBytesMut,
    ) -> eyre::Result<crate::task_framework::TaskResult<P, Self::TaskContinuation>> {
        let mut seed = [0; 16];
        seed.copy_from_slice(&input.challenge.unwrap()[0..16]);
        let mut rng = AesRng::from_seed(seed.into());
        let mut acu = AssertMultiplyState::<P, T::TF>::default();
        let out = input.simple_wire_task::<3, 0, Mac<P, T>, _>(
            ctx,
            AssertMultiplyPrototypeNoSpecWireFormat::default(),
            |[(a, ()), (b, ()), (c, ())]| {
                let challenge = T::TF::random_nonzero(&mut rng);
                acu += AssertMultiplyState::multiplication_proof(a, b, c, &self.ctx, challenge);
                Ok([])
            },
        )?;
        *self.state[ctx.thread_id].lock() += acu;
        Ok(out)
    }

    fn continue_task(
        &self,
        _tc: Box<Self::TaskContinuation>,
        _ctx: &mut crate::task_framework::TaskContext,
        _input: &crate::task_framework::TaskInput<P>,
        _incoming_data: crate::alloc::OwnedAlignedBytes,
        _outgoing_data: crate::alloc::AlignedBytesMut,
    ) -> eyre::Result<crate::task_framework::TaskResult<P, Self::TaskContinuation>> {
        unreachable!()
    }
}

type UnspecializedSmallBinary<P, TF> =
    AssertMultiplyNoSpec<P, (F2, TF, SmallBinaryFieldSpecialization)>;
pub struct AssertMultiplySmallBinary<P: Party, TF: SmallBinaryField>
where
    F2: IsSubFieldOf<TF>,
{
    unspecialized: UnspecializedSmallBinary<P, TF>,
}

impl<P: Party, TF: SmallBinaryField> TaskDefinition<P> for AssertMultiplySmallBinary<P, TF>
where
    F2: IsSubFieldOf<TF>,
{
    const NEEDS_CHALLENGE: bool = UnspecializedSmallBinary::<P, TF>::NEEDS_CHALLENGE;

    fn global_vole_support_needed() -> GlobalVolesNeeded {
        UnspecializedSmallBinary::<P, TF>::global_vole_support_needed()
    }

    fn initialize(
        c: &mut crate::tls::TlsConnection<P>,
        rng: &mut AesRng,
        vc: crate::base_vole::VoleContexts<P>,
        num_runner_threads: usize,
    ) -> eyre::Result<Self> {
        UnspecializedSmallBinary::<P, TF>::initialize(c, rng, vc, num_runner_threads)
            .map(|unspecialized| AssertMultiplySmallBinary { unspecialized })
    }

    type TaskContinuation = NoContinuation;

    fn finalize(self, c: &mut crate::tls::TlsConnection<P>, rng: &mut AesRng) -> eyre::Result<()> {
        self.unspecialized.finalize(c, rng)
    }

    fn start_task(
        &self,
        ctx: &mut crate::task_framework::TaskContext,
        input: &crate::task_framework::TaskInput<P>,
        _incoming_data: crate::alloc::OwnedAlignedBytes,
        _outgoing_data: crate::alloc::AlignedBytesMut,
    ) -> eyre::Result<TaskResult<P, Self::TaskContinuation>> {
        let mut seed = [0; 16];
        seed.copy_from_slice(&input.challenge.unwrap()[0..16]);
        let mut rng = AesRng::from_seed(seed.into());
        let mut acu: PartyEitherCopy<P, (U64x2, U64x2), U64x2> = PartyEitherCopy::default();
        let alpha = match P::WHICH {
            WhichParty::Prover(e) => PartyEitherCopy::prover_new(e, ()),
            WhichParty::Verifier(e) => PartyEitherCopy::verifier_new(
                e,
                U64x2::from([TF::peel(self.unspecialized.ctx.verifier_into(e)), 0]),
            ),
        };
        let out = input.small_binary_mac_task::<3, 0, (F2, TF, SmallBinaryFieldSpecialization)>(
            ctx,
            AssertMultiplyPrototypeSmallBinaryWireFormat::default(),
            #[inline(always)]
            |[a, b, c]| {
                // Hopefully the reorder buffer will fix this for us.
                let challenge = rng.random_bits_custom_size::<2>();
                let mask = U64x2::broadcast((1_u64 << Degree::<TF>::U64) - 1);
                let challenge = challenge.array_map(
                    #[inline(always)]
                    |x| U64x2::from(x) & mask,
                );
                <[U64x2; 2]>::from(a)
                    .array_zip(<[U64x2; 2]>::from(b))
                    .array_zip(<[U64x2; 2]>::from(c))
                    .array_zip(challenge)
                    .array_for_each(
                        #[inline(always)]
                        |(((a, b), c), challenge)| match P::WHICH {
                            WhichParty::Prover(e) => {
                                let a_x = a.shift_right::<63>();
                                let b_x = b.shift_right::<63>();
                                let a_x_mask = a_x.cmp_eq(U64x2::ZERO);
                                let b_x_mask = b_x.cmp_eq(U64x2::ZERO);
                                let a_beta = a.shift_left::<1>().shift_right::<1>();
                                let b_beta = b.shift_left::<1>().shift_right::<1>();
                                let c_beta = c.shift_left::<1>().shift_right::<1>();
                                let sum =
                                    a_beta.and_not(b_x_mask) ^ b_beta.and_not(a_x_mask) ^ c_beta;
                                acu.as_mut().prover_into(e).1 ^= sum
                                    .carryless_mul::<false, false>(challenge)
                                    ^ sum.carryless_mul::<true, true>(challenge);
                                let betas_product_0 = a_beta.carryless_mul::<false, false>(b_beta);
                                let betas_product_1 = a_beta.carryless_mul::<true, true>(b_beta);
                                let [betas_product] = TF::reduce_vectored(
                                    [betas_product_0.unpack_hi(betas_product_1)],
                                    [betas_product_0.unpack_lo(betas_product_1)],
                                );
                                let product_0 =
                                    betas_product.carryless_mul::<false, false>(challenge);
                                let product_1 =
                                    betas_product.carryless_mul::<true, true>(challenge);
                                acu.as_mut().prover_into(e).0 ^= product_0 ^ product_1;
                            }
                            WhichParty::Verifier(e) => {
                                let alpha = alpha.verifier_into(e);
                                // a*b
                                let ab0 = a.carryless_mul::<false, false>(b);
                                let ab1 = a.carryless_mul::<true, true>(b);
                                // alpha * c
                                let alpha_c0 = alpha.carryless_mul::<false, false>(c);
                                let alpha_c1 = alpha.carryless_mul::<true, false>(c);
                                let sum0 = ab0 ^ alpha_c0;
                                let sum1 = ab1 ^ alpha_c1;
                                let [reduced] = TF::reduce_vectored(
                                    [sum0.unpack_hi(sum1)],
                                    [sum0.unpack_lo(sum1)],
                                );
                                *acu.as_mut().verifier_into(e) ^=
                                    challenge.carryless_mul::<false, false>(reduced);
                                *acu.as_mut().verifier_into(e) ^=
                                    challenge.carryless_mul::<true, true>(reduced);
                            }
                        },
                    );
                Ok([])
            },
        )?;
        *self.unspecialized.state[ctx.thread_id].lock() += AssertMultiplyState(match P::WHICH {
            WhichParty::Prover(e) => {
                let (a, b) = acu.prover_into(e);
                PartyEitherCopy::prover_new(e, (TF::reduce(a), TF::reduce(b)))
            }
            WhichParty::Verifier(e) => {
                PartyEitherCopy::verifier_new(e, TF::reduce(acu.verifier_into(e)))
            }
        });
        Ok(out)
    }

    fn continue_task(
        &self,
        _tc: Box<Self::TaskContinuation>,
        _ctx: &mut crate::task_framework::TaskContext,
        _input: &crate::task_framework::TaskInput<P>,
        _incoming_data: crate::alloc::OwnedAlignedBytes,
        _outgoing_data: crate::alloc::AlignedBytesMut,
    ) -> eyre::Result<TaskResult<P, Self::TaskContinuation>> {
        unreachable!()
    }
}
