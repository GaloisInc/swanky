use std::{any::TypeId, sync::Arc};

use bytemuck::TransparentWrapper;
use keyed_arena::{KeyedArenaFromPool, KeyedArenaPool};
use mac_n_cheese_ir::compilation_format::FieldMacType;
use mac_n_cheese_vole::{
    mac::{Mac, MacTypes},
    party::{Party, WhichParty},
    specialization::SmallBinaryFieldSpecialization,
    vole::{
        VoleReceiver, VoleReceiverStep4, VoleReceiverStep6, VoleSender, VoleSenderStep3,
        VoleSenderStep5, VoleSizes,
    },
};
use smallvec::SmallVec;
use swanky_party::either::PartyEither;

use crate::{
    alloc::TaskDataBuffer,
    channel_adapter::ChannelAdapter,
    task_framework::{GlobalVolesNeeded, TaskDefinition, TaskOutput, TaskResult},
    types::RandomMac,
};

pub enum VerifierVoleStates<T: MacTypes> {
    Stage1(SmallVec<[VoleReceiverStep4<T>; 1]>),
    Stage2(SmallVec<[VoleReceiverStep6<T>; 1]>),
}
pub enum ProverVoleStates<T: MacTypes> {
    Stage1(SmallVec<[VoleSenderStep3<T>; 1]>),
    Stage2(SmallVec<[VoleSenderStep5<T>; 1]>),
}

type States<P, T> = PartyEither<P, ProverVoleStates<T>, VerifierVoleStates<T>>;
pub struct TaskContinuation<P: Party, T: MacTypes> {
    keyed_arena: KeyedArenaFromPool,
    output: TaskDataBuffer<RandomMac<P, T>>,
    states: States<P, T>,
}

pub struct VoleExtendTask<P: Party, T: MacTypes> {
    initial: PartyEither<P, VoleSender<T>, VoleReceiver<T>>,
    keyed_arena_pool: KeyedArenaPool,
}
impl<P: Party, T: MacTypes> VoleExtendTask<P, T> {
    const SIZES: VoleSizes = VoleSizes::of::<T::VF, T::TF>();
}

impl<P: Party, T: MacTypes> TaskDefinition<P> for VoleExtendTask<P, T> {
    const NEEDS_CHALLENGE: bool = false;

    fn global_vole_support_needed() -> crate::task_framework::GlobalVolesNeeded {
        let mut out = GlobalVolesNeeded::default();
        out.insert(FieldMacType::get::<T::VF, T::TF>(), 0);
        out
    }

    fn initialize(
        c: &mut crate::tls::TlsConnection<P>,
        rng: &mut swanky_rng::SwankyRng,
        vc: crate::base_vole::VoleContexts<P>,
        _num_runner_threads: usize,
    ) -> swanky_error::Result<Self> {
        Ok(Self {
            initial: match P::WHICH {
                WhichParty::Prover(e) => {
                    PartyEither::new(e, VoleSender::init(&mut ChannelAdapter(c), rng)?)
                }
                WhichParty::Verifier(e) => {
                    let alpha = vc.get::<T>().constant_context.into_inner(e);
                    let delta = -alpha;
                    PartyEither::new(e, VoleReceiver::init(&mut ChannelAdapter(c), rng, delta)?)
                }
            },
            // TODO: fill in these numbers.
            keyed_arena_pool: KeyedArenaPool::new(0, 0, 1),
        })
    }

    type TaskContinuation = TaskContinuation<P, T>;

    fn finalize(
        self,
        _c: &mut crate::tls::TlsConnection<P>,
        _rng: &mut swanky_rng::SwankyRng,
    ) -> swanky_error::Result<()> {
        Ok(())
    }

    // Can't replace chunks_exact here as the size, while constant,
    // requires unsupported operations.
    #[allow(clippy::chunks_exact_to_as_chunks)]
    fn start_task(
        &self,
        ctx: &mut crate::task_framework::TaskContext,
        input: &crate::task_framework::TaskInput<P>,
        incoming_data: crate::alloc::OwnedAlignedBytes,
        outgoing_data: crate::alloc::AlignedBytesMut,
    ) -> swanky_error::Result<crate::task_framework::TaskResult<P, Self::TaskContinuation>> {
        let base_voles = input.single_array_inputs::<RandomMac<P, T>>(ctx)?;
        let keyed_arena = self.keyed_arena_pool.get();
        let total_output_size = Self::SIZES.voles_outputted * base_voles.len();
        let mut output = TaskDataBuffer::<RandomMac<P, T>>::with_capacity(total_output_size);
        // Zero the output
        if TypeId::of::<T::S>() == TypeId::of::<SmallBinaryFieldSpecialization>() {
            // If we're using small binary fields, we can just zero out the MACs
            unsafe {
                std::ptr::write_bytes(output.as_mut_ptr(), 0, total_output_size);
                output.set_len(total_output_size);
            }
        } else {
            for _ in 0..total_output_size {
                output.push(RandomMac(Mac::zero()));
            }
        }
        let states: States<P, T> = match P::WHICH {
            WhichParty::Prover(e) => {
                let mut states = SmallVec::with_capacity(base_voles.len());
                for (i, (base_voles, outgoing_data)) in base_voles
                    .iter()
                    .copied()
                    .zip(outgoing_data.chunks_exact_mut(Self::SIZES.comms_1s))
                    .enumerate()
                {
                    let selector = (u64::from(ctx.task_id) << 32) | (i as u64);
                    states.push(self.initial.as_ref().into_inner(e).send(
                        &keyed_arena,
                        selector,
                        ctx.rng,
                        Mac::cast_slice(e, TransparentWrapper::peel_slice(base_voles)),
                        outgoing_data,
                    )?);
                }
                debug_assert_eq!(states.len(), base_voles.len());
                PartyEither::new(e, ProverVoleStates::Stage1(states))
            }
            WhichParty::Verifier(e) => {
                let mut states = SmallVec::with_capacity(base_voles.len());
                for (i, (((base_voles, incoming_data), outgoing_data), output_voles)) in base_voles
                    .iter()
                    .copied()
                    .zip(incoming_data.chunks_exact(Self::SIZES.comms_1s))
                    .zip(outgoing_data.chunks_exact_mut(Self::SIZES.comms_2r))
                    .zip(output.chunks_exact_mut(Self::SIZES.voles_outputted))
                    .enumerate()
                {
                    let selector = (u64::from(ctx.task_id) << 32) | (i as u64);
                    states.push(self.initial.as_ref().into_inner(e).receive(
                        &keyed_arena,
                        selector,
                        ctx.rng,
                        Mac::cast_slice(e, TransparentWrapper::peel_slice(base_voles)),
                        Mac::cast_slice_mut(e, TransparentWrapper::peel_slice_mut(output_voles)),
                        incoming_data,
                        outgoing_data,
                    )?);
                }
                debug_assert_eq!(states.len(), base_voles.len());
                PartyEither::new(e, VerifierVoleStates::Stage1(states))
            }
        };
        Ok(TaskResult::NeedsCommunication(TaskContinuation {
            keyed_arena,
            output,
            states,
        }))
    }

    // Can't replace chunks_exact here as the size, while constant,
    // requires unsupported operations.
    #[allow(clippy::chunks_exact_to_as_chunks)]
    fn continue_task(
        &self,
        tc: Box<Self::TaskContinuation>,
        ctx: &mut crate::task_framework::TaskContext,
        input: &crate::task_framework::TaskInput<P>,
        incoming_data: crate::alloc::OwnedAlignedBytes,
        outgoing_data: crate::alloc::AlignedBytesMut,
    ) -> swanky_error::Result<crate::task_framework::TaskResult<P, Self::TaskContinuation>> {
        let base_voles = input.single_array_inputs::<RandomMac<P, T>>(ctx)?;
        let TaskContinuation {
            keyed_arena,
            mut output,
            states,
        } = *tc;
        Ok(match P::WHICH {
            WhichParty::Prover(e) => match states.into_inner(e) {
                ProverVoleStates::Stage1(states) => {
                    let mut new_states = SmallVec::with_capacity(base_voles.len());
                    for ((((base_voles, incoming_data), outgoing_data), output_voles), state) in
                        base_voles
                            .iter()
                            .copied()
                            .zip(incoming_data.chunks_exact(Self::SIZES.comms_2r))
                            .zip(outgoing_data.chunks_exact_mut(Self::SIZES.comms_3s))
                            .zip(output.chunks_exact_mut(Self::SIZES.voles_outputted))
                            .zip(states)
                    {
                        new_states.push(state.stage2(
                            self.initial.as_ref().into_inner(e),
                            &keyed_arena,
                            Mac::cast_slice(e, TransparentWrapper::peel_slice(base_voles)),
                            Mac::cast_slice_mut(
                                e,
                                TransparentWrapper::peel_slice_mut(output_voles),
                            ),
                            incoming_data,
                            outgoing_data,
                        )?);
                    }
                    debug_assert_eq!(new_states.len(), base_voles.len());
                    TaskResult::NeedsCommunication(TaskContinuation {
                        keyed_arena,
                        output,
                        states: PartyEither::new(e, ProverVoleStates::Stage2(new_states)),
                    })
                }
                ProverVoleStates::Stage2(states) => {
                    for ((((base_voles, incoming_data), outgoing_data), output_voles), state) in
                        base_voles
                            .iter()
                            .copied()
                            .zip(incoming_data.chunks_exact(Self::SIZES.comms_4r))
                            .zip(outgoing_data.chunks_exact_mut(Self::SIZES.comms_5s))
                            .zip(output.chunks_exact_mut(Self::SIZES.voles_outputted))
                            .zip(states)
                    {
                        state.stage3(
                            self.initial.as_ref().into_inner(e),
                            &keyed_arena,
                            Mac::cast_slice(e, TransparentWrapper::peel_slice(base_voles)),
                            Mac::cast_slice_mut(
                                e,
                                TransparentWrapper::peel_slice_mut(output_voles),
                            ),
                            incoming_data,
                            outgoing_data,
                        )?;
                    }
                    TaskResult::Finished(Arc::new(TaskOutput::new_with(output)))
                }
            },
            WhichParty::Verifier(e) => match states.into_inner(e) {
                VerifierVoleStates::Stage1(states) => {
                    let mut new_states = SmallVec::with_capacity(base_voles.len());
                    for ((((base_voles, incoming_data), outgoing_data), output_voles), state) in
                        base_voles
                            .iter()
                            .copied()
                            .zip(incoming_data.chunks_exact(Self::SIZES.comms_3s))
                            .zip(outgoing_data.chunks_exact_mut(Self::SIZES.comms_4r))
                            .zip(output.chunks_exact_mut(Self::SIZES.voles_outputted))
                            .zip(states)
                    {
                        new_states.push(state.stage2(
                            self.initial.as_ref().into_inner(e),
                            &keyed_arena,
                            Mac::cast_slice(e, TransparentWrapper::peel_slice(base_voles)),
                            Mac::cast_slice_mut(
                                e,
                                TransparentWrapper::peel_slice_mut(output_voles),
                            ),
                            incoming_data,
                            outgoing_data,
                        )?);
                    }
                    debug_assert_eq!(new_states.len(), base_voles.len());
                    TaskResult::NeedsCommunication(TaskContinuation {
                        keyed_arena,
                        output,
                        states: PartyEither::new(e, VerifierVoleStates::Stage2(new_states)),
                    })
                }
                VerifierVoleStates::Stage2(states) => {
                    for (((base_voles, incoming_data), output_voles), state) in base_voles
                        .iter()
                        .copied()
                        .zip(incoming_data.chunks_exact(Self::SIZES.comms_5s))
                        .zip(output.chunks_exact_mut(Self::SIZES.voles_outputted))
                        .zip(states)
                    {
                        state.stage3(
                            self.initial.as_ref().into_inner(e),
                            &keyed_arena,
                            Mac::cast_slice(e, TransparentWrapper::peel_slice(base_voles)),
                            Mac::cast_slice_mut(
                                e,
                                TransparentWrapper::peel_slice_mut(output_voles),
                            ),
                            incoming_data,
                        )?;
                    }
                    TaskResult::Finished(Arc::new(TaskOutput::new_with(output)))
                }
            },
        })
    }
}
