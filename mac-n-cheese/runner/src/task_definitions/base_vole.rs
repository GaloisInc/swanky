use std::{marker::PhantomData, sync::Arc};

use mac_n_cheese_ir::compilation_format::FieldMacType;
use mac_n_cheese_party::Party;
use mac_n_cheese_vole::{mac::MacTypes, vole::VoleSizes};

use crate::{
    alloc::TaskDataBuffer,
    base_vole::VoleContext,
    task_framework::{GlobalVolesNeeded, NoContinuation, TaskDefinition, TaskOutput},
    types::RandomMac,
};

pub struct BaseVoleTask<P: Party, T: MacTypes> {
    output: Arc<TaskOutput<P>>,
    phantom: PhantomData<T>,
}

impl<P: Party, T: MacTypes> TaskDefinition<P> for BaseVoleTask<P, T> {
    const NEEDS_CHALLENGE: bool = false;

    fn global_vole_support_needed() -> crate::task_framework::GlobalVolesNeeded {
        let mut out = GlobalVolesNeeded::default();
        out.insert(
            FieldMacType::get::<T::VF, T::TF>(),
            VoleSizes::of::<T::VF, T::TF>().base_voles_needed,
        );
        out
    }

    fn initialize(
        _c: &mut crate::tls::TlsConnection<P>,
        _rng: &mut scuttlebutt::AesRng,
        vc: crate::base_vole::VoleContexts<P>,
        _num_runner_threads: usize,
    ) -> eyre::Result<Self> {
        let ctx: &VoleContext<P, T> = vc.get();
        let mut output: TaskDataBuffer<RandomMac<P, T>> =
            TaskDataBuffer::with_capacity(ctx.base_voles.len());
        for x in ctx.base_voles.iter().copied() {
            output.push(x);
        }
        Ok(Self {
            output: Arc::new(TaskOutput::new_with(output)),
            phantom: PhantomData,
        })
    }

    type TaskContinuation = NoContinuation;

    fn finalize(
        self,
        _c: &mut crate::tls::TlsConnection<P>,
        _rng: &mut scuttlebutt::AesRng,
    ) -> eyre::Result<()> {
        Ok(())
    }

    fn start_task(
        &self,
        _ctx: &mut crate::task_framework::TaskContext,
        _input: &crate::task_framework::TaskInput<P>,
        _incoming_data: crate::alloc::OwnedAlignedBytes,
        _outgoing_data: crate::alloc::AlignedBytesMut,
    ) -> eyre::Result<crate::task_framework::TaskResult<P, Self::TaskContinuation>> {
        Ok(crate::task_framework::TaskResult::Finished(
            self.output.clone(),
        ))
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
