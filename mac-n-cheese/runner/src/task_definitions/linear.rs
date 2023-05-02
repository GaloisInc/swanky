use std::marker::PhantomData;

use mac_n_cheese_ir::compilation_format::wire_format::LinearPrototypeWireFormat;
use mac_n_cheese_party::Party;
use mac_n_cheese_vole::mac::{Mac, MacTypes};

use crate::task_framework::{NoContinuation, TaskDefinition};

pub struct LinearTask<P: Party, T: MacTypes> {
    phantom: PhantomData<(P, T)>,
}

impl<P: Party, T: MacTypes> TaskDefinition<P> for LinearTask<P, T> {
    const NEEDS_CHALLENGE: bool = false;

    fn global_vole_support_needed() -> crate::task_framework::GlobalVolesNeeded {
        Default::default()
    }

    fn initialize(
        _c: &mut crate::tls::TlsConnection<P>,
        _rng: &mut scuttlebutt::AesRng,
        _vc: crate::base_vole::VoleContexts<P>,
        _num_runner_threads: usize,
    ) -> eyre::Result<Self> {
        Ok(Self {
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
        ctx: &mut crate::task_framework::TaskContext,
        input: &crate::task_framework::TaskInput<P>,
        _incoming_data: crate::alloc::OwnedAlignedBytes,
        _outgoing_data: crate::alloc::AlignedBytesMut,
    ) -> eyre::Result<crate::task_framework::TaskResult<P, Self::TaskContinuation>> {
        input.simple_wire_task::<2, 1, Mac<P, T>, _>(
            ctx,
            LinearPrototypeWireFormat::<T::VF>::default(),
            |[(a, a_c), (b, b_c)]| Ok([a * a_c + b * b_c]),
        )
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
