use eyre::ContextCompat;
use mac_n_cheese_ir::compilation_format::FieldMacType;
use mac_n_cheese_party::Party;
use mac_n_cheese_vole::mac::{Mac, MacConstantContext, MacTypes};
use scuttlebutt::serialization::{CanonicalSerialize, SequenceDeserializer};
use std::{io::Cursor, sync::Arc};

use crate::{
    alloc::TaskDataBuffer,
    task_framework::{
        GlobalVolesNeeded, NoContinuation, ProverPrivateFieldElementCommunicator, TaskDefinition,
        TaskOutput,
    },
    types::RandomMac,
};

pub struct FixTask<P: Party, T: MacTypes> {
    constant_context: MacConstantContext<P, T::TF>,
}

impl<P: Party, T: MacTypes> TaskDefinition<P> for FixTask<P, T> {
    const NEEDS_CHALLENGE: bool = false;

    fn global_vole_support_needed() -> crate::task_framework::GlobalVolesNeeded {
        let mut out = GlobalVolesNeeded::default();
        out.insert(FieldMacType::get::<T::VF, T::TF>(), 0);
        out
    }

    fn initialize(
        _c: &mut crate::tls::TlsConnection<P>,
        _rng: &mut scuttlebutt::AesRng,
        vc: crate::base_vole::VoleContexts<P>,
        _num_runner_threads: usize,
    ) -> eyre::Result<Self> {
        Ok(Self {
            constant_context: vc.get::<T>().constant_context,
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
        incoming_data: crate::alloc::OwnedAlignedBytes,
        outgoing_data: crate::alloc::AlignedBytesMut,
    ) -> eyre::Result<crate::task_framework::TaskResult<P, Self::TaskContinuation>> {
        let random_macs: &[&[RandomMac<P, T>]] = input.multi_array_inputs(ctx, 0)?;
        let mut random_macs = random_macs.iter().flat_map(|x| *x);
        let mut cursor = input
            .prover_private_data
            .as_ref()
            .map(|input| Cursor::new(input.as_ref().map(|x| x.as_slice()).unwrap_or_default()));
        let mut deserializer = cursor
            .as_mut()
            .map(<T::VF as CanonicalSerialize>::Deserializer::new)
            .lift_result()?;
        let num_out = ctx.task_prototype.outputs().get(0).count() as usize;
        let mut out = TaskDataBuffer::<Mac<P, T>>::with_capacity(num_out);
        let mut c = ProverPrivateFieldElementCommunicator::<P, T::VF>::new(
            &incoming_data,
            &mut *outgoing_data,
        )?;
        for _ in 0..num_out {
            let random_mac = random_macs.next().context("ran out of VOLEs")?;
            let private_value = cursor
                .as_mut()
                .zip(deserializer.as_mut())
                .map(|(c, d)| d.read(c))
                .lift_result()?;
            let adjustment = private_value
                .zip(random_mac.0.mac_value().into())
                .map(|(x, r)| r - x);
            let adjustment = c.communicate(adjustment.into())?;
            out.push(random_mac.0 - Mac::constant(&self.constant_context, adjustment));
        }
        c.finish()?;
        Ok(crate::task_framework::TaskResult::Finished(Arc::new(
            TaskOutput::new_with(out),
        )))
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
