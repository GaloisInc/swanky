use eyre::ContextCompat;
use mac_n_cheese_ir::compilation_format::FieldMacType;
use mac_n_cheese_party::Party;
use mac_n_cheese_vole::mac::{Mac, MacConstantContext, MacTypes};
use scuttlebutt::serialization::{CanonicalSerialize, SequenceDeserializer};
use std::{io::Cursor, ops::Deref, sync::Arc};

use crate::{
    alloc::TaskDataBuffer,
    flatbuffers_ext::FbVectorExt,
    task_framework::{GlobalVolesNeeded, NoContinuation, TaskDefinition, TaskOutput, TaskResult},
};

pub struct ConstantTask<P: Party, T: MacTypes> {
    constant_context: MacConstantContext<P, T::TF>,
}
impl<P: Party, T: MacTypes> TaskDefinition<P> for ConstantTask<P, T> {
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
        Ok(ConstantTask {
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
        _incoming_data: crate::alloc::OwnedAlignedBytes,
        _outgoing_data: crate::alloc::AlignedBytesMut,
    ) -> eyre::Result<crate::task_framework::TaskResult<P, Self::TaskContinuation>> {
        let num_outputs = ctx
            .task_prototype
            .outputs()
            .get_opt(0)
            .context("invalid constant task prototype")?
            .count() as usize;
        let mut out = TaskDataBuffer::with_capacity(num_outputs);
        let mut cursor = Cursor::new(input.task_data().deref());
        let mut de = <T::VF as CanonicalSerialize>::Deserializer::new(&mut cursor)?;
        for _ in 0..num_outputs {
            out.push(Mac::<P, T>::constant(
                &self.constant_context,
                de.read(&mut cursor)?,
            ));
        }
        Ok(TaskResult::Finished(Arc::new(TaskOutput::new_with::<
            Mac<P, T>,
        >(out))))
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
