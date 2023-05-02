use std::{any::Any, marker::PhantomData, sync::atomic::AtomicBool};

use mac_n_cheese_party::Party;
use scuttlebutt::AesRng;

use crate::{
    alloc::{AlignedBytesMut, OwnedAlignedBytes},
    task_framework::{TaskContext, TaskDefinition, TaskInput, TaskResult},
    tls::TlsConnection,
};

trait ObjectSafeTaskDefinition<P: Party>: 'static + Send + Sync {
    fn needs_challenge(&self) -> bool;
    fn start_task(
        &self,
        ctx: &mut TaskContext,
        input: &TaskInput<P>,
        incoming_data: OwnedAlignedBytes,
        outgoing_data: AlignedBytesMut,
    ) -> eyre::Result<TaskResult<P, Box<dyn Any + Send>>>;
    fn continue_task(
        &self,
        tc: Box<dyn Any + Send>,
        ctx: &mut TaskContext,
        input: &TaskInput<P>,
        incoming_data: OwnedAlignedBytes,
        outgoing_data: AlignedBytesMut,
    ) -> eyre::Result<TaskResult<P, Box<dyn Any + Send>>>;
    fn finalize(&mut self, c: &mut TlsConnection<P>, rng: &mut AesRng) -> eyre::Result<()>;
}

struct TaskDefinitionWrapper<P: Party, T: TaskDefinition<P>>(Option<T>, PhantomData<P>);

fn erase_task_continuation<P: Party, T: Send + 'static>(
    tr: TaskResult<P, T>,
) -> TaskResult<P, Box<dyn Any + Send>> {
    match tr {
        TaskResult::NeedsCommunication(x) => {
            // eprintln!("needs communication");
            TaskResult::NeedsCommunication(Box::new(x))
        }
        TaskResult::Finished(x) => {
            // eprintln!("finished");
            TaskResult::Finished(x)
        }
    }
}

impl<P: Party, T: TaskDefinition<P>> ObjectSafeTaskDefinition<P> for TaskDefinitionWrapper<P, T> {
    fn needs_challenge(&self) -> bool {
        T::NEEDS_CHALLENGE
    }
    fn finalize(&mut self, c: &mut TlsConnection<P>, rng: &mut AesRng) -> eyre::Result<()> {
        self.0
            .take()
            .expect("Finalized called multiple times")
            .finalize(c, rng)
    }

    fn start_task(
        &self,
        ctx: &mut TaskContext,
        input: &TaskInput<P>,
        incoming_data: OwnedAlignedBytes,
        outgoing_data: AlignedBytesMut,
    ) -> eyre::Result<TaskResult<P, Box<dyn Any + Send>>> {
        /*eprintln!(
            "Starting task {} {}",
            ctx.task_id,
            std::any::type_name::<T>()
        );*/
        self.0
            .as_ref()
            .unwrap()
            .start_task(ctx, input, incoming_data, outgoing_data)
            .map(erase_task_continuation)
    }

    fn continue_task(
        &self,
        tc: Box<dyn Any + Send>,
        ctx: &mut TaskContext,
        input: &TaskInput<P>,
        incoming_data: OwnedAlignedBytes,
        outgoing_data: AlignedBytesMut,
    ) -> eyre::Result<TaskResult<P, Box<dyn Any + Send>>> {
        /*eprintln!(
            "Continuing task {} {}",
            ctx.task_id,
            std::any::type_name::<T>()
        );*/
        let tc = tc
            .downcast::<T::TaskContinuation>()
            .map_err(|_| "illegal task continuation type")
            .unwrap();
        self.0
            .as_ref()
            .unwrap()
            .continue_task(tc, ctx, input, incoming_data, outgoing_data)
            .map(erase_task_continuation)
    }
}

pub struct ErasedTaskDefinition<P: Party> {
    contents: Box<dyn ObjectSafeTaskDefinition<P>>,
    verified: AtomicBool,
}
impl<P: Party> ErasedTaskDefinition<P> {
    pub fn new(td: impl TaskDefinition<P>) -> Self {
        ErasedTaskDefinition {
            contents: Box::new(TaskDefinitionWrapper(Some(td), PhantomData)),
            verified: AtomicBool::new(false),
        }
    }
    pub fn verified(&self) -> &AtomicBool {
        &self.verified
    }
    pub fn needs_challenge(&self) -> bool {
        self.contents.needs_challenge()
    }
    pub fn finalize(&mut self, c: &mut TlsConnection<P>, rng: &mut AesRng) -> eyre::Result<()> {
        self.contents.finalize(c, rng)
    }

    pub fn start_task(
        &self,
        ctx: &mut TaskContext,
        input: &TaskInput<P>,
        incoming_data: OwnedAlignedBytes,
        outgoing_data: AlignedBytesMut,
    ) -> eyre::Result<TaskResult<P, Box<dyn Any + Send>>> {
        self.contents
            .start_task(ctx, input, incoming_data, outgoing_data)
    }
    pub fn continue_task(
        &self,
        tc: Box<dyn Any + Send>,
        ctx: &mut TaskContext,
        input: &TaskInput<P>,
        incoming_data: OwnedAlignedBytes,
        outgoing_data: AlignedBytesMut,
    ) -> eyre::Result<TaskResult<P, Box<dyn Any + Send>>> {
        self.contents
            .continue_task(tc, ctx, input, incoming_data, outgoing_data)
    }
}
