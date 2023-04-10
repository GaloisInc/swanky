use crate::task_queue::QueueName;
use mac_n_cheese_ir::compilation_format::{NumericalEnumType, TaskId, TaskPriority};

mac_n_cheese_event_log::define_events! {
    pub schema event_log {
        span ReadingCircuit,
        span ReadingPrivates,
        oneoff ProofStart,
        oneoff ProofFinish,
        span VoleInitialization,
        lock TaskQueueLock { queue_name: QueueName },
        oneoff EnqueuingTask { queue_name: QueueName, task_id: TaskId, priority: TaskPriority },
        span RunnerProcessingTask { task_id: TaskId, priority: TaskPriority },
        span BlockingTaskDequeue { queue_name: QueueName },
        span EnqueuingOutgoingData { task_id: TaskId, length: u64 },
        span EncryptingOutgoingData { task_id: TaskId, length: u64 },
        span SendingOutgoingData {
            task_id: TaskId,
            length: u64,
            connection_idx: u64,
        },
        lock IncomingSlotsLock,
        lock IncomingSlotLock {
            task_id: TaskId,
            fresh: bool,
        },
        oneoff ReadIncomingData {
            task_id: TaskId,
            length: u32,
            connection_idx: u64,
        },
        oneoff ProvidedReactorRequest { task_id: TaskId, priority: TaskPriority },
        span SendingChallenge { task_id: TaskId },
        oneoff GotChallenge { task_id: TaskId },
        span ReadingFromDisk {
            task_id: TaskId,
            priority: TaskPriority,
            public_file: bool,
        },
        oneoff DiskCacheHitOnRequest { task_id: TaskId, priority: TaskPriority },
        oneoff LaunchTask { task_id: TaskId },
        span FinalizingTaskKind { task_kind: NumericalEnumType },
        oneoff LimitedUseArcFreed { task_id: TaskId },
        oneoff TaskFinished { task_id: TaskId },
        span RunningTask { task_id: TaskId, step: u32 },
        span AllocatingFreshBackingBuffer { size: u64 },
        oneoff FreeingBackingBuffer { size: u64 },
        lock MemoryPoolLock { size: u64 },
        oneoff DiscardingBuffer { size: u64 },
        oneoff TriedToAddBufferToPool { size: u64, success: bool },
        oneoff TriedToTakeFromMemoryPool {
            size: u64,
            success: bool,
        },
        oneoff NoMemoryPoolFor { size: u64 },
    }
}
pub use event_log::*;
