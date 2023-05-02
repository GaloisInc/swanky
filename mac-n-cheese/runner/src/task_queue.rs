use std::{collections::BinaryHeap, ops::DerefMut};

use mac_n_cheese_ir::compilation_format::{TaskId, TaskPriority};

use parking_lot::{Condvar, Mutex};

use crate::event_log;

pub type QueueName = u8;
pub const QUEUE_NAME_RUN_QUEUE: u8 = 1;
pub const QUEUE_NAME_THREAD_POOL_FILE_READ_REQUEST: u8 = 2;

// The pair (task_id, priority) can uniquely identify the stage of a task.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct RunningTaskId {
    pub task_id: TaskId,
    pub priority: TaskPriority,
}

pub struct TaskQueueEntry<T> {
    pub id: RunningTaskId,
    pub metadata: T,
}
impl<T> TaskQueueEntry<T> {
    fn sort_key(&self) -> impl Ord {
        // We want high priority, low task ID tasks to go first
        (self.id.priority, std::cmp::Reverse(self.id.task_id))
    }
}
impl<T> PartialEq for TaskQueueEntry<T> {
    fn eq(&self, other: &Self) -> bool {
        self.sort_key().eq(&other.sort_key())
    }
}
impl<T> Eq for TaskQueueEntry<T> {}
impl<T> PartialOrd for TaskQueueEntry<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.sort_key().partial_cmp(&other.sort_key())
    }
}
impl<T> Ord for TaskQueueEntry<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.sort_key().cmp(&other.sort_key())
    }
}

pub struct TaskQueue<T> {
    name: QueueName,
    queue: Mutex<Option<BinaryHeap<TaskQueueEntry<T>>>>,
    queue_changed: Condvar,
}
impl<T> TaskQueue<T> {
    pub fn new(name: QueueName) -> Self {
        TaskQueue {
            queue: Mutex::new(Some(BinaryHeap::with_capacity(8192))),
            queue_changed: Condvar::new(),
            name,
        }
    }
    // This WILL NOT block.
    pub fn enqueue(&self, item: TaskQueueEntry<T>) {
        event_log::EnqueuingTask {
            queue_name: self.name,
            task_id: item.id.task_id,
            priority: item.id.priority,
        }
        .submit();
        let mut guard = event_log::TaskQueueLock {
            queue_name: self.name,
        }
        .lock(&self.queue);
        if let Some(queue) = guard.as_mut() {
            queue.push(item);
            self.queue_changed.notify_one();
        } else {
            std::mem::drop(guard);
            eprintln!("Dropping value attempted to enqueue on closed task queue");
        }
    }
    pub fn blocking_dequeue(&self) -> Option<TaskQueueEntry<T>> {
        // TODO: make the event log support condition variables.
        let span = event_log::BlockingTaskDequeue {
            queue_name: self.name,
        }
        .start();
        let mut guard = self.queue.lock();
        let entry = loop {
            if let Some(queue) = guard.as_mut() {
                if let Some(entry) = queue.pop() {
                    break entry;
                }
                self.queue_changed.wait(&mut guard);
            } else {
                // We intentionally don't finish the span.
                return None;
            }
        };
        std::mem::drop(guard);
        span.finish();
        Some(entry)
    }
    pub fn close(&self) {
        let old_queue = {
            let mut guard = event_log::TaskQueueLock {
                queue_name: self.name,
            }
            .lock(&self.queue);
            let old_queue = std::mem::take(guard.deref_mut());
            self.queue_changed.notify_all();
            old_queue
        };
        if let Some(old_queue) = old_queue {
            if !old_queue.is_empty() {
                eprintln!(
                    "Warning: closing task queue with {} items remaining",
                    old_queue.len()
                );
            }
        }
    }
}
