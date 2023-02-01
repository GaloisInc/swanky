use std::{any::type_name, collections::VecDeque};

use parking_lot::{Condvar, Mutex};

// TODO: rename this modle to queue.rs

pub struct Queue<T> {
    bound: Option<usize>,
    contents: Mutex<Option<VecDeque<T>>>,
    enqueue_waiters: Condvar,
    dequeue_waiters: Condvar,
}
impl<T> Queue<T> {
    pub fn bounded(bound: usize) -> Self {
        Self {
            bound: Some(bound),
            contents: Mutex::new(Some(VecDeque::with_capacity(bound))),
            enqueue_waiters: Condvar::new(),
            dequeue_waiters: Condvar::new(),
        }
    }
    pub fn unbounded(capacity: usize) -> Self {
        Self {
            bound: None,
            contents: Mutex::new(Some(VecDeque::with_capacity(capacity))),
            enqueue_waiters: Condvar::new(),
            dequeue_waiters: Condvar::new(),
        }
    }
    // May block
    pub fn enqueue(&self, data: T) {
        // TODO: add this to event log when it supports condvars
        let mut guard = self.contents.lock();
        if let Some(bound) = self.bound {
            self.enqueue_waiters.wait_while(&mut guard, |queue| {
                if let Some(queue) = queue.as_ref() {
                    queue.len() >= bound
                } else {
                    false
                }
            });
        }
        if let Some(queue) = guard.as_mut() {
            queue.push_back(data);
            self.dequeue_waiters.notify_one();
        } else {
            eprintln!(
                "WARNING tried to push to closed queue {}",
                type_name::<Self>()
            );
        }
    }
    // May block
    // Returns None if closed
    pub fn dequeue(&self) -> Option<T> {
        // TODO: add this to event log when it supports condvars
        let mut guard = self.contents.lock();
        loop {
            if let Some(queue) = guard.as_mut() {
                if let Some(t) = queue.pop_front() {
                    return Some(t);
                } else {
                    self.dequeue_waiters.wait(&mut guard);
                }
            } else {
                return None;
            }
        }
    }
    pub fn close(&self) {
        let mut guard = self.contents.lock();
        *guard = None;
        self.enqueue_waiters.notify_all();
        self.dequeue_waiters.notify_all();
    }
}
