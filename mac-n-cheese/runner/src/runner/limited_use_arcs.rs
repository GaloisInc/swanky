use arc_swap::ArcSwapOption;
use mac_n_cheese_ir::compilation_format::{AtomicGraphDegreeCount, TaskId};
use std::{
    marker::PhantomData,
    sync::{atomic::Ordering, Arc},
};

use crate::event_log::event_log;

// TODO: I think these type constraints are overly restrictive, but that's okay.
// TODO: would it better for cache coherency for us to permute these counts? Or might that make
// some things worse? It probably doesn't matter for us.
pub struct LimitedUseArcs<T> {
    remaining_uses: Vec<AtomicGraphDegreeCount>,
    contents: Vec<ArcSwapOption<T>>,
    phantom: PhantomData<Arc<T>>,
}
impl<T: 'static + Send + Sync> LimitedUseArcs<T> {
    pub fn new(remaining_uses: Vec<AtomicGraphDegreeCount>) -> Self {
        let mut contents = Vec::new();
        contents.resize_with(remaining_uses.len(), || ArcSwapOption::const_empty());
        Self {
            contents,
            remaining_uses,
            phantom: PhantomData,
        }
    }
    #[allow(unused)]
    pub fn len(&self) -> usize {
        debug_assert_eq!(self.remaining_uses.len(), self.contents.len());
        self.remaining_uses.len()
    }
    pub fn insert(&self, task_id: TaskId, value: Arc<T>) {
        let idx = task_id as usize;
        if self.remaining_uses[idx].load(Ordering::Relaxed) == 0 {
            return;
        }
        let old = self.contents[idx].swap(Some(value));
        assert!(old.is_none());
    }
    pub fn take_one(&self, task_id: TaskId) -> Arc<T> {
        let idx = task_id as usize;
        let remaining_uses = &self.remaining_uses[idx];
        let content = &self.contents[idx];
        let out = content.load_full();
        // We load out BEFORE we try to decrement the refcount. Otherwise content might be removed
        // before we have a chance to get a strong reference to it.
        match remaining_uses.fetch_sub(1, Ordering::Release) {
            0 => panic!("We've underflowed a reference count"),
            1 => {
                content.store(None);
                event_log::LimitedUseArcFreed { task_id }.submit();
            }
            _ => {}
        }
        match out {
            Some(out) => out,
            None => panic!("reference count mismatch for {}", idx),
        }
    }
}
