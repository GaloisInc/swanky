use crate::circuit_ir::CompiledInfo;
use crate::circuit_ir::WireId;
use log::debug;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::ops::Bound;
use std::ptr::null_mut;

const VEC_SIZE_INIT: usize = 10;

//const VEC_SIZE_CALLFRAME_THRESHOLD: usize = 1000;
//const VEC_SIZE_MEMFRAME_THRESHOLD: usize = 10_000;
const VEC_SIZE_CALLFRAME_THRESHOLD: usize = 255;
const VEC_SIZE_MEMFRAME_THRESHOLD: usize = 100_023;

// That is pretty high. Lower it to try to save memory.
const CLEAR_FRAME_PERIOD: usize = 10_000;

#[repr(transparent)]
#[derive(Clone, Debug)]
struct WirePointer<X>(*mut X);

impl<X> Default for WirePointer<X> {
    fn default() -> Self {
        Self(null_mut())
    }
}

impl<X> WirePointer<X> {
    #[inline]
    fn incr(&self, i: isize) -> Self {
        Self(unsafe { self.0.offset(i) })
    }
}

#[test]
fn test_size_wire_ptr() {
    // X is instantiated with a big object on purpose
    assert!(std::mem::size_of::<WirePointer<Vec<usize>>>() <= 8);
}

// A Pool of wires.
// The pool is using a BTreeMap for mapping wire indices to the underlying vector of wire content.
// The interface of the Pool is `new()`, `clear()`, `present()`, `get()`, `set()`, `insert()/remove()`.
// One optimization in this structure is the use of a software cache.

// TODO: because of the unsafe character of certain operations, it might be a good idea to
// move this Pool to its own module and declare some functions of the API as `unsafe`.
// Same idea for the Stack frame. Another possible solution would be to use Mac'n'Cheese Wire map

// Allowed since the use of `Box` here can improve cache performance when many
// allocations occur
#[allow(clippy::box_collection)]
#[derive(Debug)]
pub(crate) struct Pool<X> {
    cache: RefCell<Cache<X>>, // We use a RefCell here, so that we can mutate the cache without having to declare the functions on `&mut self`. This is useful for implementing `get`
    pool: BTreeMap<WireId, Box<Vec<X>>>, // The `Box` around `Vec` is useful for performance reason. It makes searching in the BTreeMap faster.
}

struct Cache<X> {
    vector: Option<WirePointer<X>>,
    first: WireId,
    last: WireId,
}

impl<X> Default for Cache<X> {
    fn default() -> Self {
        Cache {
            first: 0,
            last: 0,
            vector: None,
        }
    }
}

impl<X> std::fmt::Debug for Cache<X> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Cache( first:{:?}, last:{:?} )", self.first, self.last)?;
        Ok(())
    }
}

impl<X> Cache<X> {
    fn in_cache(&self, id: WireId) -> bool {
        if self.vector.is_some() {
            self.first <= id && id <= self.last
        } else {
            false
        }
    }

    fn set_cache(&mut self, first: WireId, last: WireId, ptr: WirePointer<X>) {
        self.vector = Some(ptr);
        self.first = first;
        self.last = last;
    }

    fn invalidate(&mut self) {
        self.vector = None;
    }
}

impl<X> Pool<X>
where
    X: Clone + Copy + Default + Debug,
{
    fn new() -> Self {
        Pool {
            pool: BTreeMap::new(),
            cache: RefCell::new(Cache::default()),
        }
    }

    fn clear(&mut self) {
        self.pool.clear();
        self.cache.borrow_mut().invalidate();
    }

    #[inline]
    fn load_cache(&self, id: WireId) {
        let r = self
            .pool
            .range((Bound::Unbounded, Bound::Included(id)))
            .next_back();
        match r {
            None => {
                panic!("It had to be allocated");
            }
            Some((k, v)) => {
                let last = *k + (v.len() as WireId) - 1;
                debug_assert!(*k <= id && id <= last);
                let mut cache = self.cache.borrow_mut();
                cache.set_cache(*k, last, WirePointer(v.as_ptr() as *mut X));
            }
        }
    }

    // Check that a wire has been allocated. It updates the cache when the wire is present.
    fn present(&self, id: WireId) -> bool {
        if self.cache.borrow().in_cache(id) {
            return true;
        }

        // else it's not in the cache
        let r = self
            .pool
            .range((Bound::Unbounded, Bound::Included(id)))
            .next_back();
        match r {
            None => false,
            Some((k, v)) => {
                let last = *k + (v.len() as WireId) - 1;
                if *k <= id && id <= last {
                    let mut cache = self.cache.borrow_mut();
                    cache.set_cache(*k, last, WirePointer(v.as_ptr() as *mut X));
                    true
                } else {
                    false
                }
            }
        }
    }

    #[inline]
    fn move_to_cache_if_necessary(&self, id: WireId) {
        if self.cache.borrow().in_cache(id) {
            // nothing to do
            return;
        }
        self.load_cache(id);
    }

    fn get_when_in_cache(&self, id: WireId) -> &X {
        let cache = self.cache.borrow();
        unsafe {
            &*(cache
                .vector
                .as_ref()
                .unwrap()
                .0
                .offset((id - cache.first) as isize))
        }
    }

    #[cfg(test)]
    fn get(&self, id: WireId) -> &X {
        self.move_to_cache_if_necessary(id);
        self.get_when_in_cache(id)
    }

    fn get_ptr_when_in_cache(&self, id: WireId) -> WirePointer<X> {
        let cache = self.cache.borrow();
        unsafe {
            return WirePointer(
                cache
                    .vector
                    .as_ref()
                    .unwrap()
                    .0
                    .offset((id - cache.first) as isize),
            );
        }
    }

    fn get_ptr(&self, id: WireId) -> WirePointer<X> {
        self.move_to_cache_if_necessary(id);
        self.get_ptr_when_in_cache(id)
    }

    fn set_when_in_cache(&mut self, id: WireId, x: &X) {
        let cache = self.cache.borrow();
        unsafe {
            let ptr = cache
                .vector
                .as_ref()
                .unwrap()
                .0
                .offset((id - cache.first) as isize);
            *ptr = *x;
        }
    }

    #[cfg(test)]
    fn set(&mut self, id: WireId, x: &X) {
        self.move_to_cache_if_necessary(id);
        self.set_when_in_cache(id, x);
    }

    fn insert(&mut self, first: WireId, last: WireId) {
        self.pool.insert(
            first,
            Box::new(vec![
                Default::default();
                (last - first + 1).try_into().unwrap()
            ]),
        );
        self.cache.borrow_mut().invalidate();
    }

    // remove a slice in the pool whose first wire is `id`. When `id` is present it returns how many wires were in the slice.
    fn remove(&mut self, id: WireId) -> Option<usize> {
        self.cache.borrow_mut().invalidate();
        self.pool.remove(&id).map(|v| v.len())
    }
}

#[derive(Debug)]
struct CallframeElm<X> {
    first: WireId,
    last: WireId,
    wire_ptr: WirePointer<X>,
}

#[inline]
fn search_callframe<X>(v: &[CallframeElm<X>], id: WireId) -> WirePointer<X> {
    for r in v.iter() {
        let CallframeElm {
            first,
            last,
            wire_ptr,
        } = r;
        if *first <= id && id <= *last {
            return WirePointer(unsafe { wire_ptr.0.offset((id - first) as isize) });
        }
    }
    panic!("Not found")
}

#[inline]
fn set_callframe_if_ptr<X: Clone>(v: &[CallframeElm<X>], id: WireId, x: &X) {
    for r in v.iter() {
        let CallframeElm {
            first,
            last,
            wire_ptr,
        } = r;
        if *first <= id && id <= *last {
            unsafe {
                let addr = wire_ptr.0.offset((id - first) as isize);
                *addr = x.clone();
            }
            return;
        }
    }
    panic!("Not found")
}

#[derive(Debug)]
struct Callframe<X> {
    outputs_cnt: WireId,
    inputs_cnt: WireId,
    outputs: Vec<CallframeElm<X>>,
    inputs: Vec<CallframeElm<X>>,
}

impl<X> Callframe<X>
where
    X: Clone + Copy + Default + Debug,
{
    fn new() -> Self {
        Self {
            outputs: vec![],
            outputs_cnt: 0,
            inputs: vec![],
            inputs_cnt: 0,
        }
    }

    // Get in either outputs or inputs
    #[inline]
    fn get_either(&self, id: WireId) -> WirePointer<X> {
        if id < self.outputs_cnt {
            search_callframe(&self.outputs, id)
        } else {
            debug_assert!(id < self.inputs_cnt);
            search_callframe(&self.inputs, id)
        }
    }

    #[inline]
    fn get(&self, id: WireId) -> &X {
        let ptr = self.get_either(id);
        unsafe { &*ptr.0 }
    }

    #[inline]
    fn set(&mut self, id: WireId, x: &X) {
        if id < self.outputs_cnt {
            set_callframe_if_ptr(&self.outputs, id, x)
        } else {
            debug_assert!(id < self.inputs_cnt);
            set_callframe_if_ptr(&self.inputs, id, x)
        }
    }

    #[inline]
    fn allocate_outputs_ptr(&mut self, first: WireId, last: WireId, wire_ptr: WirePointer<X>) {
        self.outputs.push(CallframeElm {
            first,
            last,
            wire_ptr,
        });
    }

    #[inline]
    fn allocate_inputs_ptr(&mut self, first: WireId, last: WireId, wire_ptr: WirePointer<X>) {
        self.inputs.push(CallframeElm {
            first,
            last,
            wire_ptr,
        });
    }

    #[inline]
    fn clear(&mut self) {
        self.outputs.clear();
        self.outputs_cnt = 0;
        self.inputs.clear();
        self.inputs_cnt = 0;
    }
}

// A frame is made of
// 1) a call frame, and
// 2) a memory frame. The memory frame can be either
//    a) a `Pool` of allocated wire and a map of unallocated wires (`BTreeMap`), or
//    b) a vector containing both allocated and unallocated wires.
// The decision whether the memory frame is a pool or a vector is left to the function `push_frame`
// provided the information about the `args_count` and `body_max`
#[derive(Debug)]
struct Frame<X> {
    callframe_size: WireId,
    callframe: Callframe<X>,
    callframe_is_vector: bool,
    callframe_vector: Vec<WirePointer<X>>,

    memframe_pool: Pool<X>,
    memframe_is_vector: bool,
    memframe_vector: Vec<X>,
    memframe_unallocated: BTreeMap<WireId, Box<X>>,
    counter: usize,
}

impl<X> Frame<X>
where
    X: Clone + Copy + Default + Debug,
{
    fn new() -> Self {
        Frame {
            callframe_size: 0,
            callframe: Callframe::new(),
            callframe_is_vector: false,
            callframe_vector: vec![],
            memframe_pool: Pool::new(),
            memframe_is_vector: false,
            memframe_unallocated: BTreeMap::new(),
            memframe_vector: vec![Default::default(); VEC_SIZE_INIT],
            counter: 0,
        }
    }

    fn tick(&mut self) {
        self.counter += 1;

        if self.counter < CLEAR_FRAME_PERIOD {
            return;
        }

        self.callframe.clear();
        self.callframe_size = 0;
        self.callframe_vector.clear();

        self.memframe_pool.clear();
        self.memframe_unallocated.clear();
        self.memframe_vector.clear();
        self.memframe_is_vector = false;
        self.counter = 0;
    }
}

#[derive(Debug)]
pub(crate) struct Memory<X> {
    stack: Vec<Frame<X>>,
    top: usize,
}

impl<X> Memory<X>
where
    X: Clone + Copy + Default + Debug,
{
    pub(crate) fn new() -> Self {
        Memory {
            stack: vec![Frame::new()],
            top: 0,
        }
    }

    pub(crate) fn push_frame(&mut self, compiled_info: &CompiledInfo) {
        let callframe_is_vector = <WireId as TryInto<usize>>::try_into(compiled_info.args_count)
            .unwrap()
            < VEC_SIZE_CALLFRAME_THRESHOLD;

        let memframe_is_vector = compiled_info.body_max.is_some()
            && <WireId as TryInto<usize>>::try_into(compiled_info.body_max.unwrap()).unwrap()
                < VEC_SIZE_MEMFRAME_THRESHOLD;

        self.top += 1;

        if self.stack.len() <= self.top {
            // increase the stack
            self.stack.push(Frame::new());
            let frame = &mut self.stack[self.top];
            frame.callframe_is_vector = callframe_is_vector;
            frame.memframe_is_vector = memframe_is_vector;
        } else {
            let frame = &mut self.stack[self.top];
            frame.callframe_is_vector = callframe_is_vector;
            frame.memframe_is_vector = memframe_is_vector;

            // clear the things
            frame.callframe_size = 0;
            if !callframe_is_vector {
                frame.callframe.clear();
            }

            if !memframe_is_vector {
                frame.memframe_pool.clear();
                frame.memframe_unallocated.clear();
            }
        }

        self.stack[self.top].tick();

        let frame = &mut self.stack[self.top];

        frame.callframe.outputs_cnt = compiled_info.outputs_cnt;
        frame.callframe.inputs_cnt = compiled_info.inputs_cnt;

        // Resizing the callframe if necessary
        if callframe_is_vector {
            let s = compiled_info.args_count;
            if (s + 1)
                > (self.stack[self.top].callframe_vector.len())
                    .try_into()
                    .unwrap()
            {
                self.stack[self.top]
                    .callframe_vector
                    .resize((s + 1).try_into().unwrap(), Default::default());
            }
        }

        // Resizing the memframe_vector if necessary
        if memframe_is_vector {
            if let Some(s) = compiled_info.body_max {
                if (s + 1)
                    > self.stack[self.top]
                        .memframe_vector
                        .len()
                        .try_into()
                        .unwrap()
                {
                    let how_many = if s + 1 < compiled_info.args_count {
                        1
                    } else {
                        s + 1 - compiled_info.args_count
                    };
                    self.stack[self.top]
                        .memframe_vector
                        .resize(how_many.try_into().unwrap(), Default::default());
                }
            }
        }
    }

    pub(crate) fn pop_frame(&mut self) {
        self.top -= 1;
    }

    #[inline]
    fn get_callframe(&self, id: WireId) -> &X {
        self.stack[self.top].callframe.get(id)
    }

    #[inline]
    fn set_callframe(&mut self, id: WireId, x: &X) {
        self.stack[self.top].callframe.set(id, x);
    }

    #[inline]
    fn get_callframe_vector(wire_ptr: &WirePointer<X>) -> &X {
        unsafe { &*wire_ptr.0 }
    }

    #[inline]
    fn set_callframe_vector(wire_ptr: &WirePointer<X>, x: &X) {
        //debug!("SET VEC");
        unsafe {
            wire_ptr.0.write(*x);
        }
    }

    #[inline]
    fn get_frame(&self) -> &Frame<X> {
        &self.stack[self.top]
    }

    #[inline]
    fn get_frame_mut(&mut self) -> &mut Frame<X> {
        &mut self.stack[self.top]
    }

    #[inline]
    fn get_frame_previous_mut(&mut self) -> &mut Frame<X> {
        &mut self.stack[self.top - 1]
    }

    pub(crate) fn get(&self, id: WireId) -> &X {
        let frame = self.get_frame();
        let callframe_size = frame.callframe_size;
        if id < callframe_size {
            if !frame.callframe_is_vector {
                return self.get_callframe(id);
            } else {
                let addr = &frame.callframe_vector[id as usize];
                return Self::get_callframe_vector(addr);
            }
        }

        // else wire not in previous frame, so it can be in either
        // 1) vector allocated
        // 2) a) pool allocated,
        //    b) unallocated

        // 1)
        if frame.memframe_is_vector {
            return &frame.memframe_vector[(id - callframe_size) as usize];
        }

        // 2) a)
        if frame.memframe_pool.present(id) {
            return frame.memframe_pool.get_when_in_cache(id);
        }

        // 2) b)
        debug!("get: {:?}", frame.memframe_unallocated.get(&id).unwrap());
        return frame.memframe_unallocated.get(&id).unwrap();
    }

    pub(crate) fn set(&mut self, id: WireId, x: &X) {
        let frame = self.get_frame_mut();
        let callframe_size = frame.callframe_size;
        if id < callframe_size {
            if !frame.callframe_is_vector {
                self.set_callframe(id, x);
                return;
            } else {
                let addr = &frame.callframe_vector[id as usize].clone();
                Self::set_callframe_vector(addr, x);
                return;
            }
        }

        // else wire not in previous frame, so it can be in either
        // 1) vector allocated
        // 2) a) pool allocated,
        //    b) unallocated

        // 1)
        if frame.memframe_is_vector {
            frame.memframe_vector[(id - callframe_size) as usize] = *x;
            return;
        }

        // 2) a)
        if frame.memframe_pool.present(id) {
            frame.memframe_pool.set_when_in_cache(id, x);
            return;
        }

        // 2) b)
        debug!("set {:?}", x);
        frame.memframe_unallocated.insert(id, Box::new(*x));
    }

    fn place_ptr_in_callframe(
        &mut self,
        start: WireId,
        count: WireId,
        allow_allocation: bool,
        wire_ptr: WirePointer<X>,
    ) {
        let frame = self.get_frame_mut();

        if frame.callframe_is_vector {
            let mut idx = start as usize;
            for i in 0..(count as isize) {
                frame.callframe_vector[idx] = wire_ptr.incr(i);
                idx += 1;
            }
        } else if allow_allocation {
            frame
                .callframe
                .allocate_outputs_ptr(start, start + count - 1, wire_ptr);
        } else {
            frame
                .callframe
                .allocate_inputs_ptr(start, start + count - 1, wire_ptr);
        }
    }

    // Allocate single wire or wire ranges when they are not already allocated.
    pub(crate) fn allocate_possibly(&mut self, src_first: WireId, src_last: WireId) {
        let callframe_size = self.get_frame().callframe_size;
        let frame = self.get_frame_mut();

        // 1) wire from callframe
        if src_first < callframe_size {
            return;
        }
        // else 2) the slice is in a vector memframe
        if frame.memframe_is_vector {
            return;
        }

        // else slice in either
        // 3) pool allocated, we need to search through
        // 4) unallocated, the last option
        if frame.memframe_pool.present(src_first) {
            return;
        }

        // That's 4)
        if src_first != src_last {
            // Unallocated range
            frame.memframe_pool.insert(src_first, src_last);
        } else {
            // Unallocated single wire
            frame
                .memframe_unallocated
                .insert(src_first, Box::<X>::default());
        }
    }

    // This functions takes the first and last index of the caller,
    // finds the original slice associated with them,
    // and create a new slice added to the last frame.
    // There are four cases for the origin of the slice:
    // 1) in callframe from previous caller
    // 2) in vector memframe
    // 3) in allocated memframe
    // 4) in unallocated memframe
    // In addition, both the callframe and the memframe have a second mode, where the underlying structure
    // is a vector. For the callframe the vector holds addresses, for the memfarame it holds wires.
    pub(crate) fn allocate_slice(
        &mut self,
        src_first: WireId,
        src_last: WireId,
        start: WireId,
        count: WireId,
        allow_allocation: bool,
    ) {
        debug_assert_eq!(count, src_last - src_first + 1);

        // In any case we are going to increase the size of the Call Frame by count
        self.get_frame_mut().callframe_size += count;

        let callframe_is_vector = self.get_frame().callframe_is_vector;
        let frame = self.get_frame_previous_mut();
        let previous_callframe_size = frame.callframe_size;
        let previous_callframe_is_vector = frame.callframe_is_vector;

        // 1) wire from callframe
        if src_first < previous_callframe_size {
            debug_assert!(src_last < previous_callframe_size);

            let wire_ptr = if previous_callframe_is_vector {
                frame.callframe_vector[src_first as usize].clone()
            } else {
                frame.callframe.get_either(src_first)
            };
            self.place_ptr_in_callframe(start, count, allow_allocation, wire_ptr);
            return;
        }
        // else 2) the slice is in a vector memframe
        if frame.memframe_is_vector {
            // for the vector slice we need to shift by callframe_size so that the
            // indexing in the vector is correct using a slice_idx
            let wire_ptr = WirePointer(
                &mut frame.memframe_vector[(src_first - previous_callframe_size) as usize],
            );
            self.place_ptr_in_callframe(start, count, allow_allocation, wire_ptr);
            return;
        }

        // else slice in either
        // 3) pool allocated, we need to search through
        // 4) unallocated, the last option
        let new_slice;
        if frame.memframe_pool.present(src_first) {
            //println!("3) present in pool");
            let wire_ptr = frame.memframe_pool.get_ptr_when_in_cache(src_first);
            self.place_ptr_in_callframe(start, count, allow_allocation, wire_ptr);
        } else {
            //println!("4) unallocated");
            // if it is in unallocated then we need to allocate it
            if src_first != src_last {
                // Allocate single wires in pool now
                //println!("ALLOC NEW");
                if !allow_allocation {
                    panic!(
                        "Not allowed to allocate: maybe passed arguments are not allocated yet, \
                    or passing a range of wires in noncontiguous zone memory"
                    );
                }
                // println!("ALLOCATE_FRAME: EXTRA");
                frame.memframe_pool.insert(src_first, src_last);
                // NOTE: cannot use get_when_in_cache
                let wire_ptr = frame.memframe_pool.get_ptr(src_first);

                if callframe_is_vector {
                    //println!("callframe is vector");
                    new_slice = wire_ptr;
                    let last_frame = self.get_frame_mut();
                    let mut idx = start as usize;
                    for i in 0..(count as isize) {
                        last_frame.callframe_vector[idx] = new_slice.incr(i);
                        idx += 1;
                    }
                } else {
                    let last_frame = self.get_frame_mut();
                    last_frame
                        .callframe
                        .allocate_outputs_ptr(start, start + count - 1, wire_ptr);
                }
            } else {
                // Unallocated single wire
                let wire_ptr = if allow_allocation {
                    frame
                        .memframe_unallocated
                        .insert(src_first, Box::<X>::default());
                    WirePointer(
                        ((&**frame.memframe_unallocated.get(&src_first).unwrap()) as *const X)
                            .cast_mut(),
                    )
                } else {
                    // it is an input, and in that case we cant allocate, so it must be already assigned.
                    let ptr = frame.memframe_unallocated.get(&src_first);
                    if ptr.is_none() {
                        panic!("input passed but not previously assigned");
                    }
                    WirePointer(((&**ptr.unwrap()) as *const X).cast_mut())
                };

                let last_frame = self.get_frame_mut();
                if callframe_is_vector {
                    last_frame.callframe_vector[start as usize] = wire_ptr;
                } else if allow_allocation {
                    last_frame
                        .callframe
                        .allocate_outputs_ptr(start, start, wire_ptr);
                } else {
                    last_frame
                        .callframe
                        .allocate_inputs_ptr(start, start, wire_ptr);
                }
            }
        }
    }

    pub(crate) fn allocation_new(&mut self, first: WireId, last: WireId) {
        let frame = self.get_frame_mut();
        if !frame.memframe_is_vector {
            frame.memframe_pool.insert(first, last);
        }
    }

    pub(crate) fn allocation_delete(&mut self, first: WireId, last: WireId) {
        let frame = self.get_frame_mut();
        if !frame.memframe_is_vector {
            let mut remaining = last - first + 1;
            let mut curr = first;
            loop {
                // First we attempt to remove in the pool...
                let how_many = match frame.memframe_pool.remove(curr) {
                    Some(num_removed) => num_removed.try_into().unwrap(),
                    None => {
                        // ...if it is not present there then we attempt removing it in the unallocated wires.
                        frame.memframe_unallocated.remove(&curr)
                             .expect("cannot find wire to delete in either pool of allocated or unallocated wires");
                        // Anything removed from this pool accounts for exactly one wire
                        1
                    }
                };
                assert!(
                    how_many <= remaining,
                    "attempt to delete more wires than requested, "
                );
                remaining -= how_many;
                curr += how_many;
                if remaining == 0 {
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::memory::{Memory, Pool};

    fn test_cache1() {
        let mut pool = Pool::<u32>::new();

        // Insert 2 slices and check presence
        pool.insert(0, 3);
        assert!(pool.present(0));
        assert!(pool.present(1));
        assert!(pool.present(2));
        assert!(pool.present(3));
        assert!(!pool.present(4));

        pool.insert(4, 4);
        assert!(pool.present(4));
        assert!(!pool.present(5));

        pool.set(0, &0);
        assert_eq!(*pool.get(0), 0);
        pool.set(1, &11);
        assert_eq!(*pool.get(1), 11);
        pool.set(3, &33);
        assert_eq!(*pool.get(3), 33);

        pool.set(4, &44);
        assert_eq!(*pool.get(4), 44);

        // Insert a 3rd slice
        pool.insert(17, 19);
        pool.set(3, &333);
        assert_eq!(*pool.get(3), 333);
        pool.set(17, &117);
        assert_eq!(*pool.get(17), 117);

        // Delete the first slice
        pool.remove(0);
        assert!(!pool.present(0));
        assert!(!pool.present(3));

        // Add a subslice of the first slice
        pool.insert(1, 1);
        assert!(pool.present(1));
        assert!(!pool.present(2));

        assert_eq!(*pool.get(17), 117);
        pool.set(1, &11);
        assert_eq!(*pool.get(1), 11);

        // We clear everything
        pool.clear();
        assert!(!pool.present(0));
        assert!(!pool.present(1));
        assert!(!pool.present(2));
        assert!(!pool.present(3));
        assert!(!pool.present(4));
        assert!(!pool.present(17));
        assert!(!pool.present(19));

        // We add two slices to check the state after removing
        pool.insert(6, 7);
        pool.insert(0, 0);
        assert!(pool.present(0));
        assert!(pool.present(7));
        assert!(pool.present(6));
        pool.set(7, &77);
        assert_eq!(*pool.get(7), 77);
    }

    fn test_cache2() {
        // testing the removal of a slice in the cache
        let mut pool = Pool::<u32>::new();

        // Insert 2 slices and check presence
        pool.insert(0, 3);
        pool.insert(4, 4);
        pool.set(4, &44);
        pool.remove(4);

        assert!(!pool.present(4));
        assert!(pool.present(3));

        pool.remove(0);
        assert!(!pool.present(3));
        assert!(!pool.present(0));
    }

    #[test]
    fn test_memory_delete_spans_multiple_range() {
        // testing new and delete of spanning wire ranges.
        let mut mem = Memory::<char>::new();

        mem.allocation_new(0, 4);
        mem.allocation_new(5, 10);
        mem.allocation_new(11, 14);
        mem.allocation_new(15, 16);
        mem.allocation_new(17, 23);

        mem.allocation_delete(5, 10);
        mem.allocation_delete(11, 23);
    }

    #[test]
    fn test_memory_delete_implicit_allocation() {
        // testing delete of two implicitly allocated wires succeeds.
        let mut mem = Memory::<char>::new();

        mem.set(1, &'a');
        mem.set(2, &'b');

        mem.allocation_delete(1, 2);
    }

    #[test]
    fn test_memory_delete_explicit_and_implicit() {
        // testing delete of explicit allocation and one implicit.
        let mut mem = Memory::<char>::new();

        mem.allocation_new(100, 120);
        mem.set(121, &'b');
        mem.allocation_new(122, 140);

        mem.allocation_delete(100, 140);
    }

    #[test]
    fn test_allocate_possibly() {
        let mut mem = Memory::<char>::new();

        // tests some allocation that will allocate
        mem.allocate_possibly(100, 120);
        mem.allocate_possibly(121, 121);
        mem.allocate_possibly(122, 200);

        // delete one wire
        mem.allocation_delete(121, 121);
        // delete a range
        mem.allocation_delete(100, 120);

        // allocate a new range
        mem.allocation_new(200, 210);

        // allocate_possibly should do nothing on this wire
        mem.allocate_possibly(205, 205);
        // allocate_possibly should do nothing on this range
        mem.allocate_possibly(206, 210);
    }

    #[test]
    fn test_cache() {
        test_cache1();
        test_cache2();
    }
}
