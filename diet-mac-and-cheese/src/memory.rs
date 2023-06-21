use crate::circuit_ir::WireId;
#[allow(unused_imports)]
use log::{debug, info};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fmt::Debug;
use std::ops::Bound;

use std::ptr::null_mut;

const VEC_SIZE_INIT: usize = 10;
const VEC_SIZE_CALLFRAME_THRESHOLD: usize = 1000;
const VEC_SIZE_MEMFRAME_THRESHOLD: usize = 10_000;

#[repr(transparent)]
#[derive(Clone)]
struct Pointer<X>(*mut X);

impl<X> std::fmt::Debug for Pointer<X> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "***")?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
enum AbsoluteAddr<X> {
    PoolAllocated(PoolAddr<X>),
    Unallocated(Box<UnallocatedAddr>),
    VectorAllocated(VectorAddr<X>),
}

#[repr(transparent)]
#[derive(Clone, Debug)]
struct PoolAddr<X> {
    ptr: Pointer<X>,
}

impl<X> PoolAddr<X> {
    fn incr(&mut self, i: WireId) {
        self.ptr = Pointer(unsafe { self.ptr.0.add(i as usize) });
    }
}

#[derive(Clone, Debug)]
struct UnallocatedAddr {
    level: usize,
    idx: WireId,
}

impl UnallocatedAddr {
    fn incr(&mut self, i: WireId) {
        assert_eq!(i, 0);
        // does not make sense to increment an unallocated address
        //self.idx += i;
    }
}

#[derive(Clone, Debug)]
#[repr(transparent)]
struct VectorAddr<X> {
    ptr: Pointer<X>,
}

impl<X> VectorAddr<X> {
    fn incr(&mut self, i: WireId) {
        self.ptr = Pointer(unsafe { self.ptr.0.add(i as usize) });
    }
}

impl<X> Default for AbsoluteAddr<X> {
    fn default() -> Self {
        Self::VectorAllocated(VectorAddr {
            ptr: Pointer(null_mut()),
        })
    }
}

impl<X> AbsoluteAddr<X> {
    fn incr(&mut self, i: WireId) {
        match self {
            Self::PoolAllocated(loc) => {
                loc.incr(i);
            }
            Self::Unallocated(loc) => {
                loc.incr(i);
            }
            Self::VectorAllocated(loc) => {
                loc.incr(i);
            }
        }
    }
}

// A Pool of wires.
// The pool is using a BTreeMap for mapping wire indices to the underlying vector of wire content.
// The interface of the Pool is `new()`, `clear()`, `present()`, `get()`, `set()`, `insert()/remove()`.
// One optimization in this structure is the use of a software cache.

// TODO: because of the unsafe character of certain operations, it might be a good idea to
// move this Pool to its own module and declare some functions of the API as `unsafe`.
// Same idea for the Stack frame. Another possible solution would be to use Mac'n'Cheese Wire map
#[derive(Debug)]
pub(crate) struct Pool<X> {
    pool: BTreeMap<WireId, Vec<X>>,
    cache: RefCell<Cache<X>>, // We use a RefCell here, so that we can mutate the cache without having to declare the functions on `&mut self`. This is useful for implementing `get`
}

struct Cache<X> {
    first: WireId,
    last: WireId,
    vector: Option<Pointer<X>>,
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

    fn set_cache(&mut self, first: WireId, last: WireId, ptr: Pointer<X>) {
        self.first = first;
        self.last = last;
        self.vector = Some(ptr);
    }

    fn invalidate(&mut self) {
        self.first = 0;
        self.last = 0;
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
            .last();
        match r {
            None => {
                panic!("It had to be allocated");
            }
            Some((k, v)) => {
                let last = *k + (v.len() as WireId) - 1;
                assert!(*k <= id && id <= last);
                let mut cache = self.cache.borrow_mut();
                cache.set_cache(*k, last, Pointer(v.as_ptr() as *mut X));
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
            .last();
        match r {
            None => false,
            Some((k, v)) => {
                let last = *k + (v.len() as WireId) - 1;
                if *k <= id && id <= last {
                    let mut cache = self.cache.borrow_mut();
                    cache.set_cache(*k, last, Pointer(v.as_ptr() as *mut X));
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

    fn get(&self, id: WireId) -> &X {
        self.move_to_cache_if_necessary(id);
        let cache = self.cache.borrow();
        unsafe {
            cache
                .vector
                .as_ref()
                .unwrap()
                .0
                .offset((id - cache.first) as isize)
                .as_ref()
                .unwrap()
        }
    }

    fn get_ptr(&self, id: WireId) -> Pointer<X> {
        self.move_to_cache_if_necessary(id);

        let cache = self.cache.borrow();
        unsafe {
            return Pointer(
                cache
                    .vector
                    .as_ref()
                    .unwrap()
                    .0
                    .offset((id - cache.first) as isize) as *mut X,
            );
        }
    }

    fn set(&mut self, id: WireId, x: &X) {
        self.move_to_cache_if_necessary(id);
        // TODO: maybe there is something more efficient here
        let cache = self.cache.borrow();
        unsafe {
            let ptr = cache
                .vector
                .as_ref()
                .unwrap()
                .0
                .offset((id - cache.first) as isize) as *mut X;
            *ptr = *x;
        }
    }

    fn insert(&mut self, first: WireId, last: WireId) {
        self.pool.insert(
            first,
            vec![Default::default(); (last - first + 1).try_into().unwrap()],
        );
        self.cache.borrow_mut().invalidate();
    }

    fn remove(&mut self, id: WireId) -> usize {
        self.cache.borrow_mut().invalidate();
        self.pool.remove(&id).unwrap().len()
    }
}

// A slice in a pool or a vec
#[derive(Debug)]
struct PoolVecSlice<X> {
    first: WireId,
    last: WireId,
    ptr: Pointer<X>,
}

#[derive(Debug)]
enum CallframeElm<X> {
    PoolVec(PoolVecSlice<X>),
    Unallocated {
        first: WireId,
        unalloc: Box<UnallocatedAddr>,
    },
}

fn mk_from_absadr<X>(first: WireId, last: WireId, addr: AbsoluteAddr<X>) -> CallframeElm<X> {
    match addr {
        AbsoluteAddr::PoolAllocated(PoolAddr { ptr }) => {
            CallframeElm::PoolVec(PoolVecSlice { first, last, ptr })
        }
        AbsoluteAddr::VectorAllocated(VectorAddr { ptr }) => {
            CallframeElm::PoolVec(PoolVecSlice { first, last, ptr })
        }
        AbsoluteAddr::Unallocated(unalloc) => {
            assert_eq!(first, last);
            CallframeElm::Unallocated { first, unalloc }
        }
    }
}

impl<X> CallframeElm<X> {
    fn to_absolute_addr(&self) -> AbsoluteAddr<X> {
        match self {
            CallframeElm::PoolVec(PoolVecSlice {
                first: _,
                last: _,
                ptr,
            }) => AbsoluteAddr::VectorAllocated(VectorAddr {
                ptr: Pointer(ptr.0),
            }),
            CallframeElm::Unallocated { first: _, unalloc } => {
                AbsoluteAddr::Unallocated(Box::new(UnallocatedAddr {
                    level: unalloc.level,
                    idx: unalloc.idx,
                }))
            }
        }
    }
}

enum FoundOrLevel<T> {
    Found(T),
    Ref { level: usize, idx: WireId },
}

fn search_callframe<X>(v: &[CallframeElm<X>], id: WireId) -> FoundOrLevel<Pointer<X>> {
    for r in v.iter() {
        match r {
            CallframeElm::PoolVec(PoolVecSlice { first, last, ptr }) => {
                if *first <= id && id <= *last {
                    return FoundOrLevel::Found(Pointer(unsafe {
                        ptr.0.offset((id - first) as isize)
                    }));
                }
            }
            CallframeElm::Unallocated { first, unalloc } => {
                if *first == id {
                    return FoundOrLevel::Ref {
                        level: unalloc.level,
                        idx: unalloc.idx,
                    };
                }
            }
        }
    }
    panic!("Not found")
}

fn set_callframe_if_ptr<X: Clone>(v: &[CallframeElm<X>], id: WireId, x: &X) -> FoundOrLevel<()> {
    for r in v.iter() {
        match r {
            CallframeElm::PoolVec(PoolVecSlice { first, last, ptr }) => {
                if *first <= id && id <= *last {
                    unsafe {
                        let addr = ptr.0.offset((id - first) as isize) as *mut X;
                        *addr = x.clone();
                    }
                    return FoundOrLevel::Found(());
                }
            }
            CallframeElm::Unallocated { first, unalloc } => {
                if *first == id {
                    return FoundOrLevel::Ref {
                        level: unalloc.level,
                        idx: unalloc.idx,
                    };
                }
            }
        }
    }
    panic!("Not found")
}

#[derive(Debug)]
struct Callframe<X> {
    outputs: Vec<CallframeElm<X>>,
    outputs_cnt: WireId,
    inputs: Vec<CallframeElm<X>>,
    inputs_cnt: WireId,
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
    fn get_either(&self, id: WireId) -> FoundOrLevel<Pointer<X>> {
        if id < self.outputs_cnt {
            //2 println!("SEARCH OUTPUTS {:?} {:?}", self.outputs_cnt, id);
            search_callframe(&self.outputs, id)
        } else if id < self.inputs_cnt {
            //2 println!("SEARCH INPUTS {:?} {:?}", self.inputs_cnt, id);
            search_callframe(&self.inputs, id)
        } else {
            panic!("Not found")
        }
    }

    fn get(&self, id: WireId) -> FoundOrLevel<&X> {
        let r = self.get_either(id);
        match r {
            FoundOrLevel::Found(ptr) => FoundOrLevel::Found(unsafe { ptr.0.as_ref().unwrap() }),
            FoundOrLevel::Ref { level, idx } => FoundOrLevel::Ref { level, idx },
        }
    }

    fn set(&mut self, id: WireId, x: &X) -> FoundOrLevel<()> {
        //println!("OUT CNT: {:?}", self.outputs_cnt);
        //println!("IN CNT: {:?}", self.inputs_cnt);
        if id < self.outputs_cnt {
            set_callframe_if_ptr(&self.outputs, id, x)
        } else if id < self.inputs_cnt {
            set_callframe_if_ptr(&self.inputs, id, x)
        } else {
            panic!("UNREACHABLE");
        }
    }

    fn get_slice(
        &self,
        src_first: WireId,
        _src_last: WireId,
        first: WireId,
        last: WireId,
    ) -> CallframeElm<X> {
        let r = self.get_either(src_first);
        match r {
            FoundOrLevel::Found(ptr) => CallframeElm::PoolVec(PoolVecSlice { first, last, ptr }),
            FoundOrLevel::Ref { level, idx } => CallframeElm::Unallocated {
                first,
                unalloc: Box::new(UnallocatedAddr { level, idx }),
            },
        }
    }

    fn allocate_outputs_ptr(&mut self, first: WireId, last: WireId, ptr: Pointer<X>) {
        self.outputs
            .push(CallframeElm::PoolVec(PoolVecSlice { first, last, ptr }));
        let more = last - first + 1;
        self.outputs_cnt += more;
        self.inputs_cnt += more;
    }

    fn allocate_outputs(&mut self, count: WireId, slice: CallframeElm<X>) {
        self.outputs.push(slice);
        self.outputs_cnt += count;
        self.inputs_cnt += count;
    }

    fn allocate_outputs_unallocated(&mut self, first: WireId, addr: &UnallocatedAddr) {
        self.outputs.push(CallframeElm::Unallocated {
            first,
            unalloc: Box::new(addr.clone()),
        });
        self.outputs_cnt += 1;
        self.inputs_cnt += 1;
    }

    fn allocate_inputs_ptr(&mut self, first: WireId, last: WireId, ptr: Pointer<X>) {
        self.inputs
            .push(CallframeElm::PoolVec(PoolVecSlice { first, last, ptr }));
        self.inputs_cnt += last - first + 1;
    }

    fn allocate_inputs(&mut self, count: WireId, slice: CallframeElm<X>) {
        self.inputs.push(slice);
        self.inputs_cnt += count;
    }

    fn allocate_inputs_unallocated(&mut self, first: WireId, addr: &UnallocatedAddr) {
        self.inputs.push(CallframeElm::Unallocated {
            first,
            unalloc: Box::new(addr.clone()),
        });
        self.inputs_cnt += 1;
    }

    fn clear(&mut self) {
        self.outputs.clear();
        self.outputs_cnt = 0;
        self.inputs.clear();
        self.inputs_cnt = 0;
    }

    fn len(&mut self) -> usize {
        self.outputs.len() + self.inputs.len()
    }
}

// A frame is made of
// 1) a call frame, and
// 2) a memory frame. The memory frame can be either
//    a) a `Pool` of allocated wire (`BTreeMap`) and a map unallocated wires (`HashMap`), or
//    b) a vector for both allocated and unallocated wires.
// The decision whether the memory frame is a pool or a vector is left to the function `push_frame`
// provided the information about the `args_count` and `body_max`
#[derive(Debug)]
struct Frame<X> {
    callframe: Callframe<X>,
    callframe_size: WireId,
    callframe_vector: Vec<AbsoluteAddr<X>>,
    callframe_is_vector: bool,

    memframe_pool: Pool<X>,
    memframe_unallocated: HashMap<WireId, X>,
    memframe_vector: Vec<X>,
    memframe_is_vector: bool,
    counter: usize,
}

impl<X> Frame<X>
where
    X: Clone + Copy + Default + Debug,
{
    fn new() -> Self {
        Frame {
            callframe: Callframe::new(),
            callframe_size: 0,
            callframe_vector: vec![],
            callframe_is_vector: false,
            memframe_pool: Pool::new(),
            memframe_unallocated: HashMap::new(),
            memframe_vector: vec![Default::default(); VEC_SIZE_INIT],
            memframe_is_vector: false,
            counter: 0,
        }
    }

    fn tick(&mut self) {
        self.counter += 1;

        if self.counter < 100 {
            return;
        }

        self.callframe = Callframe::new();
        self.callframe_size = 0;
        self.callframe_vector = vec![Default::default(); VEC_SIZE_INIT];

        self.memframe_pool = Pool::new();
        self.memframe_unallocated = HashMap::new();
        self.memframe_vector = vec![Default::default(); VEC_SIZE_INIT];
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

    pub(crate) fn push_frame(&mut self, args_count: &Option<WireId>, vector_size: &Option<WireId>) {
        let callframe_is_vector = args_count.is_some()
            && <WireId as TryInto<usize>>::try_into(args_count.unwrap()).unwrap()
                < VEC_SIZE_CALLFRAME_THRESHOLD;

        let memframe_is_vector = vector_size.is_some()
            && <WireId as TryInto<usize>>::try_into(vector_size.unwrap()).unwrap()
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

        // Resizing the callframe if necessary
        if callframe_is_vector {
            match args_count {
                None => {}
                Some(s) => {
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
            }
        }

        // Resizing the memframe_vector if necessary
        match vector_size {
            None => {}
            Some(s) => {
                if memframe_is_vector
                    && (*s + 1)
                        > self.stack[self.top]
                            .memframe_vector
                            .len()
                            .try_into()
                            .unwrap()
                {
                    self.stack[self.top]
                        .memframe_vector
                        .resize((s + 1).try_into().unwrap(), Default::default());
                }
            }
        }
    }

    pub(crate) fn pop_frame(&mut self) {
        // TODO: Is there some cleanup to do here to keep to the memory peak under control???
        let frame = self.get_frame_mut();

        if frame.callframe_vector.len() >= (VEC_SIZE_CALLFRAME_THRESHOLD / 5) {
            frame.callframe_vector = vec![Default::default(); VEC_SIZE_INIT];
            frame.callframe_size = 0;
        }

        if frame.callframe.len() >= (VEC_SIZE_CALLFRAME_THRESHOLD / 5) {
            frame.callframe = Callframe::new();
            frame.callframe_size = 0;
        }

        self.top -= 1;
    }

    #[inline]
    fn get_callframe(&self, id: WireId) -> &X {
        let r = self.stack[self.top].callframe.get(id);
        match r {
            FoundOrLevel::Found(ptr) => ptr,
            FoundOrLevel::Ref { level, idx } => {
                self.stack[level].memframe_unallocated.get(&idx).unwrap()
            }
        }
    }

    #[inline]
    fn set_callframe(&mut self, id: WireId, x: &X) {
        let r = self.stack[self.top].callframe.set(id, x);
        match r {
            FoundOrLevel::Found(_) => {}
            FoundOrLevel::Ref { level, idx } => {
                self.stack[level].memframe_unallocated.insert(idx, *x);
            }
        }
    }

    #[inline]
    fn get_callframe_vector(&self, addr: &AbsoluteAddr<X>) -> &X {
        match addr {
            AbsoluteAddr::PoolAllocated(loc) => {
                //debug!("get_elem_previously: pool allocated");
                unsafe {
                    return loc.ptr.0.as_ref().unwrap();
                }
            }
            AbsoluteAddr::Unallocated(loc) => {
                //debug!("get_elem_previously: unallocated");
                self.stack[loc.level]
                    .memframe_unallocated
                    .get(&loc.idx)
                    .unwrap()
            }
            AbsoluteAddr::VectorAllocated(loc) => {
                //debug!("GET VEC");
                unsafe {
                    return loc.ptr.0.as_ref().unwrap();
                }
            }
        }
    }

    #[inline]
    fn set_callframe_vector(&mut self, addr: &AbsoluteAddr<X>, x: &X) {
        match addr {
            AbsoluteAddr::PoolAllocated(loc) => {
                //debug!("set_elem_previously: pool allocated");
                /*let lvl = loc.level;
                let frame = &mut self.stack[lvl];
                frame.memframe_allocated.get_mut().set(loc.first, x);
                */
                unsafe {
                    loc.ptr.0.write(*x);
                }
            }
            AbsoluteAddr::Unallocated(loc) => {
                //debug!("set_elem_previously: unallocated");
                self.stack[loc.level]
                    .memframe_unallocated
                    .insert(loc.idx, *x);
            }
            AbsoluteAddr::VectorAllocated(loc) => {
                //debug!("SET VEC");
                unsafe {
                    loc.ptr.0.write(*x);
                }
            }
        }
    }

    #[inline]
    fn get_frame(&self) -> &Frame<X> {
        &self.stack[self.top]
    }
    #[inline]
    fn get_frame_previous(&self) -> &Frame<X> {
        &self.stack[self.top - 1]
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

        if id < frame.callframe_size {
            if !frame.callframe_is_vector {
                return self.get_callframe(id);
            } else {
                let addr = &frame.callframe_vector[id as usize];
                return self.get_callframe_vector(addr);
            }
        }

        // else wire not in previous frame, so it can be in either
        // 1) vector allocated
        // 2) a) pool allocated,
        //    b) unallocated

        // 1)
        if frame.memframe_is_vector {
            return &frame.memframe_vector[(id - frame.callframe_size) as usize];
        }

        // 2) a)
        if frame.memframe_pool.present(id) {
            return frame.memframe_pool.get(id);
        }

        // 2) b)
        debug!("get: {:?}", frame.memframe_unallocated.get(&id).unwrap());
        return frame.memframe_unallocated.get(&id).unwrap();
    }

    pub(crate) fn set(&mut self, id: WireId, x: &X) {
        //debug!("SET {:?}", self.stack);
        //println!("CALLFRAME SIZE: {:?}", self.stack[self.top].callframe_size);
        let frame = self.get_frame_mut();
        if id < frame.callframe_size {
            if !frame.callframe_is_vector {
                //debug!("DEBUG GET in CALLFRAME {:?}", self.get_callframe(addr));
                self.set_callframe(id, x);
                return;
            } else {
                let addr = &frame.callframe_vector[id as usize].clone();
                self.set_callframe_vector(addr, x);
                return;
            }
        }

        // else wire not in previous frame, so it can be in either
        // 1) vector allocated
        // 2) a) pool allocated,
        //    b) unallocated

        // 1)
        if frame.memframe_is_vector {
            // println!("DEBUG SET in VECTOR {:?}", x,);
            frame.memframe_vector[(id - frame.callframe_size) as usize] = *x;
            return;
        }

        // 2) a)
        if frame.memframe_pool.present(id) {
            //debug!("set: allocated");
            //debug!("mem set: {:?} <- {:?}", id, x);
            frame.memframe_pool.set(id, x);
            return;
        }

        // 2) b)
        debug!("set {:?}", x);
        frame.memframe_unallocated.insert(id, *x);
    }

    // This functions takes the first and last index of the caller,
    // finds the original slice associated with them,
    // and create a new slice added to the last frame.
    // There are four cases for the origin of the slice:
    // 1) in callframe from previous caller
    // 2) in vector memframe
    // 3) in allocated memframe
    // 4) in unallocated memframe
    #[allow(clippy::needless_return)]
    pub(crate) fn allocate_slice(
        &mut self,
        src_first: WireId,
        src_last: WireId,
        start: WireId,
        count: WireId,
        allow_allocation: bool,
    ) {
        assert_eq!(count, src_last - src_first + 1);

        // In any case we are going to increase the size of the Call Frame by count
        self.get_frame_mut().callframe_size += count;

        let previous_callframe_size = self.get_frame_previous().callframe_size;
        let previous_callframe_is_vector = self.get_frame_previous().callframe_is_vector;
        let callframe_is_vector = self.get_frame().callframe_is_vector;

        let frame = self.get_frame_previous_mut();

        // 1) wire from callframe
        if src_first < previous_callframe_size {
            //println!("1: in previous_callframe_size");
            assert!(src_last < previous_callframe_size);
            if callframe_is_vector {
                //println!("callframe is vector");
                let addr = if previous_callframe_is_vector {
                    //println!("previous callframe is vector");
                    frame.callframe_vector[src_first as usize].clone()
                } else {
                    frame
                        .callframe
                        .get_slice(src_first, src_last, start, start + count - 1)
                        .to_absolute_addr()
                };

                let last_frame = self.get_frame_mut();
                for i in 0..count {
                    let idx = (start + i) as usize;
                    last_frame.callframe_vector[idx] = addr.clone();
                    last_frame.callframe_vector[idx].incr(i);
                }
                return;
            } else {
                let slice = if previous_callframe_is_vector {
                    //println!("previous callframe is vector");
                    let new_slice = frame.callframe_vector[src_first as usize].clone();
                    mk_from_absadr(start, start + count - 1, new_slice)
                } else {
                    frame
                        .callframe
                        .get_slice(src_first, src_last, start, start + count - 1)
                };

                let last_frame = self.get_frame_mut();
                if allow_allocation {
                    //println!("output");
                    last_frame.callframe.allocate_outputs(count, slice);
                    return;
                } else {
                    //println!("input");
                    last_frame.callframe.allocate_inputs(count, slice);
                    return;
                }
            }
        }
        // else 2) the slice is in a vector memframe
        if frame.memframe_is_vector {
            //println!("2: previous memframe is vector");
            let ptr =
                Pointer(&mut frame.memframe_vector[(src_first - previous_callframe_size) as usize]);
            if callframe_is_vector {
                //println!("callframe is vector");
                // for the vector slice we need to shift by callframe_size so that the
                // indexing in the vector is correct using a slice_idx
                let new_slice = AbsoluteAddr::VectorAllocated(VectorAddr { ptr });
                let last_frame = self.get_frame_mut();
                for i in 0..count {
                    let idx = (start + i) as usize;
                    last_frame.callframe_vector[idx] = new_slice.clone();
                    last_frame.callframe_vector[idx].incr(i);
                }
                return;
            } else {
                let last_frame = self.get_frame_mut();
                if allow_allocation {
                    //println!("output");
                    last_frame
                        .callframe
                        .allocate_outputs_ptr(start, start + count - 1, ptr);
                    return;
                } else {
                    //println!("input");
                    last_frame
                        .callframe
                        .allocate_inputs_ptr(start, start + count - 1, ptr);
                    return;
                }
            }
        }

        // else slice in either
        // 3) pool allocated, we need to search through
        // 4) unallocated, the last option
        let new_slice;
        if frame.memframe_pool.present(src_first) {
            //println!("3) present in pool");
            if callframe_is_vector {
                //println!("callframe is vector");
                let ptr = frame.memframe_pool.get_ptr(src_first);
                new_slice = AbsoluteAddr::PoolAllocated(PoolAddr { ptr });
                let last_frame = self.get_frame_mut();
                for i in 0..count {
                    let idx = (start + i) as usize;
                    last_frame.callframe_vector[idx] = new_slice.clone();
                    last_frame.callframe_vector[idx].incr(i);
                }
                return;
            } else {
                let ptr = frame.memframe_pool.get_ptr(src_first);
                let last_frame = self.get_frame_mut();
                if allow_allocation {
                    //println!("output");
                    last_frame
                        .callframe
                        .allocate_outputs_ptr(start, start + count - 1, ptr);
                    return;
                } else {
                    //println!("input");
                    last_frame
                        .callframe
                        .allocate_inputs_ptr(start, start + count - 1, ptr);
                    return;
                }
            }
        } else {
            //println!("4) unallocated");
            // if it is in unallocated then we need to allocate it
            let frame = self.get_frame_previous_mut();
            if src_first != src_last {
                //println!("ALLOC NEW");
                if !allow_allocation {
                    panic!(
                        "Not allowed to allocate: maybe passed arguments are not allocated yet, \
                    or passing a range of wires in noncontiguous zone memory"
                    );
                }
                // println!("ALLOCATE_FRAME: EXTRA");
                frame.memframe_pool.insert(src_first, src_last);
                let ptr = frame.memframe_pool.get_ptr(src_first);

                if callframe_is_vector {
                    //println!("callframe is vector");
                    new_slice = AbsoluteAddr::PoolAllocated(PoolAddr { ptr });
                    let last_frame = self.get_frame_mut();
                    for i in 0..count {
                        let idx = (start + i) as usize;
                        last_frame.callframe_vector[idx] = new_slice.clone();
                        last_frame.callframe_vector[idx].incr(i);
                    }
                    return;
                } else {
                    let last_frame = self.get_frame_mut();
                    last_frame
                        .callframe
                        .allocate_outputs_ptr(start, start + count - 1, ptr);
                    return;
                }
            } else {
                //println!("INDIVIDUAL NEW");
                // if it's not an interval then we just leave it unallocated
                // debug!("ALLOCATE_FRAME: UNALLOCATED {:?}", src_first);
                let unallocated_addr = UnallocatedAddr {
                    level: self.top - 1,
                    idx: src_first,
                };
                let last_frame = self.get_frame_mut();
                if callframe_is_vector {
                    //println!("callframe is vector");
                    last_frame.callframe_vector[start as usize] =
                        AbsoluteAddr::Unallocated(Box::new(unallocated_addr));
                    return;
                } else if allow_allocation {
                    last_frame
                        .callframe
                        .allocate_outputs_unallocated(start, &unallocated_addr);
                    return;
                } else {
                    last_frame
                        .callframe
                        .allocate_inputs_unallocated(start, &unallocated_addr);
                    return;
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
                let how_many: WireId = frame.memframe_pool.remove(curr).try_into().unwrap();
                assert!(how_many <= remaining);
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

    fn test_memory1() {
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
    fn test_cache() {
        test_cache1();
        test_cache2();
    }

    #[test]
    fn test_memory() {
        test_memory1();
    }
}
