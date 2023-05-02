#![allow(unused)] // TODO: re-enable the allocation system

use std::{
    alloc::Layout,
    any::TypeId,
    marker::PhantomData,
    mem::ManuallyDrop,
    num::NonZeroUsize,
    ops::{Deref, DerefMut},
    ptr::NonNull,
    sync::{
        atomic::{AtomicPtr, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use bytemuck::{TransparentWrapper, Zeroable};
use crossbeam_queue::ArrayQueue;

use rustc_hash::FxHashMap;

use crate::event_log;

#[cfg(feature = "dhat")]
#[global_allocator]
static ALLOCATOR: dhat::Alloc = dhat::Alloc;
#[cfg(feature = "jemalloc")]
#[global_allocator]
static ALLOCATOR: jemallocator::Jemalloc = jemallocator::Jemalloc;
#[cfg(feature = "snmalloc")]
#[global_allocator]
static ALLOCATOR: snmalloc_rs::SnMalloc = snmalloc_rs::SnMalloc;
#[cfg(feature = "mimalloc")]
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;
#[cfg(feature = "rpmalloc")]
#[global_allocator]
static ALLOCATOR: rpmalloc::RpMalloc = rpmalloc::RpMalloc;

pub const ALIGNMENT: usize = 32;

#[repr(C, align(32))]
struct AlignedValue(u8);

// TODO: make these configurable
const IF_SMALLER_THAN_SERVICE_WITH_MALLOC: usize = 1024 * 1024;
const COALESCE_SIZE_CLASSES_WITH_DIVSOR: usize = 10;
const LAST_ALLOCATION_TIME_LIMIT: Duration = Duration::from_secs(2);
const ALLOCATION_POOL_CAPACITY: usize = 512;

enum AllocationOrigin {
    GlobalAlloc,
    Mmap,
}

struct Pool {
    allocate_size: usize,
    contents: crossbeam_queue::ArrayQueue<OwnedAlignedInner>,
}
impl Pool {
    fn new(sz: usize) -> Self {
        Pool {
            allocate_size: sz,
            contents: ArrayQueue::new(ALLOCATION_POOL_CAPACITY),
        }
    }
    fn try_take(&self) -> Option<OwnedAlignedInner> {
        let out = self.contents.pop();
        event_log::TriedToTakeFromMemoryPool {
            size: self.allocate_size as u64,
            success: out.is_some(),
        }
        .submit();
        out
    }
    fn put(&self, buf: OwnedAlignedInner) {
        assert_eq!(buf.capacity_bytes, self.allocate_size);
        let result = self.contents.push(buf);
        event_log::TriedToAddBufferToPool {
            size: self.allocate_size as u64,
            success: result.is_ok(),
        }
        .submit();
    }
}

struct GlobalPoolState {
    start_time: Instant,
    allocation_classes: FxHashMap<usize, &'static Pool>,
}

static GLOBAL_POOL: AtomicPtr<GlobalPoolState> = AtomicPtr::new(std::ptr::null_mut());
fn get_global_pool() -> Option<&'static GlobalPoolState> {
    return None;
    let ptr = GLOBAL_POOL.load(Ordering::Acquire);
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { &*ptr })
    }
}
fn set_global_pool(x: Box<GlobalPoolState>) {
    if GLOBAL_POOL
        .compare_exchange(
            std::ptr::null_mut(),
            Box::leak(x) as *mut GlobalPoolState,
            Ordering::Release,
            Ordering::Relaxed,
        )
        .is_err()
    {
        panic!("Global pool state already set!");
    }
}

// Panics if called more than once
pub fn init_alloc_pool(sizes: &mut [usize]) {
    let start_time = Instant::now();
    sizes.sort_unstable();
    eprintln!("Input allocation classes: {sizes:?}");
    let mut allocation_classes = FxHashMap::<usize, &'static Pool>::default();
    for (sz, next_largest_class) in sizes
        .iter()
        .rev()
        .copied()
        .zip(std::iter::once(None).chain(sizes.iter().rev().copied().map(Some)))
    {
        if let Some(prev) = next_largest_class {
            debug_assert!(prev >= sz);
        }
        if next_largest_class == Some(sz) {
            continue;
        }
        /*if let Some(AllocationOrigin::GlobalAlloc) =
            NonZeroUsize::new(sz).map(OwnedAlignedInner::allocation_origin)
        {
            continue;
        }*/
        if sz < 1024 * 1024 {
            continue;
        }
        if let Some(nlc) =
            next_largest_class.filter(|nlc| *nlc >= (sz / COALESCE_SIZE_CLASSES_WITH_DIVSOR) + sz)
        {
            eprintln!("Coalescing size class {sz} into {nlc}");
            let cls = allocation_classes[&nlc];
            allocation_classes.insert(sz, cls);
        } else {
            eprintln!("Allocing size class for {sz}");
            allocation_classes.insert(sz, Box::leak(Box::new(Pool::new(sz))));
        }
    }
    set_global_pool(Box::new(GlobalPoolState {
        allocation_classes,
        start_time,
    }));
}

struct OwnedAlignedInner {
    capacity_bytes: usize,
    contents: NonNull<u8>,
}
impl OwnedAlignedInner {
    fn allocation_origin(sz: NonZeroUsize) -> AllocationOrigin {
        /*if usize::from(sz) < IF_SMALLER_THAN_SERVICE_WITH_MALLOC {
            AllocationOrigin::GlobalAlloc
        } else {
            AllocationOrigin::Mmap
        }*/
        AllocationOrigin::GlobalAlloc
    }
    fn alloc(capacity: usize) -> Self {
        if let Some(capacity) = NonZeroUsize::new(capacity) {
            let span = event_log::AllocatingFreshBackingBuffer {
                size: usize::from(capacity) as u64,
            }
            .start();
            let out = match Self::allocation_origin(capacity) {
                AllocationOrigin::GlobalAlloc => {
                    let layout = Layout::from_size_align(capacity.into(), ALIGNMENT).unwrap();
                    let contents = unsafe {
                        // SAFETY: capacity is not zero
                        std::alloc::alloc(layout)
                    };
                    if let Some(contents) = NonNull::new(contents) {
                        OwnedAlignedInner {
                            capacity_bytes: capacity.into(),
                            contents,
                        }
                    } else {
                        std::alloc::handle_alloc_error(layout)
                    }
                }
                AllocationOrigin::Mmap => {
                    #[cfg(target_os = "linux")]
                    const MAP_POPULATE: libc::c_int = libc::MAP_POPULATE;
                    #[cfg(not(target_os = "linux"))]
                    const MAP_POPULATE: libc::c_int = 0;
                    let ptr = unsafe {
                        libc::mmap(
                            std::ptr::null_mut(),
                            usize::from(capacity),
                            libc::PROT_READ | libc::PROT_WRITE,
                            libc::MAP_PRIVATE | libc::MAP_ANON | MAP_POPULATE,
                            -1,
                            0,
                        )
                    };
                    if ptr == libc::MAP_FAILED {
                        panic!(
                            "failed to mmap memory for {capacity} due to {}",
                            std::io::Error::last_os_error()
                        );
                    }
                    let ptr = NonNull::new(ptr).unwrap().cast::<u8>();
                    OwnedAlignedInner {
                        contents: ptr,
                        capacity_bytes: usize::from(capacity),
                    }
                }
            };
            span.finish();
            out
        } else {
            debug_assert_eq!(capacity, 0);
            OwnedAlignedInner {
                capacity_bytes: 0,
                contents: NonNull::<AlignedValue>::dangling().cast(),
            }
        }
    }
}
impl Drop for OwnedAlignedInner {
    fn drop(&mut self) {
        if let Some(capacity) = NonZeroUsize::new(self.capacity_bytes) {
            event_log::FreeingBackingBuffer {
                size: usize::from(capacity) as u64,
            }
            .submit();
            match Self::allocation_origin(capacity) {
                AllocationOrigin::GlobalAlloc => unsafe {
                    std::alloc::dealloc(
                        self.contents.as_ptr(),
                        Layout::from_size_align(self.capacity_bytes, ALIGNMENT).unwrap(),
                    )
                },
                AllocationOrigin::Mmap => unsafe {
                    // TODO: should we do error checking?
                    // TODO: can we use madvise instead?
                    libc::munmap(self.contents.as_ptr() as *mut _, self.capacity_bytes);
                },
            }
        } else {
            // Capacity is 0, we don't need to deallocate anything
        }
    }
}

struct PooledOwnedAlignedInner(ManuallyDrop<OwnedAlignedInner>);
impl Deref for PooledOwnedAlignedInner {
    type Target = ManuallyDrop<OwnedAlignedInner>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl DerefMut for PooledOwnedAlignedInner {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl PooledOwnedAlignedInner {
    fn new(x: OwnedAlignedInner) -> Self {
        Self(ManuallyDrop::new(x))
    }
}
impl Drop for PooledOwnedAlignedInner {
    fn drop(&mut self) {
        // Even though pools might have been coalesced, the capacity of the pool we have is the
        // pool that we should try to put this buffer back into. That is, self.inner.capacity_bytes
        // does not denote the size of the allocation request, but rather the actual size of bytes
        // allocated.
        if let Some(pool) = get_global_pool()
            .and_then(|gp| gp.allocation_classes.get(&self.0.capacity_bytes))
            // If the pool's allocate_size doesn't match self.inner.capacity_bytes, then we will
            // just get rid of our allocation. This can happen if a buffer was allocated before the
            // pools were initialized, and so a coalesced allocation size wouldn't have been
            // increased to the larger size when the buffer was allocated.
            .filter(|pool| pool.allocate_size == self.0.capacity_bytes)
        {
            pool.put(unsafe { ManuallyDrop::take(&mut self.0) });
        } else {
            unsafe { ManuallyDrop::drop(&mut self.0) }
        }
    }
}

pub struct OwnedAligned<T: Sync + Send + Copy> {
    len: usize,
    inner: PooledOwnedAlignedInner,
    phantom: PhantomData<T>,
}

unsafe impl<T: Send + Sync + Copy> Send for OwnedAligned<T> {}
unsafe impl<T: Send + Sync + Copy> Sync for OwnedAligned<T> {}

impl<T: Sync + Send + Copy> OwnedAligned<T> {
    pub fn zeroed(n: usize) -> Self
    where
        T: Zeroable,
    {
        let mut out = Self::with_capacity(n);
        unsafe {
            let capacity_bytes = out.inner.capacity_bytes;
            std::ptr::write_bytes(
                out.inner.contents.as_ptr(),
                0,
                usize::try_from(capacity_bytes).unwrap(),
            );
            out.set_len(n);
        }
        out
    }
    // capacity might exceed what's been requested.
    pub fn with_capacity(capacity: usize) -> Self {
        assert_eq!(ALIGNMENT % std::mem::align_of::<T>(), 0);
        let num_bytes = capacity.checked_mul(std::mem::size_of::<T>()).unwrap();
        let inner = if let Some(pool) =
            get_global_pool().and_then(|gp| gp.allocation_classes.get(&num_bytes))
        {
            // We allocate a buffer of size pool.allocate_size, since pools might be coalesced.
            pool.try_take()
                .map(PooledOwnedAlignedInner::new)
                .unwrap_or_else(|| {
                    PooledOwnedAlignedInner::new(OwnedAlignedInner::alloc(pool.allocate_size))
                })
        } else {
            if num_bytes > 0 {
                event_log::NoMemoryPoolFor {
                    size: num_bytes as u64,
                }
                .submit();
            }
            PooledOwnedAlignedInner::new(OwnedAlignedInner::alloc(num_bytes))
        };
        debug_assert!(inner.capacity_bytes >= num_bytes);
        Self {
            len: 0,
            inner,
            phantom: PhantomData,
        }
    }
    // This isn't pub because the exact capacity is an internal implementation detail.
    fn capacity(&self) -> usize {
        // This division will take the floor of the division.
        self.inner.capacity_bytes / std::mem::size_of::<T>()
    }
    pub unsafe fn set_len(&mut self, len: usize) {
        assert!(len <= self.capacity());
        self.len = len;
    }
    pub fn push(&mut self, x: T) {
        assert!(self.len < self.capacity());
        unsafe {
            (self.inner.contents.as_ptr() as *mut T)
                .add(self.len)
                .write(x);
            self.set_len(self.len + 1);
        }
    }
    #[allow(unused)]
    pub fn truncate(&mut self, len: usize) {
        assert!(len <= self.len);
        unsafe {
            self.set_len(len);
        }
    }
    pub fn as_slice(&self) -> &[T] {
        self
    }
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        self
    }
    pub fn erased(self) -> ErasedOwnedAligned
    where
        T: 'static,
    {
        ErasedOwnedAligned {
            len: self.len,
            inner: self.inner,
            ty: TypeId::of::<T>(),
        }
    }
}
impl<T: Sync + Send + Copy> Default for OwnedAligned<T> {
    fn default() -> Self {
        Self::with_capacity(0)
    }
}
impl<T: Sync + Send + Copy> Deref for OwnedAligned<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        debug_assert!(self.len <= self.capacity());
        unsafe { std::slice::from_raw_parts(self.inner.contents.as_ptr() as *const T, self.len) }
    }
}
impl<T: Sync + Send + Copy> DerefMut for OwnedAligned<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        debug_assert!(self.len <= self.capacity());
        unsafe { std::slice::from_raw_parts_mut(self.inner.contents.as_ptr() as *mut T, self.len) }
    }
}
impl<T: Send + Sync + Copy> AsRef<AlignedSlice<T>> for OwnedAligned<T> {
    fn as_ref(&self) -> &AlignedSlice<T> {
        TransparentWrapper::wrap_ref(self.as_slice())
    }
}
impl<T: Send + Sync + Copy> AsMut<AlignedSlice<T>> for OwnedAligned<T> {
    fn as_mut(&mut self) -> &mut AlignedSlice<T> {
        TransparentWrapper::wrap_mut(self.as_mut_slice())
    }
}

pub struct ErasedOwnedAligned {
    len: usize,
    inner: PooledOwnedAlignedInner,
    ty: TypeId,
}
unsafe impl Send for ErasedOwnedAligned {}
unsafe impl Sync for ErasedOwnedAligned {}
impl ErasedOwnedAligned {
    pub fn get<T: 'static + Sync + Send + Copy>(&self) -> Option<&AlignedSlice<T>> {
        if TypeId::of::<T>() == self.ty {
            Some(TransparentWrapper::wrap_ref(unsafe {
                std::slice::from_raw_parts(self.inner.contents.as_ptr() as *const T, self.len)
            }))
        } else {
            None
        }
    }
}

#[repr(transparent)]
pub struct AlignedSlice<T>([T]);
impl<T> Deref for AlignedSlice<T> {
    type Target = [T];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> Default for &'_ AlignedSlice<T> {
    fn default() -> Self {
        TransparentWrapper::wrap_ref(<&[T]>::default())
    }
}

// TODO: remove this impl
// Until https://github.com/Lokathor/bytemuck/pull/146 gets released, we can't derive
// TransparentWrapper.
unsafe impl<T> TransparentWrapper<[T]> for AlignedSlice<T> {}
impl<T> DerefMut for AlignedSlice<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

pub type OwnedAlignedBytes = OwnedAligned<u8>;
pub type AlignedBytes<'a> = &'a AlignedSlice<u8>;
pub type AlignedBytesMut<'a> = &'a mut AlignedSlice<u8>;
pub type TaskDataBuffer<T> = OwnedAligned<T>;
pub type BytesFromDisk = Arc<OwnedAlignedBytes>;
