use std::{
    alloc::Layout, fmt::Debug, marker::PhantomData, mem::MaybeUninit, num::NonZeroUsize,
    ptr::NonNull,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MemoryOwnership {
    Owned,
    MutablyBorrowed,
    ImmutablyBorrowed,
}

#[derive(Clone, Copy)]
pub(crate) enum BorrowKind {
    Immutable,
    Mutable,
}

// this type shouldn't be send or sync
/// An optimized version of `Vec<Option<T>>`
pub(crate) struct Allocation<'a, T> {
    base_ptr: NonNull<MaybeUninit<T>>,
    full_len: usize,
    exposed_len: usize,
    offset: usize,
    ownership: MemoryOwnership,
    phantom: PhantomData<(T, std::cell::Cell<&'a ()>)>,
}
/*impl<T: Debug> Debug for Allocation<'_, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries((0..self.len()).map(|i| self.get(i)))
            .finish()
    }
}*/
impl<T> Debug for Allocation<'_, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Allocation")
            .field("ownership", &self.ownership)
            .field("exposed_len", &self.exposed_len)
            .field("full_len", &self.full_len)
            .field("offset", &self.offset)
            .finish()
    }
}
impl<T> Default for Allocation<'_, T> {
    fn default() -> Self {
        Self {
            base_ptr: NonNull::dangling(),
            full_len: 0,
            exposed_len: 0,
            offset: 0,
            ownership: MemoryOwnership::Owned,
            phantom: PhantomData,
        }
    }
}
impl<'a, T> Allocation<'a, T> {
    fn layout(len: NonZeroUsize) -> (Layout, usize) {
        let base_array = Layout::array::<T>(len.get()).unwrap();
        base_array
            .extend(Layout::array::<u64>(Self::num_bitmap_words(len.get())).unwrap())
            .unwrap()
    }
    fn bitmap_base_ptr(base_ptr: NonNull<MaybeUninit<T>>, len: usize) -> *mut u64 {
        unsafe {
            let end_ptr = base_ptr.as_ptr().add(len) as *mut u8;
            end_ptr.add(end_ptr.align_offset(std::mem::align_of::<u64>())) as *mut u64
        }
    }
    fn num_bitmap_words(len: usize) -> usize {
        // ceil(len/64)
        (len + 64 - 1) / 64
    }
    unsafe fn bitmap_word(&self, word_idx: usize) -> *mut u64 {
        debug_assert!(word_idx < Self::num_bitmap_words(self.full_len));
        unsafe { Self::bitmap_base_ptr(self.base_ptr, self.full_len).add(word_idx) }
    }
    fn get_ptr(&self, idx: usize) -> Option<NonNull<MaybeUninit<T>>> {
        assert!(idx < self.exposed_len);
        let idx = idx + self.offset;
        debug_assert!(idx < self.full_len);
        let bitmap_word = unsafe { self.bitmap_word(idx / 64).read() };
        if ((bitmap_word >> (idx % 64)) & 1) == 0 {
            return None;
        }
        Some(unsafe { NonNull::new_unchecked(self.base_ptr.as_ptr().add(idx)) })
    }
    pub(crate) fn get(&self, idx: usize) -> Option<&T> {
        let ptr = self.get_ptr(idx);
        unsafe { ptr.map(|x| MaybeUninit::assume_init_ref(&*x.as_ptr())) }
    }
    pub(crate) fn get_mut(&mut self, idx: usize) -> Option<&mut T> {
        self.assert_mutable();
        let ptr = self.get_ptr(idx);
        unsafe { ptr.map(|x| MaybeUninit::assume_init_mut(&mut *x.as_ptr())) }
    }
    // If the idx was already in the map, return false.
    pub(crate) fn insert(&mut self, idx: usize, value: T) -> bool {
        self.assert_mutable();
        assert!(idx < self.exposed_len);
        let idx = idx + self.offset;
        debug_assert!(idx < self.full_len);
        let previously_empty = {
            let bitmap_ptr = unsafe { self.bitmap_word(idx / 64) };
            let bitmap_word = unsafe { bitmap_ptr.read() };
            let previously_empty = ((bitmap_word >> (idx % 64)) & 1) == 0;
            unsafe { bitmap_ptr.write(bitmap_word | (1 << (idx % 64))) };
            previously_empty
        };
        let cell = unsafe { self.base_ptr.as_ptr().add(idx) };
        if std::mem::needs_drop::<T>() {
            if previously_empty {
                // Cell was previously empty
                MaybeUninit::write(unsafe { &mut *cell }, value);
            } else {
                // Cell was previously filled
                *unsafe { MaybeUninit::assume_init_mut(&mut *cell) } = value;
            }
        } else {
            MaybeUninit::write(unsafe { &mut *cell }, value);
        }
        previously_empty
    }

    pub(crate) unsafe fn new_borrow(
        parent: &'a Allocation<T>,
        start: usize,
        len: usize,
        borrow_kind: BorrowKind,
    ) -> Self {
        let end = start.checked_add(len).unwrap();
        assert!(end <= parent.len());
        Allocation {
            base_ptr: parent.base_ptr,
            full_len: parent.full_len,
            exposed_len: len,
            offset: start + parent.offset,
            ownership: match borrow_kind {
                BorrowKind::Immutable => MemoryOwnership::ImmutablyBorrowed,
                BorrowKind::Mutable => {
                    parent.assert_mutable();
                    MemoryOwnership::MutablyBorrowed
                }
            },
            phantom: PhantomData,
        }
    }

    pub(crate) fn new_owned(len: usize) -> Self {
        if let Some(len) = NonZeroUsize::new(len) {
            let (layout, _bitmap_offset) = Self::layout(len);
            let base_ptr = unsafe { std::alloc::alloc_zeroed(layout) };
            let base_ptr = if let Some(base_ptr) = NonNull::new(base_ptr) {
                base_ptr.cast()
            } else {
                std::alloc::handle_alloc_error(layout)
            };
            debug_assert_eq!(
                unsafe { (base_ptr.as_ptr() as *mut u8).add(_bitmap_offset) } as *mut u64,
                Self::bitmap_base_ptr(base_ptr, len.get())
            );
            Allocation {
                base_ptr,
                exposed_len: len.get(),
                full_len: len.get(),
                ownership: MemoryOwnership::Owned,
                offset: 0,
                phantom: PhantomData,
            }
        } else {
            Self::default()
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.exposed_len
    }
    fn assert_mutable_fail() {
        panic!("Attempting to mutate an immutably borrowed value.")
    }
    pub(crate) fn is_mutable(&self) -> bool {
        self.ownership != MemoryOwnership::ImmutablyBorrowed
    }
    fn assert_mutable(&self) {
        if !self.is_mutable() {
            Self::assert_mutable_fail()
        }
    }
}
impl<T> Drop for Allocation<'_, T> {
    fn drop(&mut self) {
        if self.ownership != MemoryOwnership::Owned {
            return;
        }
        debug_assert_eq!(self.full_len, self.exposed_len);
        if let Some(len) = NonZeroUsize::new(self.full_len) {
            if std::mem::needs_drop::<T>() {
                let mut ptr = self.base_ptr.as_ptr();
                let mut bitmap_ptr = Self::bitmap_base_ptr(self.base_ptr, len.get());
                let mut bitmap_word = unsafe { *bitmap_ptr };
                let mut i = 0;
                while i < self.full_len {
                    if (bitmap_word & 1) != 0 {
                        unsafe {
                            MaybeUninit::assume_init_drop(&mut *ptr);
                        }
                    }
                    bitmap_word >>= 1;
                    i += 1;
                    unsafe {
                        ptr = ptr.add(1);
                    }
                    if i % 64 == 0 && i < self.full_len {
                        unsafe {
                            bitmap_ptr = bitmap_ptr.add(1);
                            bitmap_word = *bitmap_ptr;
                        }
                    }
                }
            }
            unsafe {
                std::alloc::dealloc(self.base_ptr.cast().as_ptr(), Self::layout(len).0);
            }
        }
    }
}

#[cfg(test)]
mod tests;
