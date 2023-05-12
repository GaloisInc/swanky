use std::{collections::BTreeMap, sync::atomic::AtomicU64};

use allocation::Allocation;
use eyre::ContextCompat;
use vectoreyes::{SimdBase, SimdBase8, SimdSaturatingArithmetic, U16x16, U64x4, U8x32};

pub type WireId = u64;
type AllocationStartId = u64;

mod allocation;

pub static NUM_LOOKUPS: AtomicU64 = AtomicU64::new(0);
pub static LOOKUP_MISSES: AtomicU64 = AtomicU64::new(0);

enum Cell<'parent, T> {
    Uncached { allocation: Allocation<'parent, T> },
    InCache { len: usize },
}

impl<'parent, T> std::fmt::Debug for Cell<'parent, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Cell::Uncached { allocation } => {
                f.debug_tuple("Cell::Uncached").field(allocation).finish()
            }
            Cell::InCache { len } => f.debug_struct("Cell::InCache").field("len", len).finish(),
        }
    }
}

impl<T> Cell<'_, T> {
    fn len(&self) -> usize {
        match self {
            Cell::Uncached { allocation: a } => a.len(),
            Cell::InCache { len } => *len,
        }
    }
}

struct WirePosition<'a, 'parent, T> {
    allocation: &'a mut Allocation<'parent, T>,
    pos_in_allocation: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireNotFound {
    NotAllocated,
    UnsetValueWithinAllocation,
}
impl std::fmt::Display for WireNotFound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl std::error::Error for WireNotFound {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertResult<T> {
    NotAllocated(T),
    PreviouslyUnset,
    PreviouslySet,
    AllocationNotMutable,
}

#[derive(Debug, Clone, Copy)]
pub struct DestinationRange {
    pub src_start: WireId,
    pub src_inclusive_end: WireId,
    pub dst_start: WireId,
}
impl DestinationRange {
    pub fn is_empty(&self) -> bool {
        self.src_start > self.src_inclusive_end
    }
}

const EMPTY_AGE_AND_LAST_USED: u64 = u16::MAX as u64;

// Neither Send nor Sync
#[derive(Debug)]
pub struct WireMap<'parent, T> {
    // Some allocations might live exclusively in the cache.
    storage: BTreeMap<AllocationStartId, Cell<'parent, T>>,
    // TODO: benchmark whether the use of U64x4 causes AVX2 warm-up delays. We might have to switch
    // to using 128-bit vectors. We should definitely avoid "heavy" AVX2 instructions.
    cache_starts: U64x4,
    // The least significant 16 bits are the age of the cache entry. The rest is the lenght of the
    // allocation. Because most x86_64 machines only have a 48-bit address space (I _think_ some
    // modern ones may have a 56-bit address space), and we have to allocate memory for the length
    // requested, we know (and assert below) that the length of the allocation must be under 2^48,
    // allowing us to use the lowest 16 bits for the age.
    cache_lens_and_last_useds: U64x4,
    cached_allocations: [Allocation<'parent, T>; 4],
}
impl<T> Default for WireMap<'static, T> {
    fn default() -> Self {
        Self::new()
    }
}
impl<T> WireMap<'static, T> {
    pub fn new() -> Self {
        WireMap {
            storage: Default::default(),
            cache_starts: Default::default(),
            cache_lens_and_last_useds: U64x4::broadcast(EMPTY_AGE_AND_LAST_USED),
            cached_allocations: Default::default(),
        }
    }
}
impl<'parent, T> WireMap<'parent, T> {
    // The wire shouldn't live in the cache.
    #[inline(never)]
    fn borrow_allocation_slow<'a>(
        &'a mut self,
        wire: WireId,
    ) -> Option<WirePosition<'a, 'parent, T>> {
        LOOKUP_MISSES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if let Some((&start, allocation)) = self.storage.range_mut(..=wire).next_back() {
            debug_assert!(start <= wire);
            let allocation_len = allocation.len();
            if wire - start >= allocation_len as u64 {
                return None;
            }
            let allocation = match std::mem::replace(
                allocation,
                Cell::InCache {
                    len: allocation_len,
                },
            ) {
                Cell::Uncached { allocation } => allocation,
                Cell::InCache { len: _ } => panic!("Allocation is already in the cache"),
            };
            let allocation = self.insert_into_cache(start, allocation);
            let pos_in_allocation = (wire - start) as usize;
            Some(WirePosition {
                allocation,
                pos_in_allocation,
            })
        } else {
            None
        }
    }
    /// We assume that the allocation doesn't conflict with any other allocation.
    fn insert_into_cache(
        &mut self,
        start: WireId,
        alloc: Allocation<'parent, T>,
    ) -> &mut Allocation<'parent, T> {
        let mut cache_starts = self.cache_starts.as_array();
        let mut cache_lens_and_last_useds = self.cache_lens_and_last_useds.as_array();
        let (victim_idx, _victim_age) = cache_lens_and_last_useds
            .iter()
            .copied()
            .map(|len_and_last_used| {
                // We intentionally do a truncating cast here
                len_and_last_used as u16
            })
            .enumerate()
            .max_by_key(|(_i, age)| *age)
            .unwrap();
        // Assert that no valid cache entry shares this start (a valid cache entry has a non-zero
        // length).
        debug_assert!(!cache_starts
            .iter()
            .zip(cache_lens_and_last_useds.iter())
            .any(|(s, l)| *s == start && ((l >> 16) > 0)));
        let evicted_start = cache_starts[victim_idx];
        let alloc_len = alloc.len();
        let evicted_allocation = std::mem::replace(&mut self.cached_allocations[victim_idx], alloc);
        cache_starts[victim_idx] = start;
        // Set age to zero.
        cache_lens_and_last_useds[victim_idx] = (alloc_len as u64) << 16;
        self.cache_starts = cache_starts.into();
        self.cache_lens_and_last_useds = cache_lens_and_last_useds.into();
        if evicted_allocation.len() > 0 {
            self.storage.insert(
                evicted_start,
                Cell::Uncached {
                    allocation: evicted_allocation,
                },
            );
        }
        &mut self.cached_allocations[victim_idx]
    }
    /// Return the index in the cache where `wire` lives, if it lives in the cache.
    /// Also return the `hit` mask which is `u64::MAX` for the cache cell where the wire
    /// lives, and zero elsewhere.
    #[inline(always)] // due to SIMD
    fn check_cache_for_wire(&self, wire: WireId) -> Option<(usize, U64x4)> {
        let wire_broadcast = U64x4::broadcast(wire);
        // u64::MAX is a valid wire ID, so we don't want to add anything to wire or start.
        // We want to subtract from them.
        let hit = (self
            .cache_lens_and_last_useds
            .shift_right::<16>()
            .cmp_gt(wire_broadcast - self.cache_starts))
        .and_not(self.cache_starts.cmp_gt(wire_broadcast));
        if hit.is_zero() {
            None
        } else {
            let idx = (U8x32::from(hit).most_significant_bits().trailing_zeros() / 8) as usize;
            #[cfg(debug_assertions)]
            {
                let num_high = hit.as_array().iter().filter(|&&x| x != 0).count();
                assert_eq!(num_high, 1);
                let (hi_idx, _) = hit
                    .as_array()
                    .iter()
                    .copied()
                    .enumerate()
                    .find(|(_, x)| *x != 0)
                    .unwrap();
                assert_eq!(hi_idx, idx);
                let start = self.cache_starts.as_array()[hi_idx];
                assert!(wire >= start);
                assert!(
                    wire - start < self.cached_allocations[hi_idx].len() as u64,
                    "wire={wire}, start={start}, allocation={:?}, cache_lens_and_last_used=0x{:X}",
                    self.cached_allocations[hi_idx],
                    self.cache_lens_and_last_useds.as_array()[hi_idx],
                );
                debug_assert!(idx < 4);
            }
            Some((idx, hit))
        }
    }
    fn borrow_allocation<'a>(&'a mut self, wire: WireId) -> Option<WirePosition<'a, 'parent, T>> {
        NUM_LOOKUPS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let (idx, hit) = if let Some(pair) = self.check_cache_for_wire(wire) {
            pair
        } else {
            return self.borrow_allocation_slow(wire);
        };
        let new_cache_lens_and_last_useds = U64x4::from(
            U16x16::from(self.cache_lens_and_last_useds)
                .saturating_add(U16x16::from(U64x4::broadcast(1).and_not(hit))),
        );
        self.cache_lens_and_last_useds = new_cache_lens_and_last_useds;
        Some(WirePosition {
            allocation: &mut self.cached_allocations[idx],
            pos_in_allocation: usize::try_from(wire - self.cache_starts.as_array()[idx]).unwrap(),
        })
    }
    fn alloc_from_allocation(
        &mut self,
        start: WireId,
        allocation: Allocation<'parent, T>,
    ) -> eyre::Result<()> {
        let len = allocation.len();
        assert_ne!(len, 0);
        assert!(len < (1 << 48));
        let inclusive_end = start.checked_add(len as u64 - 1).unwrap();
        // TODO: do we want to optimize checking the cache here with SIMD?
        // We check every cache cell along with one entry from storage. We use a range query to
        // the entry from storage that we want to query.
        for (existing_start, existing_len) in self
            .storage
            .range(..=inclusive_end)
            .next_back()
            .map(|(start, cell)| (*start, cell.len()))
            .into_iter()
            .chain(
                self.cache_starts
                    .as_array()
                    .into_iter()
                    .zip(self.cached_allocations.iter())
                    .map(|(start, alloc)| (start, alloc.len())),
            )
        {
            if existing_len == 0 || existing_start > inclusive_end {
                continue;
            }
            let existing_end_inclusive = existing_start + (existing_len as u64 - 1);
            eyre::ensure!(
                existing_end_inclusive < start,
                "destination allocation {existing_start}..={existing_end_inclusive} overlaps with {start}..={inclusive_end}"
            );
        }
        self.insert_into_cache(start, allocation);
        Ok(())
    }
    pub fn alloc(&mut self, start: WireId, inclusive_end: WireId) -> eyre::Result<()> {
        if let Some(len) = inclusive_end.checked_sub(start) {
            let len = len + 1;
            self.alloc_from_allocation(start, Allocation::new_owned(len as usize))
        } else {
            Ok(())
        }
    }
    pub fn free(&mut self, start: WireId, inclusive_end: WireId) -> eyre::Result<()> {
        let mut curr_start = start;
        while curr_start <= inclusive_end {
            let mut alloc_len = 0;

            // We first check the cache, since some allocations might live exclusively in the cache.
            let was_in_cache = if let Some((idx, _hit)) = self.check_cache_for_wire(curr_start) {
                let allocation = &mut self.cached_allocations[idx];
                alloc_len = allocation.len();
                debug_assert!(alloc_len > 0);

                let found_start = self.cache_starts.as_array()[idx];
                eyre::ensure!(
                    found_start == curr_start,
                    "Allocation starting with {curr_start} not found. Found an allocation starting with {found_start}."
                );

                let found_end = found_start + (alloc_len as u64 - 1);
                eyre::ensure!(
                    found_end <= inclusive_end,
                    "Allocation {found_start}..={found_end} extends past {inclusive_end}."
                );

                let mut cache_lens_and_last_useds = self.cache_lens_and_last_useds.as_array();
                cache_lens_and_last_useds[idx] = EMPTY_AGE_AND_LAST_USED;
                self.cache_lens_and_last_useds = cache_lens_and_last_useds.into();
                std::mem::take(allocation);

                true
            } else {
                false
            };
            match self.storage.remove(&curr_start) {
                Some(cell) => {
                    alloc_len = cell.len();
                    let found_end = curr_start + (alloc_len as u64 - 1);

                    // If the allocation extends past inclusive_end, then
                    // re-insert the cell that we removed and return an error.
                    if found_end > inclusive_end {
                        self.storage.insert(curr_start, cell);
                        eyre::bail!(
                            "Cannot free {curr_start}..={found_end}, which extends beyond {inclusive_end}."
                        );
                    }
                }

                // It's okay if the allocation wasn't found in the BTreeMap, but only if it _was_
                // found in the cache.
                None => eyre::ensure!(
                    was_in_cache,
                    "Attemping to free non-existent allocation (no allocation starts at {curr_start})",
                ),
            }

            curr_start += alloc_len as u64;
        }

        eyre::ensure!(
            curr_start == inclusive_end + 1,
            "The range {start}...{inclusive_end} does not fully cover all allocations it overlaps."
        );

        Ok(())
    }
    // panics if allocation isn't mutable
    pub fn get_mut(&mut self, wire: WireId) -> Result<&mut T, WireNotFound> {
        if let Some(WirePosition {
            allocation,
            pos_in_allocation,
        }) = self.borrow_allocation(wire)
        {
            if let Some(out) = allocation.get_mut(pos_in_allocation) {
                Ok(out)
            } else {
                Err(WireNotFound::UnsetValueWithinAllocation)
            }
        } else {
            Err(WireNotFound::NotAllocated)
        }
    }
    pub fn get(&mut self, wire: WireId) -> Result<&T, WireNotFound> {
        if let Some(WirePosition {
            allocation,
            pos_in_allocation,
        }) = self.borrow_allocation(wire)
        {
            if let Some(out) = allocation.get(pos_in_allocation) {
                Ok(out)
            } else {
                Err(WireNotFound::UnsetValueWithinAllocation)
            }
        } else {
            Err(WireNotFound::NotAllocated)
        }
    }
    // Return true if the insert is new
    // None means that the wire wasn't allocated.
    pub fn insert(&mut self, wire: WireId, value: T) -> InsertResult<T> {
        if let Some(pos) = self.borrow_allocation(wire) {
            if !pos.allocation.is_mutable() {
                return InsertResult::AllocationNotMutable;
            }
            if pos.allocation.insert(pos.pos_in_allocation, value) {
                InsertResult::PreviouslyUnset
            } else {
                InsertResult::PreviouslySet
            }
        } else {
            InsertResult::NotAllocated(value)
        }
    }

    fn immutably_borrow_allocation<'a>(
        &'a self,
        start: WireId,
        inclusive_end: WireId,
    ) -> eyre::Result<(usize, &'a Allocation<'parent, T>)> {
        if inclusive_end < start {
            None
        } else {
            let candidate_allocation = self
                .check_cache_for_wire(start)
                .map(|(idx, _hit)| {
                    (
                        self.cache_starts.as_array()[idx],
                        &self.cached_allocations[idx],
                    )
                })
                .or_else(|| match self.storage.range(..=start).next_back() {
                    Some((&start, Cell::Uncached { allocation })) => Some((start, allocation)),
                    Some((_, Cell::InCache { len: _ })) => {
                        panic!("The allocation wasn't in the cache")
                    }
                    None => None,
                });
            if let Some((alloc_start, allocation)) = candidate_allocation {
                debug_assert!(alloc_start <= start);
                if start - alloc_start >= allocation.len() as u64 {
                    None
                } else {
                    let offset = start - alloc_start;
                    let allocation_inclusive_end = alloc_start + ((allocation.len() as u64) - 1);
                    if inclusive_end <= allocation_inclusive_end {
                        let offset = usize::try_from(offset).unwrap();
                        Some((offset, allocation))
                    } else {
                        None
                    }
                }
            } else {
                None
            }
        }
        .with_context(|| {
            format!("{start}..={inclusive_end} could not be found (within a single allocation)")
        })
    }
    fn ensure_no_conflict(
        mutable_range_map: &BTreeMap<WireId, WireId>,
        start: WireId,
        inclusive_end: WireId,
    ) -> eyre::Result<()> {
        if let Some((&entry_start, &entry_end)) =
            mutable_range_map.range(..=inclusive_end).next_back()
        {
            debug_assert!(entry_start <= entry_end);
            eyre::ensure!(
                entry_end < start,
                "Range {start}..={inclusive_end} conflicts with mutable range {entry_start}..={entry_end}"
            );
        }
        Ok(())
    }
    pub fn alloc_range_if_unallocated(
        &mut self,
        start: WireId,
        inclusive_end: WireId,
    ) -> eyre::Result<()> {
        if let Some(len) = inclusive_end.checked_sub(start) {
            let len = usize::try_from(len + 1).unwrap();
            // In order for this function to be successful, the given range must be entirely
            // unallocated OR allocated within a single allocation.
            if let Some(wp) = self.borrow_allocation(start) {
                // We overlap with an existing allocation. We fail if this allocation doesn't entirely
                // contain our range.
                let region_start = start - (wp.pos_in_allocation as u64);
                eyre::ensure!(
                    wp.allocation.len() - wp.pos_in_allocation >= len,
                    "The range {}..={} has been allocated, and it doesn't fully contain {start}..={inclusive_end}",
                    region_start,
                    region_start + (wp.allocation.len() as u64 - 1)
                );
            } else {
                // If the start hasn't been allocated, try to do a full allocation. If this overlaps an
                // existing allocation, then the alloc will fail.
                self.alloc(start, inclusive_end)?;
            }
        }
        Ok(())
    }
    #[inline(never)]
    pub fn borrow_child(
        &mut self,
        mutable_ranges: impl IntoIterator<Item = DestinationRange>,
        immutable_ranges: impl IntoIterator<Item = DestinationRange>,
    ) -> eyre::Result<WireMap<'_, T>> {
        let mut out = WireMap {
            storage: Default::default(),
            cache_starts: Default::default(),
            cache_lens_and_last_useds: U64x4::broadcast(EMPTY_AGE_AND_LAST_USED),
            cached_allocations: Default::default(),
        };
        let mut mutable_range_map = BTreeMap::new();
        for range in mutable_ranges
            .into_iter()
            .filter(|range: &DestinationRange| !range.is_empty())
        {
            Self::ensure_no_conflict(&mutable_range_map, range.src_start, range.src_inclusive_end)?;
            mutable_range_map.insert(range.src_start, range.src_inclusive_end);
            let (offset, own_alloc) =
                self.immutably_borrow_allocation(range.src_start, range.src_inclusive_end)?;
            eyre::ensure!(
                own_alloc.is_mutable(),
                "Source range {}..={} isn't mutable",
                range.src_start,
                range.src_inclusive_end,
            );
            let len = usize::try_from(range.src_inclusive_end - range.src_start).unwrap() + 1;
            out.alloc_from_allocation(range.dst_start, unsafe {
                let alloc =
                    Allocation::new_borrow(own_alloc, offset, len, allocation::BorrowKind::Mutable);
                debug_assert_eq!(alloc.len(), len);
                alloc
            })?;
        }
        for range in immutable_ranges
            .into_iter()
            .filter(|range| !range.is_empty())
        {
            Self::ensure_no_conflict(&mutable_range_map, range.src_start, range.src_inclusive_end)?;
            let (offset, own_alloc) =
                self.immutably_borrow_allocation(range.src_start, range.src_inclusive_end)?;
            let len = usize::try_from(range.src_inclusive_end - range.src_start).unwrap() + 1;
            out.alloc_from_allocation(range.dst_start, unsafe {
                Allocation::new_borrow(own_alloc, offset, len, allocation::BorrowKind::Immutable)
            })?;
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests;
