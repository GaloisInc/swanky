use std::{cell::Cell, fmt::Debug};

use rand::{Rng, SeedableRng};

use crate::{DestinationRange, InsertResult, WireId, WireMap, WireNotFound};

#[derive(Debug, PartialEq, Eq)]
struct Value<'a> {
    id: u64,
    num_allocated: &'a Cell<u64>,
}
impl<'a> Drop for Value<'a> {
    fn drop(&mut self) {
        self.num_allocated.set(self.num_allocated.get() - 1);
    }
}

struct Allocation {
    start: WireId,
    num_set: usize,
    contents: Vec<Option<u64>>,
}
impl Allocation {
    fn end_inclusive(&self) -> WireId {
        self.contents.len() as u64 - 1 + self.start
    }
}

struct MirroredWireMap<'a> {
    next_fresh_value: u64,
    num_allocated: &'a Cell<u64>,
    wire_map: WireMap<'static, Value<'a>>,
    canonical: Vec<Allocation>,
}

impl<'a> MirroredWireMap<'a> {
    fn check_allocated(&self) {
        assert_eq!(
            self.num_allocated.get(),
            self.canonical
                .iter()
                .map(|alloc| alloc.num_set)
                .sum::<usize>() as u64
        );
    }
    fn alloc(&mut self, start: WireId, end: WireId) {
        let len = if let Some(len) = end.checked_sub(start) {
            len as usize
        } else {
            return;
        } + 1;
        for alloc in self.canonical.iter() {
            assert!(
                alloc.end_inclusive() < start || end < alloc.start,
                "{start}..={end} vs {}..={}",
                alloc.start,
                alloc.end_inclusive()
            );
        }
        self.canonical.push(Allocation {
            start,
            contents: vec![None; len],
            num_set: 0,
        });
        self.wire_map.alloc(start, end).unwrap();
    }
    fn free(&mut self, start: WireId, end: WireId) {
        self.canonical.retain(|alloc| alloc.start != start);
        self.wire_map.free(start, end).unwrap();
        self.check_allocated();
    }
    fn canonical_allocation(
        canonical: &mut Vec<Allocation>,
        wire: WireId,
    ) -> Option<&mut Allocation> {
        canonical
            .iter_mut()
            .find(|x| (x.start..=x.end_inclusive()).contains(&wire))
    }
    fn get_mut(&mut self, wire: WireId) {
        self.next_fresh_value += 1;
        let new_value = self.next_fresh_value;
        let out = self.wire_map.get_mut(wire);
        if let Some(alloc) = Self::canonical_allocation(&mut self.canonical, wire) {
            if let Some(cell) = alloc.contents[(wire - alloc.start) as usize].as_mut() {
                let out = out.unwrap();
                assert_eq!(out.id, *cell);
                *cell = new_value;
                out.id = new_value;
            } else {
                assert_eq!(out, Err(WireNotFound::UnsetValueWithinAllocation));
            }
        } else {
            assert_eq!(out, Err(WireNotFound::NotAllocated));
        }
    }
    fn insert(&mut self, wire: WireId) {
        self.next_fresh_value += 1;
        let new_value = self.next_fresh_value;
        self.num_allocated.set(self.num_allocated.get() + 1);
        let out = self.wire_map.insert(
            wire,
            Value {
                id: new_value,
                num_allocated: self.num_allocated,
            },
        );
        if let Some(alloc) = Self::canonical_allocation(&mut self.canonical, wire) {
            let cell = &mut alloc.contents[(wire - alloc.start) as usize];
            if cell.is_some() {
                assert_eq!(out, InsertResult::PreviouslySet);
            } else {
                assert_eq!(out, InsertResult::PreviouslyUnset);
                alloc.num_set += 1;
            }
            *cell = Some(new_value);
        } else {
            assert!(matches!(out, InsertResult::NotAllocated(_)));
        }
        std::mem::drop(out);
        self.check_allocated();
    }
}

fn with_mirrored_wire_map<F>(f: F)
where
    for<'a> F: FnOnce(MirroredWireMap<'a>),
{
    let num_allocated = Cell::new(0_u64);
    f(MirroredWireMap {
        num_allocated: &num_allocated,
        next_fresh_value: 0,
        wire_map: WireMap::new(),
        canonical: Vec::new(),
    })
}

#[test]
fn simple_test() {
    with_mirrored_wire_map(|mut wm| {
        let ids = [u64::MAX, u64::MAX - 1, u64::MAX - 2, 0, 1, 2];
        for id in ids {
            wm.get_mut(id);
        }
        wm.alloc(u64::MAX - 2, u64::MAX);
        for id in ids {
            wm.get_mut(id);
        }
        for id in ids {
            wm.insert(id);
        }
        for id in ids {
            wm.get_mut(id);
        }
        wm.alloc(0, 1);
        for id in ids {
            wm.get_mut(id);
        }
        for id in ids {
            wm.insert(id);
        }
        for id in ids {
            wm.get_mut(id);
        }
        wm.free(0, 1);
        for id in ids {
            wm.get_mut(id);
        }
        for id in ids {
            wm.insert(id);
        }
        for id in ids {
            wm.get_mut(id);
        }
    });
}

#[test]
#[ignore] // TODO: fix failing test
fn random_tests() {
    for trial in 0..16 {
        dbg!(trial);
        with_mirrored_wire_map(|mut wm| {
            let mut rng = rand::rngs::StdRng::seed_from_u64(trial);
            let mut allocations = vec![
                (0, 12, false),
                (13, 45, false),
                (13 + 46, 67, false),
                (u64::MAX - 127, 128, false),
            ];
            while allocations.len() < 16 {
                let len = rng.gen_range(1..=128);
                // We probably won't intersect any exising allocation. about (2^-39)
                let start: u64 = rng.gen();
                allocations.push((start, len, false));
            }
            for _ in 0..500_000 {
                if rng.gen_ratio(1, 128) {
                    // Alloc or free
                    let idx = rng.gen_range(0..allocations.len());
                    let alloc = &mut allocations[idx];
                    if alloc.2 {
                        wm.free(alloc.0, alloc.1);
                        alloc.2 = false;
                    } else {
                        wm.alloc(alloc.0, alloc.1);
                        alloc.2 = true;
                    }
                } else {
                    let idx: WireId = if rng.gen_ratio(1, 128) {
                        rng.gen()
                    } else {
                        // This distribution isn't weigthed by the size of each allocation.
                        let (start, len, _alloc) = allocations[rng.gen_range(0..allocations.len())];
                        // We don't care whether it's allocated or not.
                        rng.gen_range(start..=start + (len - 1))
                    };
                    if rng.gen_ratio(1, 2) {
                        wm.insert(idx);
                    } else {
                        wm.get_mut(idx);
                    }
                }
            }
        });
    }
}

#[test]
#[ignore] // TODO: fix failing test
fn test_allocation_success() {
    let mut wm = WireMap::<u64>::new();
    // Shouldn't allocate anything
    wm.alloc(u64::MAX, 75).unwrap();
    // Shouldn't free anything.
    wm.free(u64::MAX, 7).unwrap();
    wm.alloc(u64::MAX, u64::MAX).unwrap();
    assert_eq!(wm.insert(u64::MAX, 12), InsertResult::PreviouslyUnset);
    assert!(wm.alloc(u64::MAX - 1, u64::MAX).is_err());
    wm.alloc(u64::MAX - 5, u64::MAX - 1).unwrap();
    assert!(wm.free(u64::MAX - 5, u64::MAX).is_err());
    wm.free(u64::MAX - 5, u64::MAX - 1).unwrap();
    wm.free(u64::MAX, u64::MAX).unwrap();
    wm.alloc(0, 3).unwrap();
    wm.alloc(8, 10).unwrap();
    wm.alloc(4, 7).unwrap();
    assert!(wm.alloc(3, 6).is_err());
    wm.free(4, 7).unwrap();
    assert!(wm.alloc(3, 6).is_err());
}

#[test]
fn test_alloc_range_if_unallocated() {
    let mut wm = WireMap::<u64>::new();
    wm.alloc_range_if_unallocated(u64::MAX - 1, u64::MAX)
        .unwrap();
    assert_eq!(wm.insert(u64::MAX - 1, 5), InsertResult::PreviouslyUnset);
    assert_eq!(wm.insert(u64::MAX, 785), InsertResult::PreviouslyUnset);
    assert!(wm
        .alloc_range_if_unallocated(u64::MAX - 2, u64::MAX)
        .is_err());
    wm.alloc_range_if_unallocated(15, 475).unwrap();
    wm.alloc_range_if_unallocated(15, 475).unwrap();
    wm.alloc_range_if_unallocated(75, 100).unwrap();
}

fn dr(src_start: u64, src_inclusive_end: u64, dst_start: u64) -> DestinationRange {
    DestinationRange {
        src_start,
        src_inclusive_end,
        dst_start,
    }
}

#[test]
fn test_child_map_failures() {
    let mut wm = WireMap::<i32>::new();
    wm.borrow_child([], []).unwrap();
    wm.borrow_child([dr(15, 0, 0)], []).unwrap();
    wm.alloc(12, 512).unwrap();
    // Source range doesn't exist
    assert!(wm.borrow_child([dr(0, 15, 78)], []).is_err());
    // Destination range overlaps
    assert!(wm.borrow_child([dr(13, 17, 0), dr(56, 78, 0)], []).is_err());
    // Mutable range overlaps immutable range
    assert!(wm.borrow_child([dr(13, 78, 0)], [dr(15, 45, 0)]).is_err());
    // Mutable ranges overlap
    assert!(wm.borrow_child([dr(13, 78, 0), dr(15, 45, 0)], []).is_err());
    let mut child = wm
        .borrow_child([dr(13, 78, 0)], [dr(101, 112, 500)])
        .unwrap();
    assert!(child.borrow_child([dr(500, 502, 0)], []).is_err());
}

#[test]
fn simple_child_map_test() {
    let mut wm = WireMap::<i32>::new();
    wm.alloc(6917529027641081853, 6917529027641082750).unwrap();
    let mut child = wm
        .borrow_child([dr(6917529027641081853, 6917529027641081853, 15)], [])
        .unwrap();
    child.insert(15, 78);
    std::mem::drop(child);
    assert_eq!(*wm.get(6917529027641081853).unwrap(), 78);
}
