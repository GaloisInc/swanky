mod perm;
mod protocol;
mod tx;

use protocol::DoraRam;

const PRE_ALLOC_MEM: usize = 1 << 20;
const PRE_ALLOC_STEPS: usize = (1 << 23) + PRE_ALLOC_MEM;

pub trait MemorySpace<V> {
    type Addr: AsRef<[V]>;
    type Enum: Iterator<Item = Self::Addr>;

    fn addr_size(&self) -> usize;

    fn value_size(&self) -> usize;

    fn size(&self) -> usize;

    fn enumerate(&self) -> Self::Enum;
}
