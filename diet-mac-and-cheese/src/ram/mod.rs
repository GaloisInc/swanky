mod perm;
mod protocol;
mod tx;

use protocol::DoraRam;

pub trait MemorySpace<V> {
    type Addr: AsRef<[V]>;
    type Enum: Iterator<Item = Self::Addr>;

    fn addr_size(&self) -> usize;

    fn value_size(&self) -> usize;

    fn size(&self) -> usize;

    fn enumerate(&self) -> Self::Enum;
}
