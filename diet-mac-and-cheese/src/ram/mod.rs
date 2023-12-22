mod perm;
mod tx;

pub trait MemorySpace<V> {
    type Addr: AsRef<[V]>;
    type Enum: Iterator<Item = Self::Addr>;

    fn size(&self) -> usize;

    fn enumerate(&self) -> Self::Enum;
}
