mod perm;
mod protocol;
mod tx;

use protocol::DoraRam;

use crate::backend_trait::BackendT;

const PRE_ALLOC_MEM: usize = 1 << 20;
const PRE_ALLOC_STEPS: usize = (1 << 23) + PRE_ALLOC_MEM;

fn combine<'a, B: BackendT>(
    backend: &'a mut B,
    mut elems: impl Iterator<Item = &'a B::Wire>,
    x: B::FieldElement,
) -> eyre::Result<B::Wire> {
    let mut y = backend.copy(elems.next().unwrap())?;
    for c in elems {
        y = backend.mul_constant(&y, x)?;
        y = backend.add(&y, c)?;
    }
    Ok(y)
}

pub(super) fn collapse_vec<B: BackendT>(
    backend: &mut B,
    elems: &[Vec<B::Wire>],
    x: B::FieldElement,
) -> eyre::Result<Vec<B::Wire>> {
    let mut out = Vec::with_capacity(elems.len());
    for e in elems {
        out.push(combine(backend, e.iter(), x)?);
    }
    Ok(out)
}

pub trait MemorySpace<V> {
    type Addr: AsRef<[V]>;
    type Enum: Iterator<Item = Self::Addr>;

    fn addr_size(&self) -> usize;

    fn value_size(&self) -> usize;

    fn size(&self) -> usize;

    fn enumerate(&self) -> Self::Enum;
}
