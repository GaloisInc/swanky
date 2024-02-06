mod protocol;
mod tests;
mod tx;

use std::marker::PhantomData;

use eyre::Result;
use protocol::DoraRam;
use scuttlebutt::AbstractChannel;
use swanky_field::{FiniteField, IsSubFieldOf};
use swanky_party::Party;

use crate::{backend_trait::BackendT, mac::Mac, svole_trait::SvoleT, DietMacAndCheese};

fn combine<'a, B: BackendT>(
    backend: &'a mut B,
    mut elems: impl Iterator<Item = &'a B::Wire>,
    x: B::FieldElement,
) -> Result<B::Wire> {
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
) -> Result<Vec<B::Wire>> {
    let mut out = Vec::with_capacity(elems.len());
    for e in elems {
        out.push(combine(backend, e.iter(), x)?);
    }
    Ok(out)
}

/// Types representing an enumerable memory/RAM space.
pub trait MemorySpace<V> {
    /// The type of RAM addresses.
    type Addr: AsRef<[V]>;
    /// An iterator over [`Self::Addr`].
    type Enum: Iterator<Item = Self::Addr>;

    /// The size (in number of `V`) of addresses.
    fn addr_size(&self) -> usize;

    /// The size (in number of `V`) of values.
    fn value_size(&self) -> usize;

    /// The total capacity of the RAM.
    fn size(&self) -> usize;

    /// Return an iterator over all addresses.
    fn enumerate(&self) -> Self::Enum;
}

struct Arithmetic<F: FiniteField> {
    size: usize,
    _ph: PhantomData<F>,
}

impl<F: FiniteField> Arithmetic<F> {
    fn new(size: usize) -> Self {
        Self {
            size,
            _ph: PhantomData,
        }
    }
}

struct ArithmeticIter<F: FiniteField> {
    current: [F; 1],
    rem: usize,
}

impl<F: FiniteField> Iterator for ArithmeticIter<F> {
    type Item = [F; 1];

    fn next(&mut self) -> Option<Self::Item> {
        if self.rem > 0 {
            let old = self.current;
            self.current[0] += F::ONE;
            self.rem -= 1;
            Some(old)
        } else {
            None
        }
    }
}

impl<F: FiniteField> MemorySpace<F> for Arithmetic<F> {
    type Addr = [F; 1];
    type Enum = ArithmeticIter<F>;

    fn addr_size(&self) -> usize {
        1
    }

    fn value_size(&self) -> usize {
        1
    }

    fn size(&self) -> usize {
        self.size
    }

    fn enumerate(&self) -> Self::Enum {
        ArithmeticIter {
            current: [F::ZERO],
            rem: self.size,
        }
    }
}

/// A RAM with addresses/values represented by a single arithmetic field
/// element.
///
/// This is a high-level wrapper around [`DoraRam`] for the case described
/// above. Use of this structure over `DoraRam` is preferred, as it provides
/// the more familiar read/write interface and properly executes the protocol
/// steps for these operations.
pub struct ArithmeticRam<
    P: Party,
    V: IsSubFieldOf<F>,
    F: FiniteField,
    C: AbstractChannel + Clone,
    SVOLE: SvoleT<P, V, F>,
> where
    F::PrimeField: IsSubFieldOf<V>,
{
    size: usize,
    dora: Option<DoraRam<P, V, F, C, Arithmetic<V>, SVOLE>>,
}

impl<
        P: Party,
        V: IsSubFieldOf<F>,
        F: FiniteField,
        C: AbstractChannel + Clone,
        SVOLE: SvoleT<P, V, F>,
    > ArithmeticRam<P, V, F, C, SVOLE>
where
    F::PrimeField: IsSubFieldOf<V>,
{
    pub fn new(size: usize) -> Self {
        Self { size, dora: None }
    }

    pub fn read(
        &mut self,
        dmc: &mut DietMacAndCheese<P, V, F, C, SVOLE>,
        addr: &Mac<P, V, F>,
    ) -> Result<Mac<P, V, F>> {
        match self.dora.as_mut() {
            Some(ram) => {
                let value = ram.remove(dmc, &[*addr])?;
                ram.insert(dmc, &[*addr], &value)?;
                Ok(value[0])
            }
            None => {
                let ram = DoraRam::new(dmc, 2, Arithmetic::new(self.size));
                self.dora = Some(ram);
                self.read(dmc, addr)
            }
        }
    }

    pub fn write(
        &mut self,
        dmc: &mut DietMacAndCheese<P, V, F, C, SVOLE>,
        addr: &Mac<P, V, F>,
        value: &Mac<P, V, F>,
    ) -> Result<()> {
        match self.dora.as_mut() {
            Some(ram) => {
                ram.remove(dmc, &[*addr])?;
                ram.insert(dmc, &[*addr], &[*value])?;
                Ok(())
            }
            None => {
                let ram = DoraRam::new(dmc, 2, Arithmetic::new(self.size));
                self.dora = Some(ram);
                self.write(dmc, addr, value)
            }
        }
    }

    pub fn finalize(&mut self, dmc: &mut DietMacAndCheese<P, V, F, C, SVOLE>) -> Result<()> {
        match self.dora.take() {
            Some(ram) => ram.finalize(dmc),
            None => Ok(()),
        }
    }
}
