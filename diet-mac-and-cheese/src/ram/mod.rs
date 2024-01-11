mod perm;
mod protocol;
mod tx;

use std::marker::PhantomData;

use protocol::DoraRam;
use scuttlebutt::AbstractChannel;
use swanky_field::{FiniteField, IsSubFieldOf};
use swanky_party::Party;

use crate::{backend_trait::BackendT, mac::Mac, svole_trait::SvoleT, DietMacAndCheese};

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
    ram: Option<DoraRam<P, V, F, C, Arithmetic<V>, SVOLE>>,
}

impl<
        P: Party,
        V: IsSubFieldOf<F>,
        F: FiniteField,
        C: AbstractChannel + Clone,
        SVOLE: SvoleT<P, V, F>,
    > Default for ArithmeticRam<P, V, F, C, SVOLE>
where
    F::PrimeField: IsSubFieldOf<V>,
{
    fn default() -> Self {
        Self { size: 0, ram: None }
    }
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
        Self { size, ram: None }
    }

    pub fn read(
        &mut self,
        dmc: &mut DietMacAndCheese<P, V, F, C, SVOLE>,
        addr: &Mac<P, V, F>,
    ) -> eyre::Result<Mac<P, V, F>> {
        match self.ram.as_mut() {
            Some(ram) => {
                let value = ram.remove(dmc, &[*addr])?;
                ram.insert(dmc, &[*addr], &value)?;
                Ok(value[0])
            }
            None => {
                let ram = DoraRam::new(dmc, 2, Arithmetic::new(self.size));
                self.ram = Some(ram);
                self.read(dmc, addr)
            }
        }
    }

    pub fn write(
        &mut self,
        dmc: &mut DietMacAndCheese<P, V, F, C, SVOLE>,
        addr: &Mac<P, V, F>,
        value: &Mac<P, V, F>,
    ) -> eyre::Result<()> {
        match self.ram.as_mut() {
            Some(ram) => {
                ram.remove(dmc, &[*addr])?;
                ram.insert(dmc, &[*addr], &[*value])?;
                Ok(())
            }
            None => {
                let ram = DoraRam::new(dmc, 2, Arithmetic::new(self.size));
                self.ram = Some(ram);
                self.write(dmc, addr, value)
            }
        }
    }

    pub fn finalize(&mut self, dmc: &mut DietMacAndCheese<P, V, F, C, SVOLE>) -> eyre::Result<()> {
        match self.ram.take() {
            Some(ram) => ram.finalize(dmc),
            None => Ok(()),
        }
    }
}
