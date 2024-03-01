mod protocol;
mod tests;
mod tx;

use std::marker::PhantomData;

use eyre::Result;
use protocol::DoraRam;
use scuttlebutt::AbstractChannel;
use swanky_field::{FiniteField, FiniteRing, IsSubFieldOf};
use swanky_field_binary::{F40b, F2};
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
    init_value: Mac<P, V, F>,
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
    /// Create a new `ArithmeticRam` with `size` cells, each containing
    /// `init_value`.
    pub fn new(size: usize, init_value: Mac<P, V, F>) -> Self {
        Self {
            size,
            init_value,
            dora: None,
        }
    }

    /// Read and return the value at `addr`.
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
                let ram = DoraRam::new(dmc, vec![self.init_value], 2, Arithmetic::new(self.size));
                self.dora = Some(ram);
                self.read(dmc, addr)
            }
        }
    }

    /// Write `value` to `addr`.
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
                let ram = DoraRam::new(dmc, vec![self.init_value], 2, Arithmetic::new(self.size));
                self.dora = Some(ram);
                self.write(dmc, addr, value)
            }
        }
    }

    /// Finalize this `ArithmeticRam`.
    ///
    /// This should only be called when no more reads/writes will occur on this
    /// RAM.
    pub fn finalize(&mut self, dmc: &mut DietMacAndCheese<P, V, F, C, SVOLE>) -> Result<()> {
        match self.dora.take() {
            Some(ram) => ram.finalize(dmc),
            None => Ok(()),
        }
    }
}

struct Boolean {
    addr_size: usize,
    value_size: usize,
    ram_size: usize,
}

impl Boolean {
    fn new(addr_size: usize, value_size: usize, ram_size: usize) -> Self {
        Self {
            addr_size,
            value_size,
            ram_size,
        }
    }
}

/// A binary counter of a fixed width.
///
/// Internally, LSB-first for easy counting, but can be borrowed as MSB-first.
struct BinaryCounter(Vec<F2>);

impl BinaryCounter {
    /// Create a new counter that is `num_bits` wide.
    ///
    /// The counter is initialized to zero.
    fn new(num_bits: usize) -> Self {
        Self(vec![F2::ZERO; num_bits])
    }

    /// Increment the binary counter.
    ///
    /// Note that this is a 'cycling' counter, so incrementing the counter where
    /// all bits are set results in the counter of all zeros.
    fn incr(&mut self) {
        let mut need_flip = true;
        for bit in self.0.iter_mut() {
            if need_flip {
                *bit += F2::ONE;
                need_flip = *bit == F2::ZERO;
            }
        }
    }

    /// Return the counter value as an MSB-first `Vec`.
    fn curr_val(&self) -> Vec<F2> {
        self.0.iter().rev().copied().collect()
    }
}

struct BooleanIter {
    current: BinaryCounter,
    rem: usize,
}

impl Iterator for BooleanIter {
    type Item = Vec<F2>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rem > 0 {
            let old = self.current.curr_val();
            self.current.incr();
            self.rem -= 1;
            Some(old)
        } else {
            None
        }
    }
}

impl MemorySpace<F2> for Boolean {
    type Addr = Vec<F2>;
    type Enum = BooleanIter;

    fn addr_size(&self) -> usize {
        self.addr_size
    }

    fn value_size(&self) -> usize {
        self.value_size
    }

    fn size(&self) -> usize {
        self.ram_size
    }

    fn enumerate(&self) -> Self::Enum {
        BooleanIter {
            current: BinaryCounter::new(self.addr_size),
            rem: self.ram_size,
        }
    }
}

/// A RAM with addresses/values represented by one or more F2 values.
///
/// This is a high-level wrapper around [`DoraRam`] for the case described
/// above. Use of this structure over `DoraRam` is preferred, as it provides
/// the more familiar read/write interface and properly executes the protocol
/// steps for these operations.
pub struct BooleanRam<
    P: Party,
    T: FiniteField<PrimeField = F2>,
    C: AbstractChannel + Clone,
    SVOLE: SvoleT<P, F2, T>,
> where
    F2: IsSubFieldOf<T>,
{
    addr_size: usize,
    value_size: usize,
    size: usize,
    init_value: Vec<Mac<P, F2, T>>,
    dora: Option<DoraRam<P, F2, T, C, Boolean, SVOLE>>,
}

impl<
        P: Party,
        T: FiniteField<PrimeField = F2>,
        C: AbstractChannel + Clone,
        SVOLE: SvoleT<P, F2, T>,
    > BooleanRam<P, T, C, SVOLE>
where
    F2: IsSubFieldOf<T>,
{
    /// Create a new `BooleanRam` with `size` cells, each containing
    /// `init_value`.
    pub fn new(
        addr_size: usize,
        value_size: usize,
        size: usize,
        init_value: Vec<Mac<P, F2, T>>,
    ) -> Self {
        Self {
            addr_size,
            value_size,
            size,
            init_value,
            dora: None,
        }
    }

    /// Read and return the value at `addr`.
    pub fn read(
        &mut self,
        dmc: &mut DietMacAndCheese<P, F2, T, C, SVOLE>,
        addr: &[Mac<P, F2, T>],
    ) -> Result<Vec<Mac<P, F2, T>>> {
        match self.dora.as_mut() {
            Some(ram) => {
                let value = ram.remove(dmc, addr)?;
                ram.insert(dmc, addr, &value)?;
                Ok(value)
            }
            None => {
                let ram = DoraRam::new(
                    dmc,
                    self.init_value.clone(),
                    2,
                    Boolean::new(self.addr_size, self.value_size, self.size),
                );
                self.dora = Some(ram);
                self.read(dmc, addr)
            }
        }
    }

    /// Write `value` to `addr`.
    pub fn write(
        &mut self,
        dmc: &mut DietMacAndCheese<P, F2, T, C, SVOLE>,
        addr: &[Mac<P, F2, T>],
        value: &[Mac<P, F2, T>],
    ) -> Result<()> {
        match self.dora.as_mut() {
            Some(ram) => {
                ram.remove(dmc, addr)?;
                ram.insert(dmc, addr, value)?;
                Ok(())
            }
            None => {
                let ram = DoraRam::new(
                    dmc,
                    self.init_value.clone(),
                    2,
                    Boolean::new(self.addr_size, self.value_size, self.size),
                );
                self.dora = Some(ram);
                self.write(dmc, addr, value)
            }
        }
    }

    /// Finalize this `BooleanRam`.
    ///
    /// This should only be called when no more reads/writes will occur on this
    /// RAM.
    pub fn finalize(&mut self, dmc: &mut DietMacAndCheese<P, F2, T, C, SVOLE>) -> Result<()> {
        match self.dora.take() {
            Some(ram) => ram.finalize(dmc),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod counter_tests {
    use super::*;

    #[test]
    fn incr_zero() {
        let mut bc = BinaryCounter(vec![F2::ZERO, F2::ZERO, F2::ZERO]);
        bc.incr();
        assert!(&[F2::ZERO, F2::ZERO, F2::ONE].into_iter().eq(bc.curr_val()));
    }

    #[test]
    fn incr_one() {
        let mut bc = BinaryCounter(vec![F2::ONE, F2::ZERO, F2::ZERO]);
        bc.incr();
        assert!(&[F2::ZERO, F2::ONE, F2::ZERO].into_iter().eq(bc.curr_val()));
    }

    #[test]
    fn incr_two() {
        let mut bc = BinaryCounter(vec![F2::ZERO, F2::ONE, F2::ZERO]);
        bc.incr();
        assert!(&[F2::ZERO, F2::ONE, F2::ONE].into_iter().eq(bc.curr_val()));
    }

    #[test]
    fn incr_max() {
        let mut bc = BinaryCounter(vec![F2::ONE, F2::ONE, F2::ONE]);
        bc.incr();
        assert!(&[F2::ZERO, F2::ZERO, F2::ZERO].into_iter().eq(bc.curr_val()));
    }
}
