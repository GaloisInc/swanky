use crate::{
    CrtBundle,
    arithmetic::{ModChange, Subtraction},
    util::inv,
};
use core::marker::PhantomData;
use fancy_traits::{Circuit, FancyArithmetic, FancyBinary, FancyProj, HasModulus};
use swanky_channel::Channel;
use swanky_error::Result;

/// Convert a [`CrtBundle`] `x` to PMR representation.
#[derive(Default)]
pub struct ToPmr<'a>(PhantomData<&'a ()>);

impl<'a> ToPmr<'a> {
    /// Create a new [`ToPmr`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyArithmetic + FancyProj> Circuit<F> for ToPmr<'a>
where
    F::Item: HasModulus + 'a,
{
    type Input = &'a CrtBundle<F::Item>;
    type Output = CrtBundle<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let xs = inputs;
        let gadget_projection_tt = |p: u16, q: u16| -> Vec<u16> {
            let pq = p as u32 + q as u32 - 1;
            let mut tab = Vec::with_capacity(pq as usize);
            for z in 0..pq {
                let mut x = 0;
                let mut y = 0;
                'outer: for i in 0..p as u32 {
                    for j in 0..q as u32 {
                        if (i + pq - j) % pq == z {
                            x = i;
                            y = j;
                            break 'outer;
                        }
                    }
                }
                debug_assert_eq!((x + pq - y) % pq, z);
                tab.push(
                    (((x * q as u32 * inv(q as i128, p as i128) as u32
                        + y * p as u32 * inv(p as i128, q as i128) as u32)
                        / p as u32)
                        % q as u32) as u16,
                );
            }
            tab
        };

        let mut gadget = |x: F::Item, y: F::Item| -> Result<F::Item> {
            let p = x.modulus();
            let q = y.modulus();
            let x_ = ModChange.execute(backend, (x, p + q - 1), channel)?;
            let y_ = ModChange.execute(backend, (y, p + q - 1), channel)?;
            let z = backend.sub(&x_, &y_);
            backend.proj(&z, q, Some(gadget_projection_tt(p, q)), channel)
        };

        let n = xs.len();
        let mut x = vec![vec![None; n + 1]; n + 1];

        for j in 0..n {
            x[0][j + 1] = Some(xs.wires()[j].clone());
        }

        for i in 1..=n {
            for j in i + 1..=n {
                let z = gadget(x[i - 1][i].clone().unwrap(), x[i - 1][j].clone().unwrap())?;
                x[i][j] = Some(z);
            }
        }

        let mut zwires = Vec::with_capacity(n);
        for i in 0..n {
            zwires.push(x[i][i + 1].take().unwrap());
        }
        Ok(CrtBundle::new(zwires))
    }
}

/// For [`CrtBundle`]s `x` and `y`, output `x < y` using PMR representation.
///
/// For this to work, there must be an extra modulus in the CRT that is not
/// necessary to represent the values. This ensures that if `x < y`, the most
/// significant PMR digit is nonzero after subtracting them. You could add a
/// prime to your [`CrtBundle`]s right before using this gadget.
#[derive(Default)]
pub struct PmrLessThan<'a>(PhantomData<&'a ()>);

impl<'a> PmrLessThan<'a> {
    /// Create a new [`PmrLessThan`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyArithmetic + FancyProj> Circuit<F> for PmrLessThan<'a>
where
    F::Item: HasModulus + 'a,
{
    type Input = (&'a CrtBundle<F::Item>, &'a CrtBundle<F::Item>);
    type Output = F::Item;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let z = Subtraction::new().execute(backend, inputs, channel)?;
        let mut pmr = ToPmr::new().execute(backend, &z, channel)?;
        let w = pmr.pop().unwrap();
        let mut tab = vec![1; w.modulus() as usize];
        tab[0] = 0;
        backend.proj(&w, 2, Some(tab), channel)
    }
}

/// For [`CrtBundle`]s `x` and `y`, output `x >= y` using PMR representation.
///
/// For this to work, there must be an extra modulus in the CRT that is not
/// necessary to represent the values. This ensures that if `x >= y`, the most
/// significant PMR digit is nonzero after subtracting them. You could add a
/// prime to your [`CrtBundle`]s right before using this gadget.
#[derive(Default)]
pub struct PmrGreaterThanOrEqual<'a>(PhantomData<&'a ()>);

impl<'a> PmrGreaterThanOrEqual<'a> {
    /// Create a new [`PmrGreaterThanOrEqual`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyBinary + FancyArithmetic + FancyProj> Circuit<F> for PmrGreaterThanOrEqual<'a>
where
    F::Item: HasModulus + 'a,
{
    type Input = (&'a CrtBundle<F::Item>, &'a CrtBundle<F::Item>);
    type Output = F::Item;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let z = PmrLessThan::new().execute(backend, inputs, channel)?;
        Ok(backend.negate(&z))
    }
}

#[cfg(test)]
mod test {
    use rand::RngExt as _;

    use crate::{
        CrtBundle,
        arithmetic::{
            ToPmr,
            pmr::{PmrGreaterThanOrEqual, PmrLessThan},
        },
        util::{RngExt, product},
    };
    use fancy_plaintext::Dummy;

    #[test]
    fn to_pmr() {
        fn to_pmr_pt(x: u128, ps: &[u16]) -> Vec<u16> {
            let mut ds = vec![0; ps.len()];
            let mut q = 1;
            for i in 0..ps.len() {
                let p = ps[i] as u128;
                ds[i] = ((x / q) % p) as u16;
                q *= p;
            }
            ds
        }

        let mut rng = rand::rng();
        for _ in 0..8 {
            let ps = rng.gen_usable_factors();
            let q = product(&ps);

            let x = rng.random::<u128>() % q;
            let expected = to_pmr_pt(x, &ps);

            let x_input = CrtBundle::from((x, q));
            let z = Dummy::eval(&ToPmr::new(), &x_input).unwrap();
            let output = z.wires().iter().map(|w| w.val()).collect::<Vec<_>>();
            assert_eq!(output, expected);
        }
    }

    #[test]
    fn pmr_less_than() {
        let mut rng = rand::rng();
        for _ in 0..8 {
            let qs = rng.gen_usable_factors();
            let n = qs.len();
            let q = product(&qs);
            let q_ = product(&qs[..n - 1]);
            let x = rng.random::<u128>() % q_;
            let y = rng.random::<u128>() % q_;

            let x_input = CrtBundle::from((x, q));
            let y_input = CrtBundle::from((y, q));
            let output = Dummy::eval(&PmrLessThan::new(), (&x_input, &y_input)).unwrap();
            assert_eq!(output.val(), (x < y) as u16);
        }
    }

    #[test]
    fn pmr_greater_than_or_equal() {
        let mut rng = rand::rng();
        for _ in 0..8 {
            let qs = rng.gen_usable_factors();
            let n = qs.len();
            let q = product(&qs);
            let q_ = product(&qs[..n - 1]);
            let x = rng.random::<u128>() % q_;
            let y = rng.random::<u128>() % q_;

            let x_input = CrtBundle::from((x, q));
            let y_input = CrtBundle::from((y, q));
            let output = Dummy::eval(&PmrGreaterThanOrEqual::new(), (&x_input, &y_input)).unwrap();
            assert_eq!(output.val(), (x >= y) as u16);
        }
    }
}
