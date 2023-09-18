use generic_array::GenericArray;
use scuttlebutt::generic_array_length::Arr;
use std::{
    fmt::Debug,
    marker::PhantomData,
    ops::{Add, Mul, Neg, Sub},
};
use subtle::{Choice, ConditionallySelectable};
use swanky_field::{DegreeModulo, FiniteField, IsSubFieldOf};

fn make_x_i<V: IsSubFieldOf<T>, T: FiniteField>(i: usize) -> T {
    let mut v: GenericArray<V, DegreeModulo<V, T>> = GenericArray::default();
    v[i] = V::ONE;
    T::from_subfield(&v)
}

/// A trait defining a MAC type.
///
/// There are two realizations of [`Mac`]: [`MacProver`] and [`MacVerifier`].
/// These are used by the prover and verifier, respectively, as the underlying
/// data type in the circuit evaluation.
pub trait Mac: Clone + Copy + Debug + Default + Add + Sub + Neg + Mul<Self::Value> {
    /// The value field.
    type Value: IsSubFieldOf<Self::Tag>;
    /// The tag field.
    type Tag: FiniteField;
    /// A MAC lifted to its tag field.
    type LiftedMac: Mac<Value = Self::Tag, Tag = Self::Tag>;

    /// Lift an array of MACs from the value field to the tag field.
    fn lift(xs: &Arr<Self, DegreeModulo<Self::Value, Self::Tag>>) -> Self::LiftedMac;
}

/// This type holds the prover-side data associated with a MAC between a prover
/// and verifier (see [`MacVerifier`] for the verifier-side data).
///
/// The main property associated with the two types is that, given a
/// `MacProver(v, t)` and its corresponding `MacVerifier(k)`, the following
/// equation holds for a global key `Δ` known only to the verifier: `t = v · Δ +
/// k`.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct MacProver<V: IsSubFieldOf<T>, T: FiniteField>(
    /// The prover's value `v`.
    V,
    /// The prover's tag `t`.
    T,
);

impl<V: IsSubFieldOf<T>, T: FiniteField> MacProver<V, T> {
    #[inline]
    pub(crate) fn new(x: V, m: T) -> Self {
        Self(x, m)
    }
    #[inline]
    pub(crate) fn value(&self) -> V {
        self.0
    }
    #[inline]
    pub(crate) fn mac(&self) -> T {
        self.1
    }
    #[inline]
    pub(crate) fn decompose(&self) -> (V, T) {
        (self.0, self.1)
    }
}

impl<V: IsSubFieldOf<T>, T: FiniteField> Mac for MacProver<V, T> {
    type LiftedMac = MacProver<T, T>;
    type Value = V;
    type Tag = T;

    fn lift(xs: &Arr<Self, DegreeModulo<V, T>>) -> Self::LiftedMac {
        let mut value = T::ZERO;
        let mut mac = T::ZERO;
        for (i, x) in xs.iter().enumerate() {
            let x_i: T = make_x_i::<V, T>(i);
            value += x.value() * x_i;
            mac += x.mac() * x_i;
        }
        MacProver::new(value, mac)
    }
}

impl<V: IsSubFieldOf<T>, T: FiniteField> ConditionallySelectable for MacProver<V, T> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        MacProver(
            V::conditional_select(&a.0, &b.0, choice),
            T::conditional_select(&a.1, &b.1, choice),
        )
    }
}

impl<V: IsSubFieldOf<T>, T: FiniteField> Add for MacProver<V, T> {
    type Output = MacProver<V, T>;

    fn add(self, rhs: Self) -> Self::Output {
        Self::new(self.value() + rhs.value(), self.mac() + rhs.mac())
    }
}

impl<V: IsSubFieldOf<T>, T: FiniteField> Sub for MacProver<V, T> {
    type Output = MacProver<V, T>;

    fn sub(self, rhs: Self) -> Self::Output {
        Self::new(self.value() - rhs.value(), self.mac() - rhs.mac())
    }
}

impl<V: IsSubFieldOf<T>, T: FiniteField> Neg for MacProver<V, T> {
    type Output = MacProver<V, T>;

    fn neg(self) -> Self::Output {
        Self::new(-self.value(), -self.mac())
    }
}

impl<V: IsSubFieldOf<T>, T: FiniteField> Mul<V> for MacProver<V, T> {
    type Output = MacProver<V, T>;

    fn mul(self, rhs: V) -> Self::Output {
        Self::new(rhs * self.value(), rhs * self.mac())
    }
}

/// This type holds the verifier-side data associated with a MAC between a
/// prover and verifier (see [`MacProver`] for the prover-side data).
///
/// The main property associated with the two types is that, given a
/// `MacProver(v, t)` and its corresponding `MacVerifier(k)`, the following
/// equation holds for a global key `Δ` known only to the verifier: `t = v · Δ +
/// k`.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct MacVerifier<V: IsSubFieldOf<T>, T: FiniteField>(
    /// The verifier's MAC key `k`.
    T,
    PhantomData<V>,
);

impl<V: IsSubFieldOf<T>, T: FiniteField> MacVerifier<V, T> {
    pub fn new(k: T) -> Self {
        Self(k, PhantomData::<V>)
    }

    pub fn mac(&self) -> T {
        self.0
    }
}

impl<V: IsSubFieldOf<T>, T: FiniteField> Mac for MacVerifier<V, T> {
    type LiftedMac = MacVerifier<T, T>;
    type Value = V;
    type Tag = T;

    fn lift(xs: &Arr<Self, DegreeModulo<V, T>>) -> Self::LiftedMac {
        let mut mac = T::ZERO;
        for (i, x) in xs.iter().enumerate() {
            let x_i = make_x_i::<V, T>(i);
            mac += x.mac() * x_i;
        }
        MacVerifier::new(mac)
    }
}

impl<V: IsSubFieldOf<T>, T: FiniteField> Add for MacVerifier<V, T> {
    type Output = MacVerifier<V, T>;

    fn add(self, rhs: Self) -> Self::Output {
        Self::new(self.mac() + rhs.mac())
    }
}

impl<V: IsSubFieldOf<T>, T: FiniteField> Sub for MacVerifier<V, T> {
    type Output = MacVerifier<V, T>;

    fn sub(self, rhs: Self) -> Self::Output {
        Self::new(self.mac() - rhs.mac())
    }
}

impl<V: IsSubFieldOf<T>, T: FiniteField> Neg for MacVerifier<V, T> {
    type Output = MacVerifier<V, T>;

    fn neg(self) -> Self::Output {
        Self::new(-self.mac())
    }
}

impl<V: IsSubFieldOf<T>, T: FiniteField> Mul<V> for MacVerifier<V, T> {
    type Output = MacVerifier<V, T>;

    fn mul(self, rhs: V) -> Self::Output {
        Self::new(rhs * self.mac())
    }
}

impl<V: IsSubFieldOf<T>, T: FiniteField> ConditionallySelectable for MacVerifier<V, T> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let value = T::conditional_select(&a.mac(), &b.mac(), choice);
        MacVerifier::new(value)
    }
}

#[cfg(test)]
pub(crate) fn validate<V: IsSubFieldOf<T>, T: FiniteField>(
    prover: MacProver<V, T>,
    verifier: MacVerifier<V, T>,
    delta: T,
) {
    assert_eq!(prover.value() * delta + verifier.mac(), prover.mac());
}

#[cfg(test)]
mod tests {
    use generic_array::GenericArray;
    use scuttlebutt::AesRng;
    use swanky_field::{FiniteField, FiniteRing, IsSubFieldOf};
    use swanky_field_binary::{F40b, F2};

    use crate::mac::validate;

    use super::{Mac, MacProver, MacVerifier};

    fn generate<V: IsSubFieldOf<T>, T: FiniteField>(
        random: bool,
        delta: T,
        rng: &mut AesRng,
    ) -> (MacProver<V, T>, MacVerifier<V, T>) {
        let value = if random { V::random(rng) } else { V::ZERO };
        let vmac = T::random(rng);
        let prover = MacProver::new(value, value * delta - vmac);
        let verifier = MacVerifier::new(vmac);
        validate(prover, verifier, delta);
        (prover, verifier)
    }

    #[test]
    fn mac_lifting_works() {
        let mut rng = AesRng::new();
        for _ in 0..10 {
            let delta = F40b::random(&mut rng);
            let mut provers = GenericArray::default();
            let mut verifiers = GenericArray::default();
            let (prover, verifier) = generate::<F2, F40b>(true, delta, &mut rng);
            provers[0] = prover;
            verifiers[0] = verifier;

            let prover = MacProver::<F2, F40b>::lift(&provers);
            let verifier = <MacVerifier<F2, F40b> as Mac>::lift(&verifiers);

            validate(prover, verifier, delta);
        }
    }
}
