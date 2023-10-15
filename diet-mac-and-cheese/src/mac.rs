use generic_array::GenericArray;
use std::{
    fmt::Debug,
    ops::{Add, Mul, Neg, Sub},
};
use subtle::{Choice, ConditionallySelectable};
use swanky_field::{DegreeModulo, FiniteField, IsSubFieldOf};
use swanky_party::{private::ProverPrivateCopy, IsParty, Party, Prover};

fn make_x_i<V: IsSubFieldOf<T>, T: FiniteField>(i: usize) -> T {
    let mut v: GenericArray<V, DegreeModulo<V, T>> = GenericArray::default();
    v[i] = V::ONE;
    T::from_subfield(&v)
}

/// A trait defining a MAC type.
pub trait MacT: Clone + Copy + Debug + Default {
    /// The value field.
    type Value: IsSubFieldOf<Self::Tag>;
    /// The tag field.
    type Tag: FiniteField;
    /// A MAC lifted to its tag field.
    type LiftedMac: MacT<Value = Self::Tag, Tag = Self::Tag>;

    /// Lift an array of MACs from the value field to the tag field.
    fn lift(xs: &GenericArray<Self, DegreeModulo<Self::Value, Self::Tag>>) -> Self::LiftedMac;
}

/// Party-generic MACs.
///
/// The following holds for a global key known `Δ` known only to the verifier:
/// `t = v · Δ + k`.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Mac<P: Party, V: Copy, T>(ProverPrivateCopy<P, V>, T);

impl<P: Party, V: IsSubFieldOf<T>, T: FiniteField> Mac<P, V, T> {
    #[inline]
    pub(crate) fn new(x: ProverPrivateCopy<P, V>, m: T) -> Self {
        Self(x, m)
    }

    #[inline]
    pub(crate) fn value(&self) -> ProverPrivateCopy<P, V> {
        self.0
    }

    #[inline]
    pub(crate) fn mac(&self) -> T {
        self.1
    }

    #[inline]
    pub(crate) fn decompose(&self, ev: IsParty<P, Prover>) -> (V, T) {
        (self.0.into_inner(ev), self.1)
    }

    /// Lift an array of MACs from the value field to the tag field.
    pub fn lift(xs: &GenericArray<Self, DegreeModulo<V, T>>) -> Mac<P, T, T> {
        let mut value = ProverPrivateCopy::new(T::ZERO);
        let mut mac = T::ZERO;

        for (i, x) in xs.iter().enumerate() {
            let x_i: T = make_x_i::<V, T>(i);
            value
                .as_mut()
                .zip(x.0.into())
                .map(|(v, x_v)| *v += x_v * x_i);
            mac += x.mac() * x_i;
        }

        Mac::new(value, mac)
    }
}

impl<P: Party, V: IsSubFieldOf<T>, T: FiniteField> MacT for Mac<P, V, T> {
    type Value = V;
    type Tag = T;
    type LiftedMac = Mac<P, Self::Tag, Self::Tag>;

    fn lift(xs: &GenericArray<Self, DegreeModulo<Self::Value, Self::Tag>>) -> Self::LiftedMac {
        Self::lift(xs)
    }
}

impl<P: Party, V: IsSubFieldOf<T>, T: FiniteField> ConditionallySelectable for Mac<P, V, T> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Mac(
            a.0.zip(b.0)
                .map(|(av, bv)| V::conditional_select(&av, &bv, choice)),
            T::conditional_select(&a.1, &b.1, choice),
        )
    }
}

impl<P: Party, V: IsSubFieldOf<T>, T: FiniteField> Add for Mac<P, V, T> {
    type Output = Mac<P, V, T>;

    fn add(self, rhs: Self) -> Self::Output {
        Self(
            self.0.zip(rhs.0).map(|(v, rhs_v)| v + rhs_v),
            self.mac() + rhs.mac(),
        )
    }
}

impl<P: Party, V: IsSubFieldOf<T>, T: FiniteField> Sub for Mac<P, V, T> {
    type Output = Mac<P, V, T>;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(
            self.0.zip(rhs.0).map(|(v, rhs_v)| v - rhs_v),
            self.mac() - rhs.mac(),
        )
    }
}

impl<P: Party, V: IsSubFieldOf<T>, T: FiniteField> Neg for Mac<P, V, T> {
    type Output = Mac<P, V, T>;

    fn neg(self) -> Self::Output {
        Self(self.0.map(|v| -v), -self.mac())
    }
}

impl<P: Party, V: IsSubFieldOf<T>, T: FiniteField> Mul<V> for Mac<P, V, T> {
    type Output = Mac<P, V, T>;

    fn mul(self, rhs: V) -> Self::Output {
        Self(self.0.map(|v| rhs * v), rhs * self.mac())
    }
}

#[cfg(test)]
use swanky_party::Verifier;

#[cfg(test)]
pub(crate) fn validate<V: IsSubFieldOf<T>, T: FiniteField>(
    prover: Mac<Prover, V, T>,
    verifier: Mac<Verifier, V, T>,
    delta: T,
) {
    use swanky_party::IS_PROVER;

    assert_eq!(
        prover.value().into_inner(IS_PROVER) * delta + verifier.mac(),
        prover.mac()
    );
}

#[cfg(test)]
mod tests {
    use generic_array::GenericArray;
    use scuttlebutt::AesRng;
    use swanky_field::{FiniteField, FiniteRing, IsSubFieldOf};
    use swanky_field_binary::{F40b, F2};
    use swanky_party::{private::ProverPrivateCopy, Prover, Verifier, IS_VERIFIER};

    use crate::mac::validate;

    use super::Mac;

    fn generate<V: IsSubFieldOf<T>, T: FiniteField>(
        random: bool,
        delta: T,
        rng: &mut AesRng,
    ) -> (Mac<Prover, V, T>, Mac<Verifier, V, T>) {
        let value = if random { V::random(rng) } else { V::ZERO };
        let vmac = T::random(rng);
        let prover = Mac::new(ProverPrivateCopy::new(value), value * delta - vmac);
        let verifier = Mac::new(ProverPrivateCopy::empty(IS_VERIFIER), vmac);
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

            let prover = Mac::<Prover, F2, F40b>::lift(&provers);
            let verifier = Mac::<Verifier, F2, F40b>::lift(&verifiers);

            validate(prover, verifier, delta);
        }
    }
}
