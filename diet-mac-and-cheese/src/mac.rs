use eyre::bail;
use generic_array::GenericArray;
use std::{
    fmt::Debug,
    ops::{Add, Mul, Neg, Sub},
};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use swanky_field::{DegreeModulo, FiniteField, FiniteRing, IsSubFieldOf};
use swanky_field_binary::{F40b, F2};
use swanky_party::{private::ProverPrivateCopy, IsParty, Party, Prover, WhichParty};

pub(crate) fn make_x_i<V: IsSubFieldOf<T>, T: FiniteField>(i: usize) -> T {
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

impl<T: FiniteField> MacT for T {
    type Value = T;
    type Tag = T;
    type LiftedMac = Self;

    fn lift(xs: &GenericArray<Self, DegreeModulo<Self::Value, Self::Tag>>) -> Self::LiftedMac {
        debug_assert!(xs.len() == 1);
        xs[0]
    }
}

/// Party-generic MACs.
///
/// The following holds for a global key known `Δ` known only to the verifier:
/// `t = v · Δ + k`.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Mac<P: Party, V: Copy, T>(ProverPrivateCopy<P, V>, T);

// TODO: Is this safe?
impl<P: Party> From<Mac<P, F2, F40b>> for Mac<P, F40b, F40b> {
    fn from(value: Mac<P, F2, F40b>) -> Self {
        Mac::new(value.0.map(|v| v.into()), value.1)
    }
}

// TODO: Is this safe?
impl<P: Party> TryFrom<Mac<P, F40b, F40b>> for Mac<P, F2, F40b> {
    type Error = eyre::Error;

    fn try_from(value: Mac<P, F40b, F40b>) -> Result<Self, Self::Error> {
        Ok(Mac::new(
            match P::WHICH {
                WhichParty::Prover(ev) => {
                    let value_eq_zero = value.value().into_inner(ev).ct_eq(&F40b::ZERO);
                    let value_eq_one = value.value().into_inner(ev).ct_eq(&F40b::ONE);

                    let res = CtOption::new(
                        F2::conditional_select(&F2::ZERO, &F2::ONE, value_eq_one),
                        value_eq_zero | value_eq_one,
                    );

                    if res.is_none().into() {
                        bail!("F40b value too large to be an F2 value.")
                    } else {
                        // Safe: We've already checked that res is not none.
                        ProverPrivateCopy::new(res.unwrap())
                    }
                }

                WhichParty::Verifier(ev) => ProverPrivateCopy::empty(ev),
            },
            value.1,
        ))
    }
}

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

    #[test]
    fn mac_f2_mac_f40b_roundtrip() {
        let zero: Mac<Prover, F2, F40b> = Mac::new(ProverPrivateCopy::new(F2::ZERO), F40b::ZERO);
        let one: Mac<Prover, F2, F40b> = Mac::new(ProverPrivateCopy::new(F2::ONE), F40b::ZERO);

        assert_eq!(
            <Mac<_, _, _>>::try_from(<Mac<_, F40b, _>>::from(zero)).unwrap(),
            zero
        );

        assert_eq!(
            <Mac<_, _, _>>::try_from(<Mac<_, F40b, _>>::from(one)).unwrap(),
            one
        );
    }
}
