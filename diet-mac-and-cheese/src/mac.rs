use subtle::{Choice, ConditionallySelectable};
use swanky_field::{FiniteField, IsSubFieldOf};

/// This type holds the prover-side data associated with a MAC between a prover
/// and verifier (see [`MacVerifier`] for the verifier-side data).
///
/// The main property associated with the two types is that, given a
/// `MacProver(v, t)` and its corresponding `MacVerifier(k)`, the following
/// equation holds for a global key `Δ` known only to the verifier: `t = v · Δ +
/// k`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct MacProver<V: IsSubFieldOf<T>, T: FiniteField>(
    /// The prover's value `v`.
    V,
    /// The prover's MAC tag `t`.
    T,
);

impl<V: IsSubFieldOf<T>, T: FiniteField> MacProver<V, T> {
    pub fn new(x: V, m: T) -> Self {
        Self(x, m)
    }

    pub fn value(&self) -> V {
        self.0
    }

    pub fn mac(&self) -> T {
        self.1
    }

    pub fn decompose(&self) -> (V, T) {
        (self.0, self.1)
    }
}

impl<V: IsSubFieldOf<T>, T: FiniteField> Default for MacProver<V, T>
where
    T::PrimeField: IsSubFieldOf<V>,
{
    fn default() -> Self {
        Self::new(V::ZERO, T::ZERO)
    }
}

impl<V: IsSubFieldOf<T>, T: FiniteField> ConditionallySelectable for MacProver<V, T>
where
    T::PrimeField: IsSubFieldOf<V>,
{
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        MacProver(
            V::conditional_select(&a.0, &b.0, choice),
            T::conditional_select(&a.1, &b.1, choice),
        )
    }
}

/// This type holds the verifier-side data associated with a MAC between a
/// prover and verifier (see [`MacProver`] for the prover-side data).
///
/// The main property associated with the two types is that, given a
/// `MacProver(v, t)` and its corresponding `MacVerifier(k)`, the following
/// equation holds for a global key `Δ` known only to the verifier: `t = v · Δ +
/// k`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct MacVerifier<T: FiniteField>(
    /// The verifier's MAC key `k`.
    T,
);

impl<T: FiniteField> MacVerifier<T> {
    pub fn new(k: T) -> Self {
        Self(k)
    }

    pub fn mac(&self) -> T {
        self.0
    }
}

impl<T: FiniteField> Default for MacVerifier<T> {
    fn default() -> Self {
        Self::new(T::ZERO)
    }
}

impl<T: FiniteField> ConditionallySelectable for MacVerifier<T> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        MacVerifier(T::conditional_select(&a.0, &b.0, choice))
    }
}

#[cfg(test)]
pub(crate) fn validate<V: IsSubFieldOf<T>, T: FiniteField>(
    prover: MacProver<V, T>,
    verifier: MacVerifier<T>,
    delta: T,
) -> bool
where
    T::PrimeField: IsSubFieldOf<V>,
{
    prover.value() * delta + verifier.mac() == prover.mac()
}
