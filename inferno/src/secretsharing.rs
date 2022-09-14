use blake3::Hasher;
use rand::{CryptoRng, Rng};
use scuttlebutt::field::polynomial::{lagrange_denominator, lagrange_numerator};
use scuttlebutt::field::serialization::{FiniteFieldDeserializer, FiniteFieldSerializer};
use scuttlebutt::field::{FiniteField, IsSubfieldOf};

/// This trait defines an `N`-party linear secret sharing scheme
/// over finite field `F`.
pub trait LinearSharing<F: FiniteField, const N: usize>:
    'static
    + Default
    + Sized
    + Clone
    + Copy
    + std::ops::Add<Self, Output = Self>
    + std::ops::Sub<Self, Output = Self>
    + std::ops::Mul<F, Output = Self>
    + std::ops::AddAssign<Self>
{
    /// The type denoting a sharing of `F::PrimeField`.
    type SelfWithPrimeField: LinearSharing<F::PrimeField, N>;
    /// Generate a new sharing of `secret`, where each share is generated
    /// using it's corresponding RNG provided in `rngs`.
    fn new<R: Rng + CryptoRng>(secret: F, rngs: &mut [R; N]) -> Self;
    /// Generate a _non-random_ sharing of `secret`.
    fn new_non_random(secret: F) -> Self;
    /// Hash each individual share into its associated `Hasher`.
    fn hash(&self, hashers: &mut [Hasher]);

    fn lift_into_superfield(x: &Self::SelfWithPrimeField) -> Self;

    fn multiply_by_superfield(x: &Self::SelfWithPrimeField, y: F) -> Self;
}

pub struct LagrangeEvaluator<F> {
    denominators: Vec<F>,
}

impl<F: FiniteField> LagrangeEvaluator<F> {
    /// Construct a new Lagrange evaluator given `points`.
    pub fn new(points: &[F]) -> Self {
        let mut denominators: Vec<F> = Vec::with_capacity(points.len());
        for x in points.iter() {
            let d = lagrange_denominator(points, *x);
            denominators.push(d);
        }
        Self { denominators }
    }

    /// Pre-compute the Lagrange polynomial for evaluation point `e`.
    #[inline]
    pub fn basis_polynomial(&self, points: &[F], e: F, polynomial: &mut Vec<F>) {
        polynomial.clear();
        for (point, denominator) in points.iter().zip(self.denominators.iter()) {
            let point = lagrange_numerator(points, *point, e) * *denominator;
            polynomial.push(point);
        }
    }

    /// Evaluate the Lagrange polynomial using the pre-computed polynomial.
    #[inline]
    pub fn eval_with_basis_polynomial<S: LinearSharing<F, N>, const N: usize>(
        &self,
        coefficients: &[S],
        polynomial: &[F],
    ) -> S {
        let mut result = S::default();
        for (x, y) in polynomial.iter().zip(coefficients.iter()) {
            result += *y * *x;
        }
        result
    }
}

/// A sharing with a separate correction value which, when all summed together, equals the
/// underlying secret.
#[derive(Debug, Clone, Copy, Hash)]
pub struct CorrectionSharing<F: FiniteField, const N: usize> {
    shares: [F; N],
    correction: F,
}

impl<F: FiniteField, const N: usize> LinearSharing<F, N> for CorrectionSharing<F, N> {
    type SelfWithPrimeField = CorrectionSharing<F::PrimeField, N>;

    #[inline]
    fn new<R: Rng + CryptoRng>(secret: F, rngs: &mut [R; N]) -> Self {
        let mut sum = F::ZERO;
        let mut shares = [F::ZERO; N];
        for (share, rng) in shares.iter_mut().zip(rngs.iter_mut()) {
            let r = F::random(rng);
            sum += r;
            *share = r;
        }
        let correction = secret - sum;
        Self { shares, correction }
    }

    #[inline]
    fn new_non_random(secret: F) -> Self {
        let mut shares = [F::ZERO; N];
        shares[0] = secret;
        Self {
            shares,
            correction: F::ZERO,
        }
    }

    #[inline]
    fn hash(&self, hashers: &mut [Hasher]) {
        for (h, s) in hashers.iter_mut().zip(self.shares) {
            h.update(&s.to_bytes());
        }
    }

    #[inline]
    fn lift_into_superfield(x: &Self::SelfWithPrimeField) -> Self {
        Self {
            shares: x.shares.map(|s| s.lift_into_superfield()),
            correction: x.correction.lift_into_superfield(),
        }
    }

    #[inline]
    fn multiply_by_superfield(x: &Self::SelfWithPrimeField, y: F) -> Self {
        Self {
            shares: x.shares.map(|share| y.multiply_by_prime_subfield(share)),
            correction: y.multiply_by_prime_subfield(x.correction),
        }
    }
}

impl<F: FiniteField, const N: usize> CorrectionSharing<F, N> {
    pub fn check_equality(&self, other: &Self, id: usize) -> bool {
        assert!(id < N);
        for i in 0..N {
            if i != id && self.shares[i] != other.shares[i] {
                return false;
            }
        }
        true
    }

    #[inline]
    pub fn from_rngs<R: Rng + CryptoRng>(correction: F, rngs: &mut [R; N]) -> Self {
        let mut shares = [F::ZERO; N];
        for (share, rng) in shares.iter_mut().zip(rngs.iter_mut()) {
            let r = F::random(rng);
            *share = r;
        }
        Self { shares, correction }
    }

    #[inline]
    pub fn reconstruct(&self) -> F {
        self.shares.into_iter().sum::<F>() + self.correction
    }
}

impl<F: FiniteField, const N: usize> std::ops::Add for CorrectionSharing<F, N> {
    type Output = Self;

    #[inline]
    fn add(self, other: Self) -> Self {
        let mut shares = [F::ZERO; N];
        for i in 0..N {
            shares[i] = self.shares[i] + other.shares[i];
        }
        Self {
            shares,
            correction: self.correction + other.correction,
        }
    }
}

impl<F: FiniteField, const N: usize> std::ops::Sub for CorrectionSharing<F, N> {
    type Output = Self;

    #[inline]
    fn sub(self, other: Self) -> Self {
        let mut shares = [F::ZERO; N];
        for i in 0..N {
            shares[i] = self.shares[i] - other.shares[i];
        }
        Self {
            shares,
            correction: self.correction - other.correction,
        }
    }
}

impl<F: FiniteField, const N: usize> std::ops::AddAssign for CorrectionSharing<F, N> {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        for i in 0..N {
            self.shares[i] += rhs.shares[i];
        }
        self.correction += rhs.correction;
    }
}

impl<F: FiniteField, const N: usize> std::ops::Mul<F> for CorrectionSharing<F, N> {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: F) -> Self {
        Self {
            shares: self.shares.map(|a| a * rhs),
            correction: self.correction * rhs,
        }
    }
}

impl<F: FiniteField, const N: usize> Default for CorrectionSharing<F, N> {
    fn default() -> Self {
        Self {
            shares: [F::ZERO; N],
            correction: F::ZERO,
        }
    }
}

impl<F: FiniteField, const N: usize> serde::Serialize for CorrectionSharing<F, N> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error;
        use serde::ser::SerializeTupleStruct;

        let nbytes = F::Serializer::serialized_size(N + 1);
        let mut bytes = Vec::with_capacity(nbytes);
        let mut cursor = std::io::Cursor::new(&mut bytes);
        let mut ser = F::Serializer::new(&mut cursor).map_err(|e| Error::custom(e))?;
        for share in self.shares {
            ser.write(&mut cursor, share)
                .map_err(|e| Error::custom(e))?;
        }
        ser.write(&mut cursor, self.correction)
            .map_err(|e| Error::custom(e))?;
        ser.finish(&mut cursor).map_err(|e| Error::custom(e))?;

        let mut state = serializer.serialize_tuple_struct("Share", 1)?;
        state.serialize_field(&bytes)?;
        state.end()
    }
}

impl<'de, F: FiniteField, const N: usize> serde::Deserialize<'de> for CorrectionSharing<F, N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct MyVisitor<F, const N: usize> {
            field: std::marker::PhantomData<F>,
        }

        impl<'de, F: FiniteField, const N: usize> serde::de::Visitor<'de> for MyVisitor<F, N> {
            type Value = CorrectionSharing<F, N>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(
                    formatter,
                    "a sharing of field elements of type {}",
                    std::any::type_name::<F>(),
                )
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                use serde::de::Error;
                let nbytes = F::Serializer::serialized_size(N + 1);
                let bytes: Vec<u8> = match seq.next_element::<Vec<u8>>()? {
                    Some(e) => e,
                    None => return Err(A::Error::missing_field("vector of bytes")),
                };
                if let Some(_) = seq.next_element::<u8>()? {
                    return Err(A::Error::custom("extra field encountered"));
                }
                if bytes.len() != nbytes {
                    return Err(A::Error::invalid_length(bytes.len(), &self));
                }

                let mut cursor = std::io::Cursor::new(&bytes);
                let mut de = F::Deserializer::new(&mut cursor).map_err(|e| Error::custom(e))?;

                let mut shares = CorrectionSharing::<F, N>::default();
                for (_i, share) in shares.shares.iter_mut().enumerate() {
                    *share = de.read(&mut cursor).map_err(|e| Error::custom(e))?;
                }
                shares.correction = de.read(&mut cursor).map_err(|e| Error::custom(e))?;
                Ok(shares)
            }
        }

        deserializer.deserialize_tuple_struct(
            "[F; N]",
            1,
            MyVisitor {
                field: std::marker::PhantomData,
            },
        )
    }
}

/// A `CorrectionSharing` along with its secret.
#[derive(Debug, Clone, Copy, Hash)]
pub struct SecretSharing<F: FiniteField, const N: usize> {
    shares: CorrectionSharing<F, N>,
    secret: F,
}

impl<F: FiniteField, const N: usize> LinearSharing<F, N> for SecretSharing<F, N> {
    type SelfWithPrimeField = SecretSharing<F::PrimeField, N>;

    #[inline]
    fn new<R: Rng + CryptoRng>(secret: F, rngs: &mut [R; N]) -> Self {
        Self {
            shares: CorrectionSharing::new(secret, rngs),
            secret,
        }
    }

    #[inline]
    fn new_non_random(secret: F) -> Self {
        Self {
            shares: CorrectionSharing::new_non_random(secret),
            secret,
        }
    }

    #[inline]
    fn hash(&self, hashers: &mut [Hasher]) {
        self.shares.hash(hashers)
    }

    #[inline]
    fn lift_into_superfield(x: &SecretSharing<F::PrimeField, N>) -> Self {
        Self {
            shares: CorrectionSharing::lift_into_superfield(&x.shares),
            secret: x.secret.lift_into_superfield(),
        }
    }

    #[inline]
    fn multiply_by_superfield(x: &Self::SelfWithPrimeField, y: F) -> Self {
        Self {
            shares: CorrectionSharing::multiply_by_superfield(&x.shares, y),
            secret: y.multiply_by_prime_subfield(x.secret),
        }
    }
}

impl<F: FiniteField, const N: usize> SecretSharing<F, N> {
    #[inline]
    pub fn random<R: Rng + CryptoRng>(rngs: &mut [R; N]) -> Self {
        let mut secret = F::ZERO;
        let mut shares = [F::ZERO; N];
        for (share, rng) in shares.iter_mut().zip(rngs.iter_mut()) {
            *share = F::random(rng);
            secret += *share;
        }
        Self {
            shares: CorrectionSharing {
                shares,
                correction: F::ZERO,
            },
            secret,
        }
    }

    #[inline]
    pub fn secret(&self) -> F {
        self.secret
    }

    #[inline]
    pub fn correction(&self) -> F {
        self.shares.correction
    }

    #[inline]
    pub fn extract(&self, id: usize) -> CorrectionSharing<F, N> {
        debug_assert!(id < N);
        let mut arr = self.shares.shares;
        arr[id] = F::ZERO;
        CorrectionSharing {
            shares: arr,
            correction: self.shares.correction,
        }
    }

    #[inline]
    pub fn dot(xs: &[Self], ys: &[Self]) -> F {
        xs.iter()
            .zip(ys.iter())
            .map(|(x, y)| x.secret * y.secret)
            .sum::<F>()
    }
}

impl<F: FiniteField, const N: usize> std::ops::Add for SecretSharing<F, N> {
    type Output = Self;

    #[inline]
    fn add(self, other: Self) -> Self {
        Self {
            shares: self.shares + other.shares,
            secret: self.secret + other.secret,
        }
    }
}

impl<F: FiniteField, const N: usize> std::ops::Sub for SecretSharing<F, N> {
    type Output = Self;

    #[inline]
    fn sub(self, other: Self) -> Self {
        Self {
            shares: self.shares - other.shares,
            secret: self.secret - other.secret,
        }
    }
}

impl<F: FiniteField, const N: usize> std::ops::AddAssign for SecretSharing<F, N> {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        self.shares += rhs.shares;
        self.secret += rhs.secret;
    }
}

impl<F: FiniteField, const N: usize> std::ops::Mul<F> for SecretSharing<F, N> {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: F) -> Self {
        Self {
            shares: self.shares * rhs,
            secret: self.secret * rhs,
        }
    }
}

impl<F: FiniteField, const N: usize> Default for SecretSharing<F, N> {
    fn default() -> Self {
        Self {
            shares: Default::default(),
            secret: Default::default(),
        }
    }
}

impl<F: FiniteField, const N: usize> From<SecretSharing<F, N>> for CorrectionSharing<F, N> {
    fn from(s: SecretSharing<F, N>) -> Self {
        s.shares
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use scuttlebutt::field::polynomial::Polynomial;
    use scuttlebutt::field::{F128p, F61p, F2};
    use scuttlebutt::AesRng;

    const N: usize = 16;

    macro_rules! test_sharing {
        ($name:ident, $field:ty) => {
            #[test]
            fn $name() {
                let mut rng = AesRng::new();
                let mut rngs: [AesRng; N] = (0..N)
                    .map(|_| AesRng::new())
                    .collect::<Vec<AesRng>>()
                    .try_into()
                    .unwrap();
                let x = <$field>::random(&mut rng);
                let sharing = SecretSharing::<$field, N>::new(x, &mut rngs);
                let x_ = sharing.shares.reconstruct();
                assert_eq!(x, x_);
            }
        };
    }

    test_sharing!(test_sharing_f2, F2);
    test_sharing!(test_sharing_f61p, F61p);
    test_sharing!(test_sharing_f128p, F128p);

    macro_rules! test_poly_eval {
        ($name:ident, $field:ty) => {
            #[test]
            fn $name() {
                let mut rng = AesRng::from_seed(Default::default());
                let mut rngs: [AesRng; N] = (0..N)
                    .map(|_| AesRng::new())
                    .collect::<Vec<AesRng>>()
                    .try_into()
                    .unwrap();
                let e = <$field>::random(&mut rng);
                let xys: Vec<($field, $field)> = (0..16)
                    .map(|i| {
                        (
                            <$field>::GENERATOR.pow(i as u128),
                            <$field>::random(&mut rng),
                        )
                    })
                    .collect();
                let p = Polynomial::interpolate(&xys);
                let result = p.eval(e);
                let xs: Vec<$field> = xys.iter().map(|(x, _)| *x).collect();
                let ys_shares: Vec<SecretSharing<$field, N>> = xys
                    .iter()
                    .map(|(_, y)| SecretSharing::<$field, N>::new(*y, &mut rngs))
                    .collect();
                let evaluator = LagrangeEvaluator::new(&xs);
                let mut polynomial = vec![];
                evaluator.basis_polynomial(&xs, e, &mut polynomial);
                let result_shares = evaluator.eval_with_basis_polynomial(&ys_shares, &polynomial);
                assert_eq!(result, result_shares.shares.reconstruct());
            }
        };
    }

    macro_rules! test_serialization {
        ($tests_name: ident, $field: ty) => {
            mod $tests_name {
                use super::*;
                #[allow(unused_imports)]
                use proptest::prelude::*;
                use scuttlebutt::Block;

                fn any_fe() -> impl Strategy<Value = $field> {
                    any::<u128>().prop_map(|seed| {
                        <$field as FiniteField>::from_uniform_bytes(&seed.to_le_bytes())
                    })
                }

                fn any_seed() -> impl Strategy<Value = Block> {
                    any::<u128>().prop_map(|seed| Block::from(seed))
                }

                proptest! {
                #[test]
                fn sharing_serialize_serde_json(a in any_fe(), seed in any_seed()) {
                    let mut rng = AesRng::from_seed(seed);
                    let mut rngs: [AesRng; N] = (0..N)
                        .map(|_| rng.fork())
                        .collect::<Vec<AesRng>>()
                        .try_into()
                        .unwrap();
                    let sharing = CorrectionSharing::<$field, N>::new(a, &mut rngs);
                    let ser = serde_json::to_string(&sharing).unwrap();
                    let sharing_: CorrectionSharing<$field, N> = serde_json::from_str(&ser).unwrap();
                    for (a, b) in sharing.shares.iter().zip(sharing_.shares.iter()) {
                        assert_eq!(a, b);
                    }
                }
                }

                proptest! {
                #[test]
                fn sharing_serialize_bincode(a in any_fe(), seed in any_seed()) {
                    let mut rng = AesRng::from_seed(seed);
                    let mut rngs: [AesRng; N] = (0..N)
                        .map(|_| rng.fork())
                        .collect::<Vec<AesRng>>()
                        .try_into()
                        .unwrap();
                    let sharing = CorrectionSharing::<$field, N>::new(a, &mut rngs);
                    let ser = bincode::serialize(&sharing).unwrap();
                    let sharing_: CorrectionSharing<$field, N> = bincode::deserialize(&ser).unwrap();
                    for (a, b) in sharing.shares.iter().zip(sharing_.shares.iter()) {
                        assert_eq!(a, b);
                    }
                }
                }

                proptest! {
                #[test]
                fn sharing_vec_serialize_bincode(a in any_fe(), seed in any_seed()) {
                    let mut rng = AesRng::from_seed(seed);
                    let mut rngs: [AesRng; N] = (0..N)
                    .map(|_| rng.fork()).collect::<Vec<AesRng>>().try_into().unwrap();
                    let vec: Vec<CorrectionSharing<$field, N>> = (0..100).map(|_| CorrectionSharing::<$field, N>::new(a, &mut rngs)).collect();
                    let ser = bincode::serialize(&vec).unwrap();
                    let vec_: Vec<CorrectionSharing<$field, N>> = bincode::deserialize(&ser).unwrap();
                    for (a, b) in vec.iter().zip(vec_.iter()) {
                        for (x, y) in a.shares.iter().zip(b.shares.iter()) {
                            assert_eq!(x, y);
                        }
                    }


                }
                }
            }
        };
    }

    test_poly_eval!(test_poly_eval_f61p, F61p);
    test_poly_eval!(test_poly_eval_f128p, F128p);
    test_serialization!(serialization_f61p, F61p);
    test_serialization!(serialization_f2, F2);
}
