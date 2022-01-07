//! This module defines polynomials (and their operations) over finite fields.

use crate::field::FiniteField;
use rand_core::RngCore;
use smallvec::{smallvec, SmallVec};
use std::{
    fmt::Debug,
    ops::{AddAssign, Index, IndexMut, MulAssign, SubAssign},
};
use subtle::{Choice, ConstantTimeEq};

// TODO: a lot of these algorithms are the naive implementations. We should improve them if speed
// becomes an issue.

/// A polynomial over some given finite field.
#[derive(Clone, Eq)]
pub struct Polynomial<FE: FiniteField> {
    /// The coefficient for `x^0`
    pub constant: FE,
    /// The coefficients for `x^1, ..., x^n`
    ///
    /// `coefficients[i]` is the coefficient for `x^(i+1)`
    pub coefficients: SmallVec<[FE; 3]>,
}

impl<FE: FiniteField> Polynomial<FE> {
    /// Construct a random polynomial of the given degree.
    pub fn random(rng: &mut (impl RngCore + ?Sized), degree: usize) -> Self {
        let constant = FE::random(rng);
        Polynomial {
            constant,
            coefficients: (0..degree).map(|_| FE::random(rng)).collect(),
        }
    }

    /// Return the zero polynomial.
    pub fn zero() -> Self {
        Polynomial {
            constant: FE::ZERO,
            coefficients: Default::default(),
        }
    }

    /// Return the polynomial `P(x)=1`
    pub fn one() -> Self {
        Polynomial {
            constant: FE::ONE,
            coefficients: Default::default(),
        }
    }

    /// Return the polynomial `P(x)=x`
    pub fn x() -> Self {
        Polynomial {
            constant: FE::ZERO,
            coefficients: smallvec![FE::ONE],
        }
    }

    /// Return the degree of the polynomial
    pub fn degree(&self) -> usize {
        self.coefficients.len()
            - self
                .coefficients
                .iter()
                .rev()
                .take_while(|x| **x == FE::ZERO)
                .count()
    }

    /// Evaluate the polynomial at a given `x` value.
    pub fn eval(&self, at: FE) -> FE {
        let mut acu = self.constant;
        let mut x_pow = at;
        for coeff in self.coefficients.iter() {
            acu += x_pow * *coeff;
            // TODO: should we worry about the last multiplication at the end? (for performance)
            x_pow *= at;
        }
        acu
    }

    /// Return `(self / divisor, self % divisor)`
    pub fn divmod(&self, divisor: &Self) -> (Self, Self) {
        let mut q = Self::zero();
        let mut r = self.clone();
        let d = divisor.degree();
        while r != Self::zero() && r.degree() >= divisor.degree() {
            // The leading term is lead(r) / lead(divisor).
            // Let lead(r) = a * x ^ b.
            // Let lead(divisor) = c * x ^ d
            // b - d is positive, since r.degree() > divisor.degree()
            // lead(r) / lead(divisor) = (a/c) * x ^ (b-d)
            let b = r.degree();
            let mut t = Polynomial {
                constant: FE::ZERO,
                coefficients: smallvec![FE::ZERO; b.checked_sub(d).unwrap()],
            };
            t[b - d] = r[b] / divisor[d];
            q += &t;
            t *= divisor;
            r -= &t;
        }
        (q, r)
    }

    /// Interpolate a polynomial from the given `(x,y)` points
    ///
    /// # Panics
    /// This function will panic if `points` is empty, or if any `x` values collide.
    pub fn interpolate(points: &[(FE, FE)]) -> Self {
        assert!(!points.is_empty());
        let mut out = Polynomial {
            constant: FE::ZERO,
            coefficients: smallvec![FE::ZERO; points.len() - 1],
        };
        for (j, (xj, yj)) in points.iter().enumerate() {
            let mut l = Polynomial::one();
            for (m, (xm, _)) in points.iter().enumerate() {
                if m == j {
                    continue;
                }
                assert_ne!(*xm, *xj);
                let delta_x = *xj - *xm;
                let delta_x_inverse = delta_x.inverse();
                l *= &Polynomial {
                    constant: -(*xm) * delta_x_inverse,
                    coefficients: smallvec![delta_x_inverse],
                };
            }
            l *= *yj;
            out += &l;
        }
        out
    }
}

impl<'a, FE: FiniteField> AddAssign<&'a Polynomial<FE>> for Polynomial<FE> {
    fn add_assign(&mut self, rhs: &'a Polynomial<FE>) {
        self.coefficients.resize(
            self.coefficients.len().max(rhs.coefficients.len()),
            FE::ZERO,
        );
        self.constant += rhs.constant;
        for (a, b) in self.coefficients.iter_mut().zip(rhs.coefficients.iter()) {
            *a += *b;
        }
    }
}

impl<'a, FE: FiniteField> SubAssign<&'a Polynomial<FE>> for Polynomial<FE> {
    fn sub_assign(&mut self, rhs: &'a Polynomial<FE>) {
        self.coefficients.resize(
            self.coefficients.len().max(rhs.coefficients.len()),
            FE::ZERO,
        );
        self.constant -= rhs.constant;
        for (a, b) in self.coefficients.iter_mut().zip(rhs.coefficients.iter()) {
            *a -= *b;
        }
    }
}

impl<FE: FiniteField> MulAssign<FE> for Polynomial<FE> {
    fn mul_assign(&mut self, rhs: FE) {
        self.constant *= rhs;
        for coeff in self.coefficients.iter_mut() {
            *coeff *= rhs;
        }
    }
}

/// Index into the Polynomial where 0 is the constant term.
impl<FE: FiniteField> Index<usize> for Polynomial<FE> {
    type Output = FE;

    fn index(&self, index: usize) -> &Self::Output {
        if index == 0 {
            &self.constant
        } else {
            &self.coefficients[index - 1]
        }
    }
}

/// Index into the Polynomial where 0 is the constant term.
impl<FE: FiniteField> IndexMut<usize> for Polynomial<FE> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        if index == 0 {
            &mut self.constant
        } else {
            &mut self.coefficients[index - 1]
        }
    }
}

impl<'a, FE: FiniteField> MulAssign<&'a Polynomial<FE>> for Polynomial<FE> {
    fn mul_assign(&mut self, rhs: &'a Polynomial<FE>) {
        // TODO: this is the most naive, most simple, and slowest implementation of multiplication.
        // If this is a bottleneck, then pick a faster algorithm.
        let tmp = self.clone();
        self.constant = FE::ZERO;
        for x in self.coefficients.iter_mut() {
            *x = FE::ZERO;
        }
        self.coefficients
            .resize(tmp.degree() + rhs.degree() + 1, FE::ZERO);
        for i in 0..tmp.degree() + 1 {
            for j in 0..rhs.degree() + 1 {
                self[i + j] += tmp[i] * rhs[j];
            }
        }
    }
}

impl<FE: FiniteField> PartialEq for Polynomial<FE> {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl<FE: FiniteField> ConstantTimeEq for Polynomial<FE> {
    fn ct_eq(&self, other: &Self) -> Choice {
        let mut out = self.constant.ct_eq(&other.constant);
        for (a, b) in self
            .coefficients
            .iter()
            .cloned()
            .chain(std::iter::repeat(FE::ZERO))
            .zip(
                other
                    .coefficients
                    .iter()
                    .cloned()
                    .chain(std::iter::repeat(FE::ZERO)),
            )
            .take(self.coefficients.len().max(other.coefficients.len()))
        {
            out &= a.ct_eq(&b);
        }
        out
    }
}

impl<FE: FiniteField> Debug for Polynomial<FE> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "P(x) = {:?}", self.constant)?;
        for (i, coeff) in self.coefficients.iter().enumerate() {
            if *coeff != FE::ZERO {
                write!(f, " + {:?} * x^{}", coeff, i + 1)?;
            }
        }
        Ok(())
    }
}

/// Holds together points and Newton-interpolated coefficients for fast evaluation.
///
/// TODO: Merge this with the `Polynomial` struct.
#[derive(Debug)]
pub struct NewtonPolynomial<'a, Field>
where
    Field: FiniteField,
{
    points: &'a [Field],
    coefficients: Vec<Field>,
}

impl<'a, Field: FiniteField> NewtonPolynomial<'a, Field> {
    /// Construct a Newton polynomial interpolation.
    ///
    /// Given enough `points` (x) and `values` (p(x)), find the coefficients for `p`.
    pub fn init(points: &'a [Field], values: &[Field]) -> Self {
        let coefficients = compute_newton_coefficients(points, values);
        Self {
            points,
            coefficients,
        }
    }

    /// Evaluate the Newton polynomial.
    pub fn evaluate(&self, point: Field) -> Field {
        // compute Newton points
        let mut newton_points = vec![Field::ONE];
        for i in 0..self.points.len() - 1 {
            let diff = point - self.points[i];
            let product = newton_points[i] * diff;
            newton_points.push(product);
        }
        let ref newton_coefs = self.coefficients;
        // sum up
        newton_coefs
            .iter()
            .zip(newton_points)
            .map(|(&coef, point)| coef * point)
            .sum()
    }
}

fn compute_newton_coefficients<Field>(points: &[Field], values: &[Field]) -> Vec<Field>
where
    Field: FiniteField,
{
    assert_eq!(points.len(), values.len());

    let mut store: Vec<(usize, usize, Field)> = values
        .iter()
        .enumerate()
        .map(|(index, &value)| (index, index, value))
        .collect();

    for j in 1..store.len() {
        for i in (j..store.len()).rev() {
            let index_lower = store[i - 1].0;
            let index_upper = store[i].1;

            let point_lower = points[index_lower];
            let point_upper = points[index_upper];
            let point_diff = point_upper - point_lower;
            let point_diff_inverse = point_diff.inverse();

            let coef_lower = store[i - 1].2;
            let coef_upper = store[i].2;
            let coef_diff = coef_upper - coef_lower;

            let fraction = coef_diff * point_diff_inverse;

            store[i] = (index_lower, index_upper, fraction);
        }
    }

    store.iter().map(|&(_, _, v)| v).collect()
}

/// Evaluate polynomial given by `coefficients` at `point`.
pub fn eval<Field>(coefficients: &[Field], point: Field) -> Field
where
    Field: FiniteField,
{
    // evaluate using Horner's rule
    //  - to combine with fold we consider the coefficients in reverse order
    let mut reversed_coefficients = coefficients.iter().rev();
    // manually split due to fold insisting on an initial value
    let head = *reversed_coefficients.next().unwrap();
    let tail = reversed_coefficients;
    tail.fold(head, |partial, &coef| partial * point + coef)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::*;
    use crate::{AesRng, Block};
    use rand::Rng;
    use rand_core::SeedableRng;

    #[test]
    fn test_degree() {
        fn f<FE: FiniteField>() {
            assert_eq!(Polynomial::<FE>::zero().degree(), 0);
            assert_eq!(Polynomial::<FE>::one().degree(), 0);
            assert_eq!(Polynomial::<FE>::x().degree(), 1);
            assert_eq!(
                (Polynomial {
                    constant: FE::ZERO,
                    coefficients: smallvec![FE::ZERO, FE::ZERO],
                })
                .degree(),
                0
            );
            assert_eq!(
                (Polynomial {
                    constant: FE::ZERO,
                    coefficients: smallvec![
                        FE::ZERO,
                        FE::ZERO,
                        FE::ONE,
                        FE::ZERO,
                        FE::ZERO,
                        FE::ZERO
                    ],
                })
                .degree(),
                3
            );
        }
        call_with_finite_field!(f);
    }

    #[test]
    fn test_addition() {
        fn f<FE: FiniteField>() {
            let mut rng = AesRng::from_seed(Block::default());
            for _ in 0..100 {
                let a = Polynomial::random(&mut rng, 10);
                let b = Polynomial::random(&mut rng, 10);
                let mut product = a.clone();
                product += &b;
                for _ in 0..100 {
                    let x = FE::random(&mut rng);
                    assert_eq!(product.eval(x), a.eval(x) + b.eval(x));
                }
            }
        }
        call_with_finite_field!(f);
    }

    #[test]
    fn test_subtraction() {
        fn f<FE: FiniteField>() {
            let mut rng = AesRng::from_seed(Block::default());
            for _ in 0..100 {
                let a = Polynomial::random(&mut rng, 10);
                let b = Polynomial::random(&mut rng, 10);
                let mut product = a.clone();
                product -= &b;
                for _ in 0..100 {
                    let x = FE::random(&mut rng);
                    assert_eq!(product.eval(x), a.eval(x) - b.eval(x));
                }
            }
        }
        call_with_finite_field!(f);
    }

    #[test]
    fn test_multiplication() {
        fn f<FE: FiniteField>() {
            let mut rng = AesRng::from_seed(Block::default());
            for _ in 0..100 {
                let a = Polynomial::random(&mut rng, 10);
                let b = Polynomial::random(&mut rng, 10);
                let mut product = a.clone();
                product *= &b;
                for _ in 0..100 {
                    let x = FE::random(&mut rng);
                    assert_eq!(product.eval(x), a.eval(x) * b.eval(x));
                }
            }
        }
        call_with_finite_field!(f);
    }

    #[test]
    fn test_scalar_multiplication() {
        fn f<FE: FiniteField>() {
            let mut rng = AesRng::from_seed(Block::default());
            for _ in 0..100 {
                let a = Polynomial::random(&mut rng, 10);
                let c = FE::random(&mut rng);
                let mut product = a.clone();
                product *= c;
                for _ in 0..100 {
                    let x = FE::random(&mut rng);
                    assert_eq!(product.eval(x), a.eval(x) * c);
                }
            }
        }
        call_with_finite_field!(f);
    }

    #[test]
    fn test_interpolation() {
        fn f<FE: FiniteField>() {
            let mut rng = AesRng::from_seed(Block::default());
            {
                let poly = Polynomial::interpolate(&[(FE::ZERO, FE::ZERO), (FE::ONE, FE::ONE)]);
                assert_eq!(poly.eval(FE::ZERO), FE::ZERO);
                assert_eq!(poly.eval(FE::ONE), FE::ONE);
            }
            {
                let poly = Polynomial::interpolate(&[(FE::ZERO, FE::ONE)]);
                assert_eq!(poly.eval(FE::ZERO), FE::ONE);
            }
            for _ in 0..100 {
                let n_points = 5;
                let mut points = Vec::new();
                for _ in 0..n_points {
                    let x = FE::random(&mut rng);
                    let y = FE::random(&mut rng);
                    points.push((x, y));
                }
                let p = Polynomial::interpolate(&points);
                for (x, y) in points {
                    assert_eq!(p.eval(x), y);
                }
            }
        }
        // We don't want collisions between x values.
        call_with_big_finite_fields!(f);
    }

    #[test]
    fn test_divmod() {
        fn f<FE: FiniteField>() {
            let mut rng = AesRng::from_seed(Block::default());
            for _ in 0..1000 {
                let degree1 = rng.gen_range(0usize, 20usize);
                let degree2 = rng.gen_range(0usize, 20usize);
                let a = Polynomial::<FE>::random(&mut rng, degree1);
                let mut b = Polynomial::<FE>::random(&mut rng, degree2);
                if b == Polynomial::<FE>::zero() {
                    continue;
                }
                let (q, r) = a.divmod(&b);
                assert!(
                    r == Polynomial::zero() || r.degree() < b.degree(),
                    "{:?} {:?}",
                    r,
                    b
                );
                b *= &q;
                b += &r;
                // a = b*q + r
                assert_eq!(a, b);
            }
        }
        call_with_finite_field!(f);
    }

    // Tests `eval` function.
    macro_rules! polynomial_evaluation_tests {
        ($name:ident, $field: ty) => {
            #[test]
            fn $name() {
                let mut rng = AesRng::new();
                let coeffs: Vec<_> = (0..10).map(|_| <$field>::random(&mut rng)).collect();
                let point = <$field>::random(&mut rng);
                let y = eval(&coeffs, point);
                let mut y_ = <$field>::ZERO;
                for (i, c) in coeffs.iter().enumerate() {
                    y_ += point.pow(i as u128) * c;
                }
                assert_eq!(y, y_);
            }
        };
    }

    polynomial_evaluation_tests!(poly_eval_tests_f61p, F61p);
    polynomial_evaluation_tests!(poly_eval_tests_gf40, Gf40);
    polynomial_evaluation_tests!(poly_eval_tests_f128p, F128p);

    /// Newton interpolation tests
    macro_rules! interpolation_tests {
        ($name:ident, $field: ty) => {
            #[test]
            fn $name() {
                let mut rng = AesRng::new();
                let coeffs: Vec<_> = (0..9).map(|_| <$field>::random(&mut rng)).collect();
                let xs: Vec<_> = (0..10).map(|_| <$field>::random(&mut rng)).collect();
                let ys: Vec<$field> = xs.iter().map(|&x| eval(&coeffs, x)).collect();
                println!("coeffs = {:?}", coeffs);
                println!("xs = {:?}", xs);
                println!("ys = {:?}", ys);

                let poly = NewtonPolynomial::init(&xs, &ys);
                println!("poly = {:?}", poly);
                assert_eq!(coeffs, poly.coefficients);
                let ys_: Vec<$field> = xs.iter().map(|&x| poly.evaluate(x)).collect();
                assert_eq!(ys, ys_);
            }
        };
    }

    interpolation_tests!(interpolation_tests_f61p, F61p);
    // interpolation_tests!(interpolation_tests_gf40, Gf40);
    // interpolation_tests!(interpolation_tests_f128p, F128p);
}
