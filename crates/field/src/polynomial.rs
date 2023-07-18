//! This module defines polynomials (and their operations) over finite fields.

use crate::field::FiniteField;
use rand::RngCore;
use std::{
    fmt::Debug,
    ops::{AddAssign, Index, IndexMut, MulAssign, SubAssign},
};
use subtle::{Choice, ConstantTimeEq};

// TODO: a lot of these algorithms are the naive implementations. We should improve them if speed
// becomes an issue.

/// Compute the Lagrange coefficient $`ℓᵤ(e)`$ specified by points `points` and `u
/// ∈ points`.
///
/// This function is _not_ constant time.
pub fn lagrange_coefficient<F: FiniteField>(points: &[F], u: F, e: F) -> F {
    lagrange_numerator(points, u, e) * lagrange_denominator(points, u)
}

/// Compute the Lagrange coefficient numerator.
///
/// This function is _not_ constant time.
pub fn lagrange_numerator<F: FiniteField>(points: &[F], u: F, e: F) -> F {
    let mut numerator = F::ONE;
    for point in points.iter() {
        if *point == u {
            continue;
        }
        numerator *= e - *point;
    }
    numerator
}

/// Compute the Lagrange coefficient denominator.
///
/// This function is _not_ constant time.
pub fn lagrange_denominator<F: FiniteField>(points: &[F], u: F) -> F {
    lagrange_numerator(points, u, u).inverse()
}

/// A polynomial over some given finite field, represented as the coefficient vector.
#[derive(Clone, Eq)]
pub struct Polynomial<FE: FiniteField> {
    /// The coefficient for $`x^0`$
    pub constant: FE,
    /// The coefficients for $`x^1, ..., x^n`$
    ///
    /// `coefficients[i]` is the coefficient for $`x^{i+1}`$
    pub coefficients: Vec<FE>,
}

impl<FE: FiniteField> Polynomial<FE> {
    /// Construct a random polynomial of the given degree.
    pub fn random(rng: &mut (impl RngCore + ?Sized), degree: usize) -> Self {
        let constant = FE::random(rng);
        Self {
            constant,
            coefficients: (0..degree).map(|_| FE::random(rng)).collect(),
        }
    }

    /// Return the zero polynomial.
    pub fn zero() -> Self {
        Self {
            constant: FE::ZERO,
            coefficients: Default::default(),
        }
    }

    /// Return the polynomial `P(x) = 1`
    pub fn one() -> Self {
        Self::constant(FE::ONE)
    }

    /// Return the polynomial `P(x) = c`
    pub fn constant(c: FE) -> Self {
        Self {
            constant: c,
            coefficients: Default::default(),
        }
    }

    /// Return the polynomial `P(x) = x`
    pub fn x() -> Self {
        Polynomial {
            constant: FE::ZERO,
            coefficients: vec![FE::ONE],
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
        // Evaluate using Horner's rule
        let mut reversed = self.coefficients.iter().rev();
        if let Some(head) = reversed.next() {
            let mut acc = *head;
            for coeff in reversed {
                acc = acc * at + *coeff;
            }
            acc * at + self.constant
        } else {
            // This happens if there are no coefficients
            self.constant
        }
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
                coefficients: vec![FE::ZERO; b.checked_sub(d).unwrap()],
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
            coefficients: vec![FE::ZERO; points.len() - 1],
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
                    coefficients: vec![delta_x_inverse],
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
            .resize(tmp.degree() + rhs.degree(), FE::ZERO);
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

impl<FE: FiniteField> From<&[FE]> for Polynomial<FE> {
    fn from(v: &[FE]) -> Self {
        match v.len() {
            0 => Self::zero(),
            1 => Self::constant(v[0]),
            _ => Self {
                constant: v[0],
                coefficients: v[1..].to_vec(),
            },
        }
    }
}

impl<FE: FiniteField> Debug for Polynomial<FE> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "P(X) = {:?}", self.constant)?;
        for (i, coeff) in self.coefficients.iter().enumerate() {
            if *coeff != FE::ZERO {
                write!(f, " + {:?} X^{}", coeff, i + 1)?;
            }
        }
        Ok(())
    }
}

/// A polynomial in Newton polynomial form.
#[derive(Clone, Debug)]
pub struct NewtonPolynomial<F: FiniteField> {
    points: Vec<F>,
    cache: Vec<F>,
}

impl<F: FiniteField> NewtonPolynomial<F> {
    /// Construct a base Newton polynomial.
    pub fn new(points: Vec<F>) -> Self {
        // TODO: Optimize this cache
        let cache = compute_newton_points(&points);
        Self { points, cache }
    }

    /// Given `values`, find the coefficients for the Newton polynomial.
    pub fn interpolate_in_place(&self, values: &mut [F]) {
        assert!(values.len() <= self.points.len());

        for j in 1..values.len() {
            for i in (j..values.len()).rev() {
                let coef_lower = values[i - 1];
                let coef_upper = values[i];
                let coef_diff = coef_upper - coef_lower;

                let fraction = coef_diff * self.cache[j * values.len() + i];

                values[i] = fraction;
            }
        }
    }

    /// Compute the Newton basis polynomial on `point`.
    pub fn basis_polynomial(&self, point: F, polynomial: &mut Vec<F>) {
        let mut product = F::ONE;
        polynomial.push(product);
        for i in 0..self.points.len() - 1 {
            product *= point - self.points[i];
            polynomial.push(product);
        }
    }

    /// Evaluate the Newton polynomial given a pre-computed basis polynomial.
    pub fn eval_with_basis_polynomial(&self, polynomial: &[F], coefficients: &[F]) -> F {
        let mut result = F::ZERO;
        for (x, y) in coefficients.iter().zip(polynomial.iter()) {
            result += *x * *y;
        }
        result
    }

    /// Evaluate the Newton polynomial with `coefficients` on `point`.
    /// # Preconditions
    /// The length of `coefficients` must be less than or equal to the length of `points` provided
    /// to `Polynomial::new`.
    pub fn eval(&self, coefficients: &[F], point: F) -> F {
        assert!(coefficients.len() <= self.points.len());
        let mut result = F::ZERO;
        let mut product = F::ONE;
        for i in 0..coefficients.len() - 1 {
            result += coefficients[i] * product;
            product *= point - self.points[i];
        }
        result + *coefficients.last().unwrap() * product
    }
}

fn compute_newton_points<F: FiniteField>(points: &[F]) -> Vec<F> {
    let length = points.len();
    let mut indices: Vec<(usize, usize)> = (0..length).map(|index| (index, index)).collect();
    let mut cache = vec![F::ZERO; length * length];

    for j in 1..points.len() {
        for i in (j..points.len()).rev() {
            let index_lower = indices[i - 1].0;
            let index_upper = indices[i].1;

            let point_lower = points[index_lower];
            let point_upper = points[index_upper];
            let point_diff = point_upper - point_lower;
            let point_diff_inverse = point_diff.inverse();

            indices[i] = (index_lower, index_upper);
            cache[j * length + i] = point_diff_inverse;
        }
    }
    cache
}
