use scuttlebutt::field::FiniteField;

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
    use scuttlebutt::field::*;
    use scuttlebutt::AesRng;

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

                let poly = NewtonPolynomial::init(&xs, &ys);
                let ys_: Vec<$field> = xs.iter().map(|&x| poly.evaluate(x)).collect();
                assert_eq!(ys, ys_);
            }
        };
    }

    interpolation_tests!(interpolation_tests_f61p, F61p);
    interpolation_tests!(interpolation_tests_gf40, Gf40);
    interpolation_tests!(interpolation_tests_f128p, F128p);
}
