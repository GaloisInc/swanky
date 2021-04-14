use ndarray::{Array1, ArrayView1};

pub type Field = crate::f2_19x3_26::F;

// Trait for collections that allow taking `n` initial elements while ensuring
// that only zero-elements are dropped from the end.
pub trait TakeNZ where Self: Sized {
    fn take_nz(self, n: usize) -> std::iter::Take<Self>;
}

impl<L> TakeNZ for L where L: Iterator<Item = Field> + Clone {
    #[inline]
    fn take_nz(self, n: usize) -> std::iter::Take<Self> {
        debug_assert_eq!(
            self.clone().skip(n).collect::<Vec<_>>(),
            self.clone().skip(n).map(|_| Field::ZERO).collect::<Vec<_>>(),
        );

        self.take(n)
    }
}

// Given polynomials `p` and `q`, with `deg(p) < n` and `deg(q) < m`, return
// the `n+m`-degree polynomial `r` with `r(x) = p(x)*q(x)`.
//
// N.b.: This is the naive `O(n^2) algorithm. For `O(n log n)` performance on
// polynomials of degree less than `k+1`, use `Params::pmul2`.
#[allow(dead_code)]
pub fn pmul(p: ArrayView1<Field>, q: ArrayView1<Field>) -> Array1<Field> {
    let mut r = Array1::zeros(p.len() + q.len());

    for i in 0 .. p.len() {
        for j in 0 .. q.len() {
            r[i + j] += p[i] * q[j];
        }
    }

    r
}

// Given polynomials `p` with `deg(p) < n` and `q` with `deg(q) < m`, return
// the polynomial `r` with `deg(r) < max(n,m)` and `r(.) = p(.) + q(.)`.
pub fn padd(p: ArrayView1<Field>, q: ArrayView1<Field>) -> Array1<Field> {
    let r_len = std::cmp::max(p.len(), q.len());

    let p0: Array1<_> = p.iter()
        .cloned()
        .chain(vec![Field::ZERO; r_len - p.len()])
        .collect();
    let q0: Array1<_> = q.iter()
        .cloned()
        .chain(vec![Field::ZERO; r_len - q.len()])
        .collect();

    p0 + q0
}

// Given polynomials `p` with `deg(p) < n` and `q` with `deg(q) < m`, return
// the polynomial `r` with `deg(r) < max(n,m)` and `r(.) = p(.) - q(.)`.
pub fn psub(p: ArrayView1<Field>, q: ArrayView1<Field>) -> Array1<Field> {
    let r_len = std::cmp::max(p.len(), q.len());

    let p0: Array1<_> = p.iter()
        .cloned()
        .chain(vec![Field::ZERO; r_len - p.len()])
        .collect();
    let q0: Array1<_> = q.iter()
        .cloned()
        .chain(vec![Field::ZERO; r_len - q.len()])
        .collect();

    p0 - q0
}

// Evaluate a polynomial, represented by its coefficients, at a point `x`.
pub fn peval(p: ArrayView1<Field>, x: Field) -> Field {
    //let mut res = Field::ZERO;

    //for &pi in p.to_vec()[1..].iter().rev() {
    //    res = res + pi;
    //    res = res * x;
    //}

    //res + p[0]
    crate::numtheory::mod_evaluate_polynomial(&p.to_vec(), x)
}

pub fn random_field_array<R>(rng: &mut R, size: usize) -> Array1<Field>
    where R: rand::Rng
{
    (0 .. size).map(|_| rng.sample(rand::distributions::Standard)).collect()
}
