//! Parameters for threshold secret sharing in Ligero. This includes
//! parameter-specific

// TODO: Eliminate excessive use of vectors in anonymous functions, function
// return values, etc.

use crate::ligero::FieldForLigero;
use crate::threshold_secret_sharing::PackedSecretSharingGenerator;
use crate::util::*;
use ndarray::{concatenate, Array1, Array2, ArrayView1, ArrayView2, Axis, Zip};
use rand::{CryptoRng, Rng};
use scuttlebutt::field::fft;
use scuttlebutt::field::fft::FieldForFFT;
use scuttlebutt::field::polynomial::Polynomial;

/// Parameters for interleaved coding, based on the size of the circuit and
/// input. Note that these variable names, although terse, correspond to those
/// used in https://dl.acm.org/doi/pdf/10.1145/3133956.3134104
///
/// We fix the security threshold t = log |F| to get the following soundness
/// errors, where e is a positive integer with e < d/4, d is the code distance,
/// and n = 2^p:
///
/// * Test-Interleaved:             (1 - e/n)^t + (e + 1)/|F|
///                               = (1 - e/|F|)^p + (e + 1)/|F|
/// * Test-Linear-Constraints:      ((e + k + l)/n)^t + 1/|F|
///                               = ((e + k + l)/|F|)^p + 1/|F|
/// * Test-Quadratic-Constraints:   ((e + 2k)/n)^t + 1/|F|
///                               = ((e + 2k)/|F|)^p + 1/|F|
///
/// I.e., we ensure soundness error is negligible in the field size.
//
// XXX: Is this right? Seems like t could be smaller, say ceil(log |F| / p).
#[derive(Debug, Clone, Copy)]
pub struct Params<Field> {
    /// Parameters for `threshold_secret_sharing::PackedSecretSharing`.
    pss: PackedSecretSharingGenerator<Field>,

    /// Log base-2 of k
    kexp: u32,
    /// Log base-3 of k
    _nexp: u32,

    /// Number of field elements encoded in a single codeword row.
    /// (Note: k = l + t = 2^j - 1, for some j)
    pub(crate) l: usize,
    /// Security threshold: max number of columns that can be revealed securely
    pub(crate) t: usize,
    /// Reconstruction threshold: min number of columns for reconstruction
    pub(crate) k: usize,
    /// Codeword size, i.e., number of columns (Note: n = 3^i - 1, for some i)
    pub(crate) n: usize,
    /// Interleaved code size, i.e., number of rows
    pub(crate) m: usize,
}

impl<Field: FieldForLigero> Params<Field> {
    /// Select parameters appropriate for a given circuit+input size.
    /// Constraints for parameter selection are given in section 5.3 of
    /// https://dl.acm.org/doi/pdf/10.1145/3133956.3134104
    pub fn new(size: usize) -> Self {
        if size == 0 {
            panic!("Empty circuits are not supported")
        }
        // XXX: There's probably a better way to select these. As it is, we
        // evaluate parameters for all appropriate 2-power/3-power pairs and
        // select the ones that minimize |l - t*m|. Since m is the cost of
        // sending interleaved-codeword columns and n is the cost of sending
        // codeword rows, this should minimize overall proof size. Evaluating
        // all parameter sets seems expensive, but in practice, there aren't
        // many to evaluate. Still, there's probably a way to do this
        // analytically.
        //
        // XXX: Since the possibilities for parameter selection are limited by
        // the field modulus and the need to perform fft2/fft3, we never
        // achieve m = sqrt(|c|). For concrete proof size, we might want to
        // prefer small rows or small columns, depending on which we're sending
        // more of.
        //
        // Have: sz, t
        // Want:
        //      k^2 >= sz
        //      k = l + t = 2^j - 1 for some j, 1 < j < PHI_2_EXP
        //      t ~ log(|Field|)
        //      n > l; n = 3^i - 1 for some i, 1 < i <= PHI_3_EXP
        //
        // Note: Using j < PHI_2_EXP, rather than j <= PHI_2_EXP, allows us
        // to multiply polynomials in O(d log d) time (see pmul2). We could
        // avoid this at the cost of some performance by using fft3 instead.
        let t = Field::FIELD_SIZE;
        let (kexp, nexp, k, l, n, m) = (0..<Field as FieldForFFT<2>>::PHI_EXP as u32)
            .map(|kexp| (kexp, 2usize.pow(kexp) - 1))
            .filter(|&(_, k)| k > t)
            .filter_map(|(kexp, k)| {
                let (nexp, n) = (0..=<Field as FieldForFFT<3>>::PHI_EXP as u32)
                    .map(|nexp| (nexp, 3usize.pow(nexp) - 1))
                    .find(|&(_, n)| n > k)?;
                let l = k - t;
                let m = (size + l - 1) / l;

                let diff = (l as isize - (t * m) as isize).abs();
                Some((diff, (kexp, nexp, k, l, n, m)))
            })
            //.map(|p| { eprintln!("{:?}", p); p })
            .min_by(|(d1, _), (d2, _)| d1.cmp(d2))
            .expect("Failed to find appropriate parameters")
            .1;

        Self {
            kexp,
            _nexp: nexp,
            k,
            t,
            l,
            n,
            m,
            pss: PackedSecretSharingGenerator::new(t, n, l, kexp as usize, nexp as usize),
        }
    }

    /// Encode a row of l field elements into a codeword row of n elements.
    pub fn encode<R>(&self, wf: ArrayView1<Field>, rng: &mut R) -> Array1<Field>
    where
        R: Rng + CryptoRng,
    {
        debug_assert_eq!(wf.len(), self.l);

        Array1::from(self.pss.share(&wf.to_vec(), rng))
    }

    /// Decode a codeword row without stripping the random elements off the end.
    // TODO make this an in-place operation?
    fn decode_no_strip(&self, cf: ArrayView1<Field>) -> Vec<Field> {
        debug_assert_eq!(cf.len(), self.n);

        let coeffs0 = concatenate!(Axis(0), Array1::zeros(1), cf);
        let points = fft::fft3_inverse(
            &coeffs0.iter().cloned().collect::<Vec<_>>(),
            self.pss.omega_shares,
        );

        fft::fft2(&points[0..=self.k], self.pss.omega_secrets())
    }

    /// Decode a codeword row of n field elements into a row of l elements.
    pub fn decode(&self, cf: ArrayView1<Field>) -> Array1<Field> {
        self.decode_no_strip(cf)[1..=self.l]
            .iter()
            .cloned()
            .collect()
    }

    /// Decode an incomplete codeword.
    ///
    /// Note: This is _slow_! Don't use it if you can avoid it.
    #[allow(dead_code)]
    fn decode_part(&self, ixs: &[usize], cf: ArrayView1<Field>) -> Array1<Field> {
        debug_assert!(cf.len() <= self.n);
        debug_assert!(cf.len() >= self.k);

        Array1::from(self.pss.reconstruct(ixs, &cf.to_vec()))
    }

    /// Check whether a codeword is in the image of the encode function by
    /// applying FFT3^-1 and checking that the final n-k elements are zeros.
    // XXX: Not sure this is sufficient to check whether this is a valid
    // codeword. Need to check the number of errors this detects, etc.
    pub fn codeword_is_valid(&self, cf: ArrayView1<Field>) -> bool {
        debug_assert_eq!(cf.len(), self.n);

        let mut coeffs0 = std::iter::once(&Field::ZERO)
            .chain(cf.iter())
            .cloned()
            .collect::<Vec<_>>();
        fft::fft3_inverse_in_place(&mut coeffs0, self.pss.omega_shares());

        let (points, zeros) = coeffs0[..].split_at_mut(self.k + 1);
        fft::fft2_in_place(points, self.pss.omega_secrets());

        points[0] == Field::ZERO && zeros.iter().all(|&f| f == Field::ZERO)
    }

    /// Encode an mXl matrix of field elements into an mXn interleaved
    /// codeword.
    pub fn encode_interleaved<R>(&self, ws: ArrayView1<Field>, rng: &mut R) -> Array2<Field>
    where
        R: Rng + CryptoRng,
    {
        debug_assert_eq!(ws.len(), self.l * self.m);

        let mut res = Vec::with_capacity(self.n * self.m);

        for w in ws.exact_chunks(self.pss.secret_count()) {
            res.append(&mut self.encode(w, rng).to_vec());
        }

        Array2::from_shape_vec((self.m, self.n), res)
            .expect("Unreachable: encoded array is wrong size")
    }

    /// Decode an mXn intereaved codeword into an mXl matrix of field elements.
    #[allow(dead_code)]
    pub fn decode_interleaved(&self, cs: ArrayView2<Field>) -> Array1<Field> {
        debug_assert_eq!(cs.shape(), [self.m, self.n]);

        let mut res = Vec::with_capacity(self.l * self.m);

        for c in 0..cs.nrows() {
            res.append(&mut self.decode(cs.row(c)).to_vec());
        }

        From::from(res)
    }

    /// Take a sequence of values `p(zeta_1) .. p(zeta_c)` for `c <= k` and
    /// return the `(k+1)`-coefficients of the polynomial `p`.
    // TODO make this an in-place operation?
    pub fn fft2_inverse(&self, points: ArrayView1<Field>) -> Array1<Field> {
        debug_assert!(points.len() <= self.k);

        let mut points0 = Array1::zeros(self.k + 1);
        points0
            .slice_mut(ndarray::s!(1..=points.len()))
            .assign(&points);

        fft::fft2_inverse(&points0.to_vec(), self.pss.omega_secrets())
            .iter()
            .cloned()
            .collect()
    }

    /// Take a sequence of `k+1` coefficients of the polynomial `p` and
    /// return evaluation points `p(zeta_1) .. p(zeta_{k})`. Note that
    /// `p(zeta_0)`, which should always be zero for our application, is
    /// not returned.
    // TODO make this an in-place operation?
    pub fn fft2(&self, coeffs: ArrayView1<Field>) -> Array1<Field> {
        debug_assert!(coeffs.len() <= self.k + 1);

        let mut coeffs0 = Array1::zeros(self.k + 1);
        coeffs0
            .slice_mut(ndarray::s!(0..coeffs.len()))
            .assign(&coeffs);

        fft::fft2(&coeffs0.to_vec(), self.pss.omega_secrets())[1..]
            .iter()
            .cloned()
            .collect()
    }

    /// Apply `fft2_inverse` to the rows of an `Array2`.
    // TODO make this an in-place operation?
    pub fn fft2_inverse_rows(&self, mat: ArrayView2<Field>) -> Array2<Field> {
        debug_assert!(mat.ncols() <= self.k);

        let mut res = Array2::zeros((mat.nrows(), self.k + 1)); // TODO use uninit for efficiency
                                                                //mat.to_owned() // TODO better if we move this argument?
                                                                //    .move_into(res.slice_mut(ndarray::s![.., 1..mat.ncols()+1]));
        res.slice_mut(ndarray::s![.., 1..mat.ncols() + 1])
            .assign(&mat);

        Zip::from(res.rows_mut()).for_each(|mut row| {
            fft::fft2_inverse_in_place(row.as_slice_mut().unwrap(), self.pss.omega_secrets());
        });

        res
    }

    /// Apply `fft2` to the rows of an `Array2`.
    // TODO make this an in-place operation?
    pub fn fft2_rows(&self, mat: ArrayView2<Field>) -> Array2<Field> {
        debug_assert!(mat.ncols() <= self.k + 1);

        let mut res = Array2::zeros((mat.nrows(), self.k + 1)); // TODO use uninit for efficiency
                                                                //mat.to_owned() // TODO better if we move this argument?
                                                                //    .move_into(res.slice_mut(ndarray::s![.., 0..mat.ncols()]));
        res.slice_mut(ndarray::s![.., 0..mat.ncols()]).assign(&mat);

        Zip::from(res.rows_mut()).for_each(|mut row| {
            fft::fft2_in_place(row.as_slice_mut().unwrap(), self.pss.omega_secrets());
        });

        res.slice(ndarray::s![.., 1..]).to_owned()
    }

    /// Take a sequence of _possibly more than_ `k+1` coefficients of the
    /// polynomial `p` and return evaluation points `p(zeta_0) .. p(zeta_{k})`.
    /// Note that _all_ `k+1` coefficients are returned
    // TODO use in-place fft?
    pub fn fft2_peval(&self, coeffs: ArrayView1<Field>) -> Array1<Field> {
        let coeffs0 = coeffs.to_vec()[..]
            .chunks(self.k + 1)
            .fold(Array1::zeros(self.k + 1), |acc, v| {
                padd(acc.view(), Array1::from(v.to_vec()).view())
            });

        fft::fft2(&coeffs0.to_vec(), self.pss.omega_secrets())
            .iter()
            .cloned()
            .collect()
    }

    /// Take a sequence of values `p(eta_1) .. p(eta_c)` for `c <= n` and
    /// return the `(n+1)`-coefficients of the polynomial `p`.
    // TODO make this an in-place operation?
    pub fn fft3_inverse(&self, points: ArrayView1<Field>) -> Array1<Field> {
        debug_assert!(points.len() <= self.n);

        let mut points0 = Array1::zeros(self.n + 1);
        points0
            .slice_mut(ndarray::s!(1..points.len() + 1))
            .assign(&points);

        fft::fft3_inverse(&points0.to_vec(), self.pss.omega_shares())
            .iter()
            .cloned()
            .collect()
    }

    /// Take a sequence of `n+1` coefficients of the polynomial `p` and
    /// return evaluation points `p(eta_1) .. p(eta_{n})`. Note that
    /// `p(eta_0)`, which should always be zero for our application, is
    /// not returned.
    // TODO make this an in-place operation?
    pub fn fft3(&self, coeffs: ArrayView1<Field>) -> Array1<Field> {
        debug_assert!(coeffs.len() <= self.n + 1);

        let mut coeffs0 = Array1::zeros(self.n + 1);
        coeffs0
            .slice_mut(ndarray::s!(0..coeffs.len()))
            .assign(&coeffs);

        fft::fft3(&coeffs0.to_vec(), self.pss.omega_shares())[1..]
            .iter()
            .cloned()
            .collect()
    }

    /// Apply `fft3_inverse` to the rows of an `Array2`.
    // TODO make this an in-place operation?
    pub fn fft3_inverse_rows(&self, mat: ArrayView2<Field>) -> Array2<Field> {
        debug_assert!(mat.ncols() <= self.n);

        let mut res = Array2::zeros((mat.nrows(), self.n + 1)); // TODO use uninit for efficiency
                                                                //mat.to_owned() // TODO better if we move this argument?
                                                                //    .move_into(res.slice_mut(ndarray::s![.., 1..mat.ncols()+1]));
        res.slice_mut(ndarray::s![.., 1..mat.ncols() + 1])
            .assign(&mat);

        Zip::from(res.rows_mut()).for_each(|mut row| {
            fft::fft3_inverse_in_place(row.as_slice_mut().unwrap(), self.pss.omega_shares());
        });

        res
    }

    /// Apply `fft3` to the rows of an `Array2`.
    // TODO make this an in-place operation?
    pub fn fft3_rows(&self, mat: ArrayView2<Field>) -> Array2<Field> {
        debug_assert!(mat.ncols() <= self.n + 1);

        let mut res = Array2::zeros((mat.nrows(), self.n + 1)); // TODO use uninit for efficiency
                                                                //mat.to_owned() // TODO better if we move this argument?
                                                                //    .move_into(res.slice_mut(ndarray::s![.., 0..mat.ncols()]));
        res.slice_mut(ndarray::s![.., 0..mat.ncols()]).assign(&mat);

        Zip::from(res.rows_mut()).for_each(|mut row| {
            fft::fft3_in_place(row.as_slice_mut().unwrap(), self.pss.omega_shares());
        });

        res.slice(ndarray::s![.., 1..]).to_owned()
    }

    /// Take a sequence of _possibly more than_ `n+1` coefficients of the
    /// polynomial `p` and return evaluation points `p(eta_0) .. p(eta_{n})`.
    /// Note that _all_ `n+1` coefficients are returned
    pub fn fft3_peval(&self, coeffs: ArrayView1<Field>) -> Array1<Field> {
        let coeffs0 = coeffs.to_vec()[..]
            .chunks(self.n + 1)
            .fold(Array1::zeros(self.n + 1), |acc, v| {
                padd(acc.view(), Array1::from(v.to_vec()).view())
            });

        fft::fft3(&coeffs0.to_vec(), self.pss.omega_shares())
            .iter()
            .cloned()
            .collect()
    }

    /// Take a sequence of _possibly more than_ `k+1` coefficients of the
    /// polynomial `p` and return the single evaluation point `p(zeta_{ix})`.
    pub fn peval2(&self, p: ArrayView1<Field>, ix: usize) -> Field {
        let poly = Polynomial::from(&p.to_vec()[..]);
        poly.eval(self.pss.omega_secrets().pow(ix as u128))
    }

    /// Take a sequence of _possibly more than_ `n+1` coefficients of the
    /// polynomial `p` and return the single evaluation point `p(eta_{ix})`.
    pub fn peval3(&self, p: ArrayView1<Field>, ix: usize) -> Field {
        let poly = Polynomial::from(&p.to_vec()[..]);
        poly.eval(self.pss.omega_shares().pow(ix as u128))
    }

    /// Take two polynomials p and q of degree less than 2^kexp and produce a
    /// polynomial s of degree less than 2^(kexp+1)-1 s.t. s(.) = p(.) * q(.).
    /// This takes `n*log(n)` time, as opposed to the `n^2` naive algorithm.
    pub fn pmul2(&self, p: ArrayView1<Field>, q: ArrayView1<Field>) -> Array1<Field> {
        debug_assert!(p.len() <= 2usize.pow(self.kexp));
        debug_assert!(q.len() <= 2usize.pow(self.kexp));

        let p_deg = p.len();
        let q_deg = q.len();

        let max_deg = 2usize.pow(self.kexp + 1);
        let pq_deg = p_deg + q_deg - 1;
        let omega = <Field as FieldForFFT<2>>::roots(self.kexp as usize + 1);

        let mut p0 = p
            .iter()
            .chain(std::iter::repeat(&Field::ZERO).take(max_deg - p_deg))
            .cloned()
            .collect::<Array1<_>>();
        let mut q0 = q
            .iter()
            .chain(std::iter::repeat(&Field::ZERO).take(max_deg - q_deg))
            .cloned()
            .collect::<Array1<_>>();

        // Use in-place fft to avoid allocating any more Vecs.
        fft::fft2_in_place(p0.as_slice_mut().unwrap(), omega);
        fft::fft2_in_place(q0.as_slice_mut().unwrap(), omega);
        for i in 0..max_deg {
            p0[i] *= q0[i]
        }
        fft::fft2_inverse_in_place(p0.as_slice_mut().unwrap(), omega);

        p0.slice_move(ndarray::s![0..pq_deg])
    }

    /// Return a random size-t subset of `[n]`.
    #[allow(non_snake_case)]
    pub fn random_indices<R>(&self, rng: &mut R) -> Vec<usize>
    where
        R: Rng + CryptoRng,
    {
        use rand::seq::SliceRandom;

        let mut Q = (0..self.n).collect::<Vec<usize>>();
        Q.shuffle(rng);
        Q.truncate(self.t);

        Q
    }

    /// Return a random valid codeword.
    pub fn random_codeword<R>(&self, rng: &mut R) -> Array1<Field>
    where
        R: Rng + CryptoRng,
    {
        self.encode(
            Array1::from_shape_fn(self.l, |_| Field::random(rng)).view(),
            rng,
        )
    }

    /// Return a valid codeword for `0^l`.
    pub fn random_zero_codeword<R>(&self, rng: &mut R) -> Array1<Field>
    where
        R: Rng + CryptoRng,
    {
        debug_assert_ne!(self.l, 0);

        let mut w = Array1::from_shape_fn(self.l, |_| Field::random(rng));
        let sum = w.sum();
        w[self.l - 1] -= sum;

        self.encode(w.view(), rng)
    }
}

#[cfg(test)]
use {
    proptest::{collection::vec as pvec, prelude::*, *},
    rand::prelude::{SeedableRng, StdRng},
    scuttlebutt::ring::FiniteRing,
};

#[cfg(test)]
impl Arbitrary for Params<TestField> {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        (1usize..100)
            .prop_flat_map(|size| Just(Self::new(size)))
            .boxed()
    }
}

#[cfg(test)]
proptest! {
    #[test]
    fn test_new_params_props(s in 1usize .. 200000) {
        let p: Params<TestField> = Params::new(s);

        prop_assert_eq!(2usize.pow(p.kexp), p.k + 1);
        prop_assert_eq!(3usize.pow(p._nexp), p.n + 1);
        prop_assert_eq!(p.l + p.t, p.k);
        prop_assert!(p.k <= p.n);
        prop_assert!(p.l * p.m >= s);
        prop_assert!(p.m > 0);
        prop_assert!(p.l > 0);
    }

    #[test]
    fn test_fft2_inverse(
        (p, len, v) in any::<Params<TestField>>()
            .prop_flat_map(|p| (Just(p), 1 ..= p.l))
            .prop_flat_map(|(p, len)| (Just(p), Just(len), pvec(arb_test_field(), len)))
    ) {
        let mut a = std::iter::once(TestField::ZERO)
            .chain(v)
            .chain(std::iter::repeat(TestField::ZERO).take(p.k - len))
            .collect::<Array1<_>>();
        prop_assert_eq!(a.len(), p.k + 1);

        let coeffs = p.fft2_inverse(a.slice(ndarray::s![1..=len]));

        fft::fft2_inverse_in_place(a.as_slice_mut().unwrap(), p.pss.omega_secrets);
        let coeffs_ref = a;

        prop_assert_eq!(coeffs.len(), coeffs_ref.len());
        prop_assert_eq!(coeffs, coeffs_ref);
    }

    #[test]
    fn test_fft2(
        (p, len, v) in any::<Params<TestField>>()
            .prop_flat_map(|p| (Just(p), 1 ..= p.l+1))
            .prop_flat_map(|(p, len)| (Just(p), Just(len), pvec(arb_test_field(), len)))
    ) {
        let mut a = v.into_iter()
            .chain(std::iter::repeat(TestField::ZERO).take(p.k+1 - len))
            .collect::<Array1<_>>();
        prop_assert_eq!(a.len(), p.k + 1);

        let points = p.fft2(a.slice(ndarray::s![0..len]));

        fft::fft2_in_place(a.as_slice_mut().unwrap(), p.pss.omega_secrets);
        let points_ref = a.slice(ndarray::s![1..]);

        prop_assert_eq!(points.len(), points_ref.len());
        prop_assert_eq!(points, points_ref);
    }

    #[test]
    fn test_fft2_inverse_rows(
        (p, len, v1, v2) in any::<Params<TestField>>()
            .prop_flat_map(|p| (Just(p), 1 ..= p.k))
            .prop_flat_map(|(p, len)| (
                    Just(p),
                    Just(len),
                    pvec(arb_test_field(), len),
                    pvec(arb_test_field(), len),
            ))
    ) {
        use ndarray::{stack, s};

        let mut a1 = std::iter::once(TestField::ZERO)
            .chain(v1)
            .chain(std::iter::repeat(TestField::ZERO).take(p.k - len))
            .collect::<Array1<_>>();
        prop_assert_eq!(a1.len(), p.k + 1);
        let mut a2 = std::iter::once(TestField::ZERO)
            .chain(v2)
            .chain(std::iter::repeat(TestField::ZERO).take(p.k - len))
            .collect::<Array1<_>>();
        prop_assert_eq!(a2.len(), p.k + 1);
        let points = stack(Axis(0), &[a1.slice(s![1..=len]), a2.slice(s![1..=len])]).unwrap();

        let coeffs = p.fft2_inverse_rows(points.view());

        fft::fft2_inverse_in_place(a1.as_slice_mut().unwrap(), p.pss.omega_secrets);
        fft::fft2_inverse_in_place(a2.as_slice_mut().unwrap(), p.pss.omega_secrets);
        let coeffs_ref = ndarray::stack(Axis(0), &[a1.view(), a2.view()]).unwrap();

        prop_assert_eq!(coeffs.dim(), coeffs_ref.dim());
        prop_assert_eq!(coeffs, coeffs_ref);
    }

    #[test]
    fn test_fft2_rows(
        (p, len, v1, v2) in any::<Params<TestField>>()
            .prop_flat_map(|p| (Just(p), 1 ..= p.l+1))
            .prop_flat_map(|(p, len)| (
                    Just(p),
                    Just(len),
                    pvec(arb_test_field(), len),
                    pvec(arb_test_field(), len),
            ))
    ) {
        let mut a1 = v1.into_iter()
            .chain(std::iter::repeat(TestField::ZERO).take(p.k+1 - len))
            .collect::<Array1<_>>();
        prop_assert_eq!(a1.len(), p.k + 1);
        let mut a2 = v2.into_iter()
            .chain(std::iter::repeat(TestField::ZERO).take(p.k+1 - len))
            .collect::<Array1<_>>();
        prop_assert_eq!(a1.len(), p.k + 1);
        let coeffs = ndarray::stack(Axis(0), &[a1.view(), a2.view()]).unwrap();

        let points = p.fft2_rows(coeffs.view());

        fft::fft2_in_place(a1.as_slice_mut().unwrap(), p.pss.omega_secrets);
        fft::fft2_in_place(a2.as_slice_mut().unwrap(), p.pss.omega_secrets);
        let points_ref0 = ndarray::stack(Axis(0), &[a1.view(), a2.view()]).unwrap();
        let points_ref = points_ref0.slice(ndarray::s![.., 1..]);

        prop_assert_eq!(points.dim(), points_ref.dim());
        prop_assert_eq!(points, points_ref);
    }

    #[test]
    fn test_fft3_inverse(
        (p, len, v) in any::<Params<TestField>>()
            .prop_flat_map(|p| (Just(p), 1 ..= p.n))
            .prop_flat_map(|(p, len)| (Just(p), Just(len), pvec(arb_test_field(), len)))
    ) {
        let mut a = std::iter::once(TestField::ZERO)
            .chain(v)
            .chain(std::iter::repeat(TestField::ZERO).take(p.n - len))
            .collect::<Array1<_>>();
        prop_assert_eq!(a.len(), p.n + 1);

        let coeffs = p.fft3_inverse(a.slice(ndarray::s![1..=len]));

        fft::fft3_inverse_in_place(a.as_slice_mut().unwrap(), p.pss.omega_shares);
        let coeffs_ref = a;

        prop_assert_eq!(coeffs.len(), coeffs_ref.len());
        prop_assert_eq!(coeffs, coeffs_ref);
    }

    #[test]
    fn test_fft3(
        (p, len, v) in any::<Params<TestField>>()
            .prop_flat_map(|p| (Just(p), 1 ..= p.n+1))
            .prop_flat_map(|(p, len)| (Just(p), Just(len), pvec(arb_test_field(), len)))
    ) {
        let mut a = v.into_iter()
            .chain(std::iter::repeat(TestField::ZERO).take(p.n+1 - len))
            .collect::<Array1<_>>();
        prop_assert_eq!(a.len(), p.n + 1);

        let points = p.fft3(a.slice(ndarray::s![0..len]));

        fft::fft3_in_place(a.as_slice_mut().unwrap(), p.pss.omega_shares);
        let points_ref = a.slice(ndarray::s![1..]);

        prop_assert_eq!(points.len(), points_ref.len());
        prop_assert_eq!(points, points_ref);
    }

    #[test]
    fn test_fft3_inverse_rows(
        (p, len, v1, v2) in any::<Params<TestField>>()
            .prop_flat_map(|p| (Just(p), 1 ..= p.n))
            .prop_flat_map(|(p, len)| (
                    Just(p),
                    Just(len),
                    pvec(arb_test_field(), len),
                    pvec(arb_test_field(), len),
            ))
    ) {
        use ndarray::{stack, s};

        let mut a1 = std::iter::once(TestField::ZERO)
            .chain(v1)
            .chain(std::iter::repeat(TestField::ZERO).take(p.n - len))
            .collect::<Array1<_>>();
        prop_assert_eq!(a1.len(), p.n + 1);
        let mut a2 = std::iter::once(TestField::ZERO)
            .chain(v2)
            .chain(std::iter::repeat(TestField::ZERO).take(p.n - len))
            .collect::<Array1<_>>();
        prop_assert_eq!(a2.len(), p.n + 1);
        let points = stack(Axis(0), &[a1.slice(s![1..=len]), a2.slice(s![1..=len])]).unwrap();

        let coeffs = p.fft3_inverse_rows(points.view());

        fft::fft3_inverse_in_place(a1.as_slice_mut().unwrap(), p.pss.omega_shares);
        fft::fft3_inverse_in_place(a2.as_slice_mut().unwrap(), p.pss.omega_shares);
        let coeffs_ref = ndarray::stack(Axis(0), &[a1.view(), a2.view()]).unwrap();

        prop_assert_eq!(coeffs.dim(), coeffs_ref.dim());
        prop_assert_eq!(coeffs, coeffs_ref);
    }

    #[test]
    fn test_fft3_rows(
        (p, len, v1, v2) in any::<Params<TestField>>()
            .prop_flat_map(|p| (Just(p), 1 ..= p.n+1))
            .prop_flat_map(|(p, len)| (
                    Just(p),
                    Just(len),
                    pvec(arb_test_field(), len),
                    pvec(arb_test_field(), len),
            ))
    ) {
        let mut a1 = v1.into_iter()
            .chain(std::iter::repeat(TestField::ZERO).take(p.n+1 - len))
            .collect::<Array1<_>>();
        prop_assert_eq!(a1.len(), p.n + 1);
        let mut a2 = v2.into_iter()
            .chain(std::iter::repeat(TestField::ZERO).take(p.n+1 - len))
            .collect::<Array1<_>>();
        prop_assert_eq!(a1.len(), p.n + 1);
        let coeffs = ndarray::stack(Axis(0), &[a1.view(), a2.view()]).unwrap();

        let points = p.fft3_rows(coeffs.view());

        fft::fft3_in_place(a1.as_slice_mut().unwrap(), p.pss.omega_shares);
        fft::fft3_in_place(a2.as_slice_mut().unwrap(), p.pss.omega_shares);
        let points_ref0 = ndarray::stack(Axis(0), &[a1.view(), a2.view()]).unwrap();
        let points_ref = points_ref0.slice(ndarray::s![.., 1..]);

        prop_assert_eq!(points.dim(), points_ref.dim());
        prop_assert_eq!(points, points_ref);
    }

    #[test]
    fn test_decode_encode(
        (p,v) in any::<Params<TestField>>().prop_flat_map(|p| {
            let v = pvec(arb_test_field(), p.l);
            (Just(p), v)
        })
    ) {
        let mut rng = StdRng::seed_from_u64(0);

        let ve = p.encode(ArrayView1::from(&v), &mut rng);
        let vd = p.decode(ve.view()).to_vec();

        prop_assert_eq!(vd, v);
    }

    #[test]
    fn test_codeword_is_valid_accepts_valid(
        (p,v) in any::<Params<TestField>>().prop_flat_map(|p| {
            let v = pvec(arb_test_field(), p.l);
            (Just(p), v)
        })
    ) {
        let mut rng = StdRng::seed_from_u64(0);

        let ve = p.encode(Array1::from(v).view(), &mut rng);

        prop_assert!(p.codeword_is_valid(ve.view()));
    }

    #[test]
    fn test_codeword_is_valid_detects_invalid(
        (p,v,ix) in any::<Params<TestField>>().prop_flat_map(|p| {
            let v = pvec(arb_test_field(), p.l);
            let ix = 0..p.l;
            (Just(p), v, ix)
        })
    ) {
        let mut rng = StdRng::seed_from_u64(0);

        let mut ve = p.encode(Array1::from(v).view(), &mut rng);
        ve[ix] += TestField::ONE;

        prop_assert!(!p.codeword_is_valid(ve.view()));
    }

    #[test]
    fn test_codeword_is_valid_accepts_sum(
        (p,v) in any::<Params<TestField>>().prop_flat_map(|p| {
            let v = pvec(arb_test_field(), p.m * p.l);
            (Just(p), v)
        })
    ) {
        let mut rng = StdRng::seed_from_u64(0);

        let ve = p.encode_interleaved(Array1::from(v).view(), &mut rng);
        let vs = ve.rows().into_iter()
            .fold(Array1::zeros(p.n), |acc, row| acc + row);

        prop_assert!(p.codeword_is_valid(vs.view()));
    }

    #[test]
    fn test_codeword_is_valid_detects_invalid_sum(
        (p,v,r,c) in any::<Params<TestField>>().prop_flat_map(|p| {
            let v = pvec(arb_test_field(), p.m * p.l);
            let r = 0..p.m;
            let c = 0..p.l;
            (Just(p), v, r, c)
        })
    ) {
        let mut rng = StdRng::seed_from_u64(0);

        let mut ve = p.encode_interleaved(Array1::from(v).view(), &mut rng);
        ve[(r,c)] += TestField::ONE;

        let vs = ve.rows().into_iter()
            .fold(Array1::zeros(p.n), |acc, row| acc + row);

        prop_assert!(!p.codeword_is_valid(vs.view()));
    }

    #[test]
    fn test_peval2(
        (p,v) in any::<Params<TestField>>().prop_flat_map(|p| {
            let v = pvec(arb_test_field(), p.k + 1);
            (Just(p), v)
        })
    ) {
        let v_coeffs = fft::fft2_inverse(
            &v,
            p.pss.omega_secrets,
        ).iter().cloned().map(TestField::from)
            .collect::<Array1<TestField>>();

        for i in 0 .. v.len() {
            prop_assert_eq!(
                p.peval2(v_coeffs.view(), i),
                v[i]
            );
        }
    }

    #[test]
    fn test_fft2_peval(
        (p,v) in any::<Params<TestField>>().prop_flat_map(|p| {
            (1 ..= 3*(p.k+1)).prop_flat_map(move |len| {
                let v = pvec(arb_test_field(), len);
                (Just(p), v)
            })
        })
    ) {
        let v_coeffs = Array1::from(v);
        let v_points = p.fft2_peval(v_coeffs.view());

        for i in 0 .. v_points.len() {
            prop_assert_eq!(v_points[i], p.peval2(v_coeffs.view(), i));
        }
    }

    #[test]
    fn test_peval3(
        (p,v) in any::<Params<TestField>>().prop_flat_map(|p| {
            let v = pvec(arb_test_field(), p.n + 1);
            (Just(p), v)
        })
    ) {
        let v_coeffs = fft::fft3_inverse(
            &v,
            p.pss.omega_shares,
        ).iter().cloned().map(TestField::from)
            .collect::<Array1<TestField>>();

        for i in 0 .. v.len() {
            prop_assert_eq!(p.peval3(v_coeffs.view(), i), v[i]);
        }
    }

    #[test]
    fn test_fft3_peval(
        (p,v) in any::<Params<TestField>>().prop_flat_map(|p| {
            (1 ..= 3*(p.n+1)).prop_flat_map(move |len| {
                let v = pvec(arb_test_field(), len);
                (Just(p), v)
            })
        })
    ) {
        let v_coeffs = Array1::from(v);
        let v_points = p.fft3_peval(v_coeffs.view());

        for i in 0 .. v_points.len() {
            prop_assert_eq!(v_points[i], p.peval3(v_coeffs.view(), i));
        }
    }

    #[test]
    fn test_pmul2(
        (p, u, v) in any::<Params<TestField>>().prop_flat_map(|p| {
            (1..=p.k+1, 1..=p.k+1).prop_flat_map(move |(ulen, vlen)| {
                let u_coeffs = pvec(arb_test_field(), ulen);
                let v_coeffs = pvec(arb_test_field(), vlen);
                (Just(p), u_coeffs, v_coeffs)
            })
        })
    ) {
        let u_coeffs = Array1::from(u);
        let v_coeffs = Array1::from(v);
        let uv_coeffs = p.pmul2(u_coeffs.view(), v_coeffs.view());

        for i in 0 .. p.n {
            prop_assert_eq!(
                p.peval3(uv_coeffs.view(), i),
                p.peval3(ArrayView1::from(&u_coeffs), i)
                    * p.peval3(ArrayView1::from(&v_coeffs), i)
            );
        }
    }

    #[test]
    fn test_padd(
        (p, u, v) in any::<Params<TestField>>().prop_flat_map(|p| {
            (1..=p.k+1, 1..=p.k+1).prop_flat_map(move |(ulen, vlen)| {
                let u_coeffs = pvec(arb_test_field(), ulen);
                let v_coeffs = pvec(arb_test_field(), vlen);
                (Just(p), u_coeffs, v_coeffs)
            })
        })
    ) {
        let u_coeffs = Array1::from(u);
        let v_coeffs = Array1::from(v);
        let uv_coeffs = padd(u_coeffs.view(), v_coeffs.view());

        for i in 0 .. p.n {
            prop_assert_eq!(
                p.peval3(uv_coeffs.view(), i),
                p.peval3(ArrayView1::from(&u_coeffs), i)
                    + p.peval3(ArrayView1::from(&v_coeffs), i)
            );
        }
    }

    #[test]
    fn test_psub(
        (p, u, v) in any::<Params<TestField>>().prop_flat_map(|p| {
            (1..=p.k+1, 1..=p.k+1).prop_flat_map(move |(ulen, vlen)| {
                let u_coeffs = pvec(arb_test_field(), ulen);
                let v_coeffs = pvec(arb_test_field(), vlen);
                (Just(p), u_coeffs, v_coeffs)
            })
        })
    ) {
        let u_coeffs = Array1::from(u);
        let v_coeffs = Array1::from(v);
        let uv_coeffs = psub(u_coeffs.view(), v_coeffs.view());

        for i in 0 .. p.n {
            prop_assert_eq!(
                p.peval3(uv_coeffs.view(), i),
                p.peval3(ArrayView1::from(&u_coeffs), i)
                    - p.peval3(ArrayView1::from(&v_coeffs), i)
            );
        }
    }

    #[test]
    fn test_random_zero_codeword(p in any::<Params<TestField>>()) {
        use rand::{SeedableRng, rngs::StdRng};

        let c = p.random_zero_codeword(&mut StdRng::from_entropy());
        let w = p.decode(c.view());

        prop_assert_eq!(w.sum(), TestField::ZERO);
    }
}
