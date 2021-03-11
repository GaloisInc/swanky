use threshold_secret_sharing::packed::PackedSecretSharing as PSS;
use ndarray::{Array1, Array2, ArrayView1, ArrayView2};

#[cfg(test)]
use proptest::{*, prelude::*, collection::vec as pvec};

use crate::util::*;

//
// XXX: Use a silly field for now.
//
type Field = crate::f2_19x3_26::F;

// Parameters for interleaved coding, based on the size of the circuit and
// input. Note that these variable names, although terse, correspond to those
// used in https://acmccs.github.io/papers/p2087-amesA.pdf.
//
// We fix the security threshold t = log |F| to get the following soundness
// errors, where e is a positive integer with e < d/4, d is the code distance,
// and n = 2^p:
//
// * Test-Interleaved:             (1 - e/n)^t + (e + 1)/|F|
//                               = (1 - e/|F|)^p + (e + 1)/|F|
// * Test-Linear-Constraints:      ((e + k + l)/n)^t + 1/|F|
//                               = ((e + k + l)/|F|)^p + 1/|F|
// * Test-Quadratic-Constraints:   ((e + 2k)/n)^t + 1/|F|
//                               = ((e + 2k)/|F|)^p + 1/|F|
//
// I.e., we ensure soundness error is negligible in the field size.
// XXX: Is this right? Seems like t could be smaller, say ceil(log |F| / p).
#[derive(Debug, Clone, Copy)]
pub struct Params {
    pub pss: PSS, // Share-packing parameters

    pub kexp: u32,  // log2(k)
    pub nexp: u32,  // log3(n)

    pub l: usize,   // Message size (Note: k = l + t = 2^j - 1, for some j)
    pub t: usize,   // Security threshold
    pub k: usize,   // Reconstruction threshold
    pub n: usize,   // Codeword size (Note: n = 3^i - 1, for some i)
    pub m: usize,   // Interleaved code size
}

impl Params {
    pub fn new(size: usize) -> Self {
        if size == 0 { panic!("Empty circuits are not supported") }
        // XXX: There's probably a better way to select these. As it is, we
        // evaluate parameters for all appropriate 2-power/3-power pairs and
        // select the ones that minimize |n - m|. Since m is the cost of
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
        //      k = l + t = 2^j - 1 for some j, 1 < j <= PHI_2_EXP
        //      t ~ log(|Field|)
        //      n > l; n = 3^i - 1 for some i, 1 < i <= PHI_3_EXP
        let t = Field::BITS;
        let (kexp, nexp, k, l, n, m) = (0 ..= Field::PHI_2_EXP as u32)
            .into_iter()
            .map(|kexp| (kexp, 2usize.pow(kexp) - 1))
            .filter(|&(_,k)| k as usize > t)
            .filter_map(|(kexp, k)| {
                let (nexp, n) = (0 ..= Field::PHI_3_EXP as u32)
                    .into_iter()
                    .map(|nexp| (nexp, 3usize.pow(nexp) - 1))
                    .find(|&(_,n)| n as usize > k)?;
                let l = k - t;
                let m = (size + l - 1) / l;

                let diff = (n as isize - m as isize).abs();
                Some((diff, (kexp, nexp, k, l, n, m)))
            })
            //.map(|p| { eprintln!("{:?}", p); p })
            .min_by(|(d1,_), (d2,_)| d1.cmp(d2))
            .expect("Failed to find appropriate parameters")
            .1;

        Self { kexp, nexp, k, t, l, n, m,
            pss: PSS {
                threshold: t,
                share_count: n,
                secret_count: l,

                prime: Field::MOD,
                omega_secrets: Field::ROOTS_BASE_2[kexp as usize] as i128,
                omega_shares: Field::ROOTS_BASE_3[nexp as usize] as i128,
            }
        }
    }

    //
    // XXX: In the following, can we eliminate some of the copies?
    //

    #[inline]
    fn encode(&self, wf: ArrayView1<Field>) -> Array1<Field> {
        debug_assert_eq!(wf.len(), self.l);

        let w: Vec<i128> = wf.iter().cloned().map(i128::from).collect();
        let c: Vec<i128> = self.pss.share(&w);

        c.iter().cloned().map(Field::from).collect()
    }

    #[inline]
    fn decode(&self, cf: ArrayView1<Field>) -> Array1<Field> {
        debug_assert_eq!(cf.len(), self.n);

        let c: Vec<i128> = cf.iter().take(self.k).cloned().map(i128::from).collect();
        let ixs: Vec<usize> = (0 .. self.k).collect();
        let w: Vec<i128> = self.pss.reconstruct(&ixs, &c);

        w.iter().cloned().map(Field::from).collect()
    }

    #[inline]
    fn decode_part(&self,
        ixs: &[usize],
        cf: ArrayView1<Field>,
    ) -> Array1<Field> {
        debug_assert!(cf.len() <= self.n);
        debug_assert!(cf.len() >= self.k);

        let c: Vec<i128> = cf.iter().cloned().map(i128::from).collect();
        let w: Vec<i128> = self.pss.reconstruct(ixs, &c);

        w.iter().cloned().map(Field::from).collect()
    }

    #[inline]
    pub fn codeword_is_valid(&self, ce: ArrayView1<Field>) -> bool {
        debug_assert_eq!(ce.len(), self.n);

        use ndarray::s;
        let cd0 = self.decode_part(
            &(0 .. self.k).collect::<Vec<usize>>(),
            ce.slice(s![0 .. self.k]).view(),
        );
        let cd1 = self.decode_part(
            &(self.n - self.k .. self.n).collect::<Vec<usize>>(),
            ce.slice(s![self.n - self.k .. self.n]).view(),
        );

        // XXX: I think this is necessary for c to be a codeword. Is it
        // sufficient?
        cd0 == cd1
    }

    pub fn encode_interleaved(&self, ws: ArrayView1<Field>) -> Array2<Field> {
        debug_assert_eq!(ws.len(), self.l * self.m);

        let mut res = Vec::with_capacity(self.n * self.m);

        for w in ws.exact_chunks(self.pss.secret_count) {
            res.append(&mut self.encode(w).to_vec());
        }

        Array2::from_shape_vec((self.m, self.n), res)
            .expect("Unreachable: encoded array is wrong size")
    }

    #[allow(dead_code)]
    pub fn decode_interleaved(&self, cs: ArrayView2<Field>) -> Array1<Field> {
        debug_assert_eq!(cs.shape(), [self.m, self.n]);

        let mut res = Vec::with_capacity(self.l * self.m);

        for c in 0 .. cs.nrows() {
            res.append(&mut self.decode(cs.row(c)).to_vec());
        }

        From::from(res)
    }

    // Take a sequence of values `p(zeta_1) .. p(zeta_c)` for `c <= k` and
    // return the `(k+1)`-coefficients of the polynomial `p`.
    pub fn fft2_inverse(&self, points: ArrayView1<Field>) -> Array1<Field> {
        debug_assert!(points.len() <= self.k);

        let mut points0 = Array1::zeros(self.k + 1);
        points0.slice_mut(ndarray::s!(1 .. points.len()+1)).assign(&points);

        threshold_secret_sharing::numtheory::fft2_inverse(
            &points0.iter().cloned().map(i128::from).collect::<Vec<i128>>(),
            self.pss.omega_secrets,
            self.pss.prime,
        ).iter().cloned().map(Field::from).collect::<Array1<Field>>()
    }

    // Take a sequence of `k+1` coefficients of the polynomial `p` and
    // return evaluation points `p(zeta_0) .. p(zeta_{k+1})`.
    #[allow(dead_code)]
    pub fn fft2(&self, coeffs: ArrayView1<Field>) -> Array1<Field> {
        debug_assert!(coeffs.len() <= self.k+1);

        let mut coeffs0 = Array1::zeros(self.k + 1);
        coeffs0.slice_mut(ndarray::s!(0 .. coeffs.len())).assign(&coeffs);

        threshold_secret_sharing::numtheory::fft2(
            &coeffs0.iter().cloned().map(i128::from).collect::<Vec<i128>>(),
            self.pss.omega_secrets,
            self.pss.prime,
        )[1..].iter().cloned().map(Field::from).collect::<Array1<Field>>()
    }

    // Take a sequence of values `p(eta_1) .. p(eta_c)` for `c <= n` and
    // return the `(n+1)`-coefficients of the polynomial `p`.
    pub fn fft3_inverse(&self, points: ArrayView1<Field>) -> Array1<Field> {
        debug_assert!(points.len() <= self.n);

        let mut points0 = Array1::zeros(self.n + 1);
        points0.slice_mut(ndarray::s!(1 .. points.len()+1)).assign(&points);

        threshold_secret_sharing::numtheory::fft3_inverse(
            &points0.iter().cloned().map(i128::from).collect::<Vec<i128>>(),
            self.pss.omega_shares,
            self.pss.prime,
        ).iter().cloned().map(Field::from).collect::<Array1<Field>>()
    }

    // Take a sequence of `n+1` coefficients of the polynomial `p` and
    // return evaluation points `p(eta_0) .. p(eta_{n+1})`.
    #[allow(dead_code)]
    pub fn fft3(&self, coeffs: ArrayView1<Field>) -> Array1<Field> {
        debug_assert!(coeffs.len() <= self.n);

        let mut coeffs0 = Array1::zeros(self.n + 1);
        coeffs0.slice_mut(ndarray::s!(0 .. coeffs.len())).assign(&coeffs);

        threshold_secret_sharing::numtheory::fft3(
            &coeffs0.iter().cloned().map(i128::from).collect::<Vec<i128>>(),
            self.pss.omega_shares,
            self.pss.prime,
        )[1..].iter().cloned().map(Field::from).collect::<Array1<Field>>()
    }

    pub fn peval2(&self, p: ArrayView1<Field>, ix: usize) -> Field {
        crate::util::peval(p, Field::from(self.pss.omega_secrets).pow(ix as i128))
    }

    pub fn peval3(&self, p: ArrayView1<Field>, ix: usize) -> Field {
        crate::util::peval(p, Field::from(self.pss.omega_shares).pow(ix as i128))
    }

    #[allow(non_snake_case)]
    pub fn peval3_rows_at(&self,
        p: ArrayView2<Field>,
        Q: &Vec<usize>,
    ) -> Vec<Array1<Field>> {
        Q.iter().map(|j| {
            p.genrows()
                .into_iter()
                .map(|pi| {
                    self.peval3(pi.view(), j+1)
                })
                .collect()
        }).collect()
    }

    #[allow(non_snake_case)]
    pub fn codeword_to_coeffs(&self,
        U: ArrayView2<Field>,
        size: usize,
    ) -> Array2<Field> {
        let mut p = Array2::zeros((self.m, size));

        ndarray::Zip::from(p.genrows_mut())
            .and(U.genrows())
            .apply(|mut pi0, Ui| {
                let pi = self.fft3_inverse(Ui.view());
                pi0.assign(&pad_or_unpad(pi.view(), size));
            });

        p
    }

    pub fn word_to_coeffs(&self, w: ArrayView1<Field>) -> Array2<Field> {
        let mut p = Array2::zeros((self.m, self.k+1));

        ndarray::Zip::from(p.genrows_mut())
            .and(w.exact_chunks(self.l))
            .apply(|mut pi0, wi| {
                pi0.assign(&self.fft2_inverse(wi.view()));
            });

        p
    }
}

#[cfg(test)]
impl Arbitrary for Params {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        (1usize .. 500).prop_flat_map(|size| Just(Self::new(size))).boxed()
    }
}

#[test]
fn test_new_params() {
    let csize = (2usize.pow(9) - 1 - Field::BITS) * (3usize.pow(6) - 1);
    let p = Params::new(csize);

    assert_eq!(p.t, Field::BITS);
    assert_eq!(p.kexp, 9);
    assert_eq!(p.nexp, 6);
    assert_eq!(p.n, 3usize.pow(6) - 1);
    assert_eq!(p.m, 3usize.pow(6) - 1);
    assert_eq!(p.k, 2usize.pow(9) - 1);
    assert_eq!(p.l, 2usize.pow(9) - 1 - Field::BITS);
}

#[cfg(test)]
proptest! {
    #[test]
    fn test_new_params_props(s in 1usize .. 200000) {
        let p = Params::new(s);

        prop_assert_eq!(2usize.pow(p.kexp), p.k + 1);
        prop_assert_eq!(3usize.pow(p.nexp), p.n + 1);
        prop_assert_eq!(p.l + p.t, p.k);
        prop_assert!(p.k <= p.n);
        prop_assert!(p.l * p.m >= s);
        prop_assert!(p.m > 0);
        prop_assert!(p.l > 0);
    }

    #[test]
    fn test_decode_encode(
        (p,v) in any::<Params>().prop_flat_map(|p| {
            let v = pvec(any::<Field>(), p.l);
            (Just(p), v)
        })
    ) {
        let ve = p.encode(ArrayView1::from(&v));
        let vd = p.decode(ve.view()).to_vec();

        prop_assert_eq!(vd, v);
    }

    #[test]
    fn test_codeword_is_valid_accepts_valid(
        (p,v) in any::<Params>().prop_flat_map(|p| {
            let v = pvec(any::<Field>(), p.l);
            (Just(p), v)
        })
    ) {
        let ve = p.encode(Array1::from(v).view());

        prop_assert!(p.codeword_is_valid(ve.view()));
    }

    #[test]
    fn test_codeword_is_valid_detects_invalid(
        (p,v,ix) in any::<Params>().prop_flat_map(|p| {
            let v = pvec(any::<Field>(), p.l);
            let ix = 0..p.l;
            (Just(p), v, ix)
        })
    ) {
        let mut ve = p.encode(Array1::from(v).view());
        ve[ix] += Field::ONE;

        prop_assert!(!p.codeword_is_valid(ve.view()));
    }

    #[test]
    fn test_codeword_is_valid_accepts_sum(
        (p,v) in any::<Params>().prop_flat_map(|p| {
            let v = pvec(any::<Field>(), p.m * p.l);
            (Just(p), v)
        })
    ) {
        let ve = p.encode_interleaved(Array1::from(v).view());
        let vs = ve.genrows().into_iter()
            .fold(Array1::zeros(p.n), |acc, row| acc + row);

        prop_assert!(p.codeword_is_valid(vs.view()));
    }

    #[test]
    fn test_codeword_is_valid_detects_invalid_sum(
        (p,v,r,c) in any::<Params>().prop_flat_map(|p| {
            let v = pvec(any::<Field>(), p.m * p.l);
            let r = 0..p.m;
            let c = 0..p.l;
            (Just(p), v, r, c)
        })
    ) {
        let mut ve = p.encode_interleaved(Array1::from(v).view());
        ve[(r,c)] += Field::ONE;

        let vs = ve.genrows().into_iter()
            .fold(Array1::zeros(p.n), |acc, row| acc + row);

        prop_assert!(!p.codeword_is_valid(vs.view()));
    }

    #[test]
    fn test_peval2(
        (p,v) in any::<Params>().prop_flat_map(|p| {
            let v = pvec(any::<i128>(), p.k + 1);
            (Just(p), v)
        })
    ) {
        let v_coeffs = threshold_secret_sharing::numtheory::fft2_inverse(
            &v,
            p.pss.omega_secrets,
            p.pss.prime,
        ).iter().cloned().map(Field::from).collect::<Array1<Field>>();

        for i in 0 .. v.len() {
            assert_eq!(p.peval2(v_coeffs.view(), i), Field::from(v[i]));
        }
    }

    #[test]
    fn test_peval3(
        (p,v) in any::<Params>().prop_flat_map(|p| {
            let v = pvec(any::<i128>(), p.n + 1);
            (Just(p), v)
        })
    ) {
        let v_coeffs = threshold_secret_sharing::numtheory::fft3_inverse(
            &v,
            p.pss.omega_shares,
            p.pss.prime,
        ).iter().cloned().map(Field::from).collect::<Array1<Field>>();

        for i in 0 .. v.len() {
            assert_eq!(p.peval3(v_coeffs.view(), i), Field::from(v[i]));
        }
    }

    #[test]
    fn test_pmul(
        (p,u,v) in any::<Params>().prop_flat_map(|p| {
            let u = pvec(any::<Field>(), p.k);
            let v = pvec(any::<Field>(), p.k);
            (Just(p), u, v)
        })
    ) {
        let u_coeffs = p.fft2_inverse(ArrayView1::from(&u));
        let v_coeffs = p.fft2_inverse(ArrayView1::from(&v));
        let uv_coeffs = pmul(u_coeffs.view(), v_coeffs.view());

        for i in 0 .. u.len() {
            debug_assert_eq!(
                p.peval2(uv_coeffs.view(), i+1),
                Field::from(u[i] * v[i]),
            );
        }
    }
}
