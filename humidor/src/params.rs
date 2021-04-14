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
    //pub pss: PSS, // Share-packing parameters
    pub pss: crate::threshold_secret_sharing::PackedSecretSharing,

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
        let t = Field::BITS;
        let (kexp, nexp, k, l, n, m) = (0 .. Field::PHI_2_EXP as u32)
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

                let diff = (l as isize - (t*m) as isize).abs();
                Some((diff, (kexp, nexp, k, l, n, m)))
            })
            //.map(|p| { eprintln!("{:?}", p); p })
            .min_by(|(d1,_), (d2,_)| d1.cmp(d2))
            .expect("Failed to find appropriate parameters")
            .1;

        Self { kexp, nexp, k, t, l, n, m,
            pss: crate::threshold_secret_sharing::PackedSecretSharing {
                threshold: t,
                share_count: n,
                secret_count: l,

                omega_secrets: Field::from(Field::ROOTS_BASE_2[kexp as usize]),
                omega_shares: Field::from(Field::ROOTS_BASE_3[nexp as usize]),
            }
        }
    }

    pub fn encode(&self, wf: ArrayView1<Field>) -> Array1<Field> {
        debug_assert_eq!(wf.len(), self.l);

        Array1::from(self.pss.share(&wf.to_vec()))
    }

    fn decode_no_strip(&self, cf: ArrayView1<Field>) -> Vec<Field> {
        use ndarray::{stack, Axis};

        debug_assert_eq!(cf.len(), self.n);

        let coeffs0 = stack!(Axis(0), Array1::zeros(1), cf);
        let points = crate::numtheory::fft3_inverse(
            &coeffs0.to_vec(),
            Field::from(self.pss.omega_shares),
        );

        crate::numtheory::fft2(
            &points[0 ..= self.k],
            Field::from(self.pss.omega_secrets),
        )
    }

    pub fn decode(&self, cf: ArrayView1<Field>) -> Array1<Field> {
        self.decode_no_strip(cf)[1 ..= self.l].iter().cloned().collect()
    }

    // Note: This is _slow_! Don't use it if you can avoid it.
    #[allow(dead_code)]
    fn decode_part(&self,
        ixs: &[usize],
        cf: ArrayView1<Field>,
    ) -> Array1<Field> {
        debug_assert!(cf.len() <= self.n);
        debug_assert!(cf.len() >= self.k);

        Array1::from(self.pss.reconstruct(ixs, &cf.to_vec()))
    }

    // XXX: Not sure this is sufficient to check whether this is a valid
    // codeword. Need to check the number of errors this detects, etc.
    pub fn codeword_is_valid(&self, cf: ArrayView1<Field>) -> bool {
        self.decode_no_strip(cf)
            .iter()
            .enumerate()
            .filter(|&(ix,_)| ix == 0)
            .all(|(_,&f)| f == Field::ZERO)
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
        points0.slice_mut(ndarray::s!(1 ..= points.len())).assign(&points);

        crate::numtheory::fft2_inverse(
            &points0.to_vec(),
            Field::from(self.pss.omega_secrets),
        ).iter().cloned().collect()
    }

    // Take a sequence of `k+1` coefficients of the polynomial `p` and
    // return evaluation points `p(zeta_1) .. p(zeta_{k})`. Note that
    // `p(zeta_0)`, which should always be zero for our application, is
    // not returned.
    pub fn fft2(&self, coeffs: ArrayView1<Field>) -> Array1<Field> {
        debug_assert!(coeffs.len() <= self.k+1);

        let mut coeffs0 = Array1::zeros(self.k + 1);
        coeffs0.slice_mut(ndarray::s!(0 .. coeffs.len())).assign(&coeffs);

        crate::numtheory::fft2(
            &coeffs0.to_vec(),
            Field::from(self.pss.omega_secrets),
        )[1..].iter().cloned().collect()
    }

    // Take a sequence of _possibly more than_ `k+1` coefficients of the
    // polynomial `p` and return evaluation points `p(zeta_0) .. p(zeta_{k})`.
    // Note that _all_ `k+1` coefficients are returned
    pub fn fft2_peval(&self, coeffs: ArrayView1<Field>) -> Array1<Field> {
        let coeffs0 = coeffs.to_vec()[..]
            .chunks(self.k + 1)
            .fold(Array1::zeros(self.k + 1),
                |acc, v| padd(acc.view(), Array1::from(v.to_vec()).view()));

        crate::numtheory::fft2(
            &coeffs0.to_vec(),
            Field::from(self.pss.omega_secrets),
        ).iter().cloned().collect()
    }

    // Take a sequence of values `p(eta_1) .. p(eta_c)` for `c <= n` and
    // return the `(n+1)`-coefficients of the polynomial `p`.
    pub fn fft3_inverse(&self, points: ArrayView1<Field>) -> Array1<Field> {
        debug_assert!(points.len() <= self.n);

        let mut points0 = Array1::zeros(self.n + 1);
        points0.slice_mut(ndarray::s!(1 .. points.len()+1)).assign(&points);

        crate::numtheory::fft3_inverse(
            &points0.to_vec(),
            Field::from(self.pss.omega_shares),
        ).iter().cloned().collect()
    }

    // Take a sequence of `n+1` coefficients of the polynomial `p` and
    // return evaluation points `p(eta_1) .. p(eta_{n})`. Note that
    // `p(eta_0)`, which should always be zero for our application, is
    // not returned.
    pub fn fft3(&self, coeffs: ArrayView1<Field>) -> Array1<Field> {
        debug_assert!(coeffs.len() <= self.n + 1);

        let mut coeffs0 = Array1::zeros(self.n + 1);
        coeffs0.slice_mut(ndarray::s!(0 .. coeffs.len())).assign(&coeffs);

        crate::numtheory::fft3(
            &coeffs0.to_vec(),
            Field::from(self.pss.omega_shares),
        )[1..].iter().cloned().collect()
    }

    // Take a sequence of _possibly more than_ `n+1` coefficients of the
    // polynomial `p` and return evaluation points `p(eta_0) .. p(eta_{n})`.
    // Note that _all_ `n+1` coefficients are returned
    pub fn fft3_peval(&self, coeffs: ArrayView1<Field>) -> Array1<Field> {
        let coeffs0 = coeffs.to_vec()[..]
            .chunks(self.n + 1)
            .fold(Array1::zeros(self.n + 1),
                |acc, v| padd(acc.view(), Array1::from(v.to_vec()).view()));

        crate::numtheory::fft3(
            &coeffs0.to_vec(),
            Field::from(self.pss.omega_shares),
        ).iter().cloned().collect()
    }

    pub fn peval2(&self, p: ArrayView1<Field>, ix: usize) -> Field {
        crate::util::peval(p, Field::from(self.pss.omega_secrets).pow(ix as u64))
    }

    pub fn peval3(&self, p: ArrayView1<Field>, ix: usize) -> Field {
        crate::util::peval(p, Field::from(self.pss.omega_shares).pow(ix as u64))
    }

    // Take two polynomials p and q of degree less than 2^kexp and produce a
    // polynomial s of degree less than 2^(kexp+1)-1 s.t. s(.) = p(.) * q(.).
    pub fn pmul2(&self,
        p: ArrayView1<Field>,
        q: ArrayView1<Field>
    ) -> Array1<Field> {
        debug_assert!(p.len() <= 2usize.pow(self.kexp));
        debug_assert!(q.len() <= 2usize.pow(self.kexp));

        let p_deg = p.len();
        let q_deg = q.len();
        let mut p_coeffs = p.to_vec();
        let mut q_coeffs = q.to_vec();

        let max_deg = 2usize.pow(self.kexp + 1);
        let pq_deg = p_deg + q_deg - 1;
        let omega = Field::from(Field::ROOTS_BASE_2[self.kexp as usize + 1]);

        p_coeffs.append(&mut vec![Field::ZERO; max_deg - p_deg]);
        q_coeffs.append(&mut vec![Field::ZERO; max_deg - q_deg]);

        let p_points = crate::numtheory::fft2(&p_coeffs, omega);
        let q_points = crate::numtheory::fft2(&q_coeffs, omega);
        let pq_points = p_points.iter()
            .zip(q_points)
            .map(|(&pi,qi)| pi * qi)
            .collect::<Vec<_>>();
        let pq_coeffs = crate::numtheory::fft2_inverse(&pq_points, omega);

        pq_coeffs.iter().take(pq_deg).cloned().collect()
    }

    #[allow(non_snake_case)]
    pub fn random_indices<R>(&self, rng: &mut R) -> Vec<usize>
        where R: rand::RngCore
    {
        use rand::seq::SliceRandom;

        let mut Q = (0 .. self.n).collect::<Vec<usize>>();
        Q.shuffle(rng);
        Q.truncate(self.t);

        Q
    }

    pub fn random_codeword<R>(&self, rng: &mut R) -> Array1<Field>
        where R: rand::RngCore
    {
        self.encode(random_field_array(rng, self.l).view())
    }

    pub fn random_zero_codeword<R>(&self, rng: &mut R) -> Array1<Field>
        where R: rand::RngCore
    {
        debug_assert_ne!(self.l, 0);

        let mut w = random_field_array(rng, self.l);
        let sum = w.scalar_sum();
        w[self.l - 1] -= sum;

        self.encode(w.view())
    }
}

#[cfg(test)]
impl Arbitrary for Params {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        (1usize .. 100).prop_flat_map(|size| Just(Self::new(size))).boxed()
    }
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
            let v = pvec(any::<Field>(), p.k + 1);
            (Just(p), v)
        })
    ) {
        let v_coeffs = crate::numtheory::fft2_inverse(
            &v,
            p.pss.omega_secrets,
        ).iter().cloned().map(Field::from).collect::<Array1<Field>>();

        for i in 0 .. v.len() {
            prop_assert_eq!(p.peval2(v_coeffs.view(), i), Field::from(v[i]));
        }
    }

    #[test]
    fn test_fft2_peval(
        (p,v) in any::<Params>().prop_flat_map(|p| {
            (1 ..= 3*(p.k+1)).prop_flat_map(move |len| {
                let v = pvec(any::<Field>(), len);
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
        (p,v) in any::<Params>().prop_flat_map(|p| {
            let v = pvec(any::<Field>(), p.n + 1);
            (Just(p), v)
        })
    ) {
        let v_coeffs = crate::numtheory::fft3_inverse(
            &v,
            p.pss.omega_shares,
        ).iter().cloned().map(Field::from).collect::<Array1<Field>>();

        for i in 0 .. v.len() {
            prop_assert_eq!(p.peval3(v_coeffs.view(), i), v[i]);
        }
    }

    #[test]
    fn test_fft3_peval(
        (p,v) in any::<Params>().prop_flat_map(|p| {
            (1 ..= 3*(p.n+1)).prop_flat_map(move |len| {
                let v = pvec(any::<Field>(), len);
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
            prop_assert_eq!(
                p.peval2(uv_coeffs.view(), i+1),
                u[i] * v[i]
            );
        }
    }

    #[test]
    fn test_pmul2(
        (p, u, v) in any::<Params>().prop_flat_map(|p| {
            (1..=p.k+1, 1..=p.k+1).prop_flat_map(move |(ulen, vlen)| {
                let u_coeffs = pvec(any::<Field>(), ulen);
                let v_coeffs = pvec(any::<Field>(), vlen);
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
        (p, u, v) in any::<Params>().prop_flat_map(|p| {
            (1..=p.k+1, 1..=p.k+1).prop_flat_map(move |(ulen, vlen)| {
                let u_coeffs = pvec(any::<Field>(), ulen);
                let v_coeffs = pvec(any::<Field>(), vlen);
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
        (p, u, v) in any::<Params>().prop_flat_map(|p| {
            (1..=p.k+1, 1..=p.k+1).prop_flat_map(move |(ulen, vlen)| {
                let u_coeffs = pvec(any::<Field>(), ulen);
                let v_coeffs = pvec(any::<Field>(), vlen);
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
    fn test_random_zero_codeword(p in any::<Params>()) {
        use rand::{SeedableRng, rngs::StdRng};
        let c = p.random_zero_codeword(&mut StdRng::from_entropy());
        let w = p.decode(c.view());

        prop_assert_eq!(w.scalar_sum(), Field::ZERO);
    }
}
