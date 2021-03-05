use ndarray::{Array1, Array2, ArrayView1, ArrayView2, Zip};
use sprs::{CsMat, TriMat};
use threshold_secret_sharing::packed::PackedSecretSharing as PSS;

#[cfg(test)]
use proptest::{*, prelude::*};

use crate::circuit::{Op, Ckt};
use crate::merkle;
use crate::util::*;

//
// XXX: Use a silly field for now.
//
type Field = crate::f5038849::F;

// Proof information available to both the prover and the verifier.
//
// We fix the security threshold t = log |F| to get the following
// soundness errors, where positive integer e < d/4, d is the code
// distance, and n = 2^p:
//
// * Test-Interleaved:             (1 - e/n)^t + (e + 1)/|F|
//                               = (1 - e/|F|)^p + (e + 1)/|F|
// * Test-Linear-Constraints:      ((e + k + l)/n)^t + 1/|F|
//                               = ((e + k + l)/|F|)^p + 1/|F|
// * Test-Quadratic-Constraints:   ((e + 2k)/n)^t + 1/|F|
//                               = ((e + 2k)/|F|)^p + 1/|F|
//
// I.e., we ensure soundness error is negligible in the field size.
// XXX: Is this right? Seems like t could be smaller, say
// ceil(log |F| / p).
#[derive(Debug, Clone)]
#[allow(non_snake_case)]
struct Public {
    l: usize,      // Message size (Note: k = l + t = 2^j - 1, for some j)
    t: usize,      // Security threshold
    k: usize,      // Reconstruction threshold
    n: usize,      // Codeword size (Note: n = 3^i - 1, for some i)
    m: usize,      // Interleaved code size

    Px: CsMat<Field>,
    Py: CsMat<Field>,
    Pz: CsMat<Field>,
    Padd: CsMat<Field>,

    pss: PSS, // Share-packing parameters
}

impl Public {
    #[allow(non_snake_case)]
    fn new(c: &Ckt) -> Self {
        // XXX: How should parameters be selected? Using fixed parameters
        // for now.
        //
        // Have: sz, t
        // Want:
        //      k^2 >= sz
        //      k = l + t = 2^j - 1 for some j, 1 < j <= PHI_2_EXP
        //      t ~ log(|Field|)
        //      n > l; n = 3^i - 1 for some i, 1 < i <= PHI_3_EXP
        //
        // Also want:
        //      n >= l + k      (from linear-constraint check)
        //      n >= 2*k        (from quadratic-constraint check)
        let kexp = 6; // least_2_pow_gt(ceil(sqrt(sz))) or similar
        let nexp = 4; // least_3_pow_gt(ceil(sqrt(2.pow(lexp)))) or similar
        let k = 2usize.pow(kexp) - 1;
        let t = Field::BITS;
        let l = k - t;
        let n = 3usize.pow(nexp) - 1;
        let m = (c.size() + l - 1) / l;
        let ml = m * l; // padded circuit size

        let new_ml_ml_mat = |cap| TriMat::with_capacity((ml,ml), cap);
        let mut Px = new_ml_ml_mat(ml);     // x = Px * w
        let mut Py = new_ml_ml_mat(ml);     // y = Py * w
        let mut Pz = new_ml_ml_mat(ml);     // z = Py * w
        let mut Padd = new_ml_ml_mat(3*ml); // Padd * w = 0

        for (s, op) in c.ops.iter().enumerate() {
            match *op {
                Op::Mul(i, j) => {
                    // x[s] * y[s] + -1 * z[s] = 0
                    Px.add_triplet(s, i, Field::ONE);
                    Py.add_triplet(s, j, Field::ONE);
                    Pz.add_triplet(s, s + c.inp_size, Field::ONE);
                }
                Op::Add(i, j) => {
                    // sum_i Padd[k,i] * w[i] = 0
                    Padd.add_triplet(s, i, Field::ONE);
                    Padd.add_triplet(s, j, Field::ONE);
                    Padd.add_triplet(s, s + c.inp_size, Field::ONE.neg());
                }
            }
        }

        Public {k, t, l, n, m,
            Px: Px.to_csc(),
            Py: Py.to_csc(),
            Pz: Pz.to_csc(),
            Padd: Padd.to_csc(),

            pss: PSS {
                threshold: t,
                share_count: n,
                secret_count: l,

                prime: Field::MOD,
                omega_secrets: Field::ROOTS_BASE_2[kexp as usize] as i64,
                omega_shares: Field::ROOTS_BASE_3[nexp as usize] as i64,
            },
        }
    }

    #[cfg(test)]
    fn test_value() -> Self {
        Self::new(&Ckt::test_value())
    }

    //
    // XXX: In the following, can we eliminate some of the copies?
    //

    // TODO: Append a random codeword.
    #[inline]
    fn encode(&self, wf: ArrayView1<Field>) -> Array1<Field> {
        debug_assert_eq!(wf.len(), self.l);

        let w: Vec<i64> = wf.iter().cloned().map(i64::from).collect();
        let c: Vec<i64> = self.pss.share(&w);

        c.iter().cloned().map(Field::from).collect()
    }

    #[inline]
    fn decode(&self, cf: ArrayView1<Field>) -> Array1<Field> {
        debug_assert_eq!(cf.len(), self.n);

        let c: Vec<i64> = cf.iter().take(self.k).cloned().map(i64::from).collect();
        let ixs: Vec<usize> = (0 .. self.k).collect();
        let w: Vec<i64> = self.pss.reconstruct(&ixs, &c);

        w.iter().cloned().map(Field::from).collect()
    }

    #[inline]
    fn decode_part(&self,
        ixs: &[usize],
        cf: ArrayView1<Field>,
    ) -> Array1<Field> {
        debug_assert!(cf.len() <= self.n);
        debug_assert!(cf.len() >= self.k);

        let c: Vec<i64> = cf.iter().cloned().map(i64::from).collect();
        let w: Vec<i64> = self.pss.reconstruct(ixs, &c);

        w.iter().cloned().map(Field::from).collect()
    }

    #[inline]
    fn codeword_is_valid(&self, ce: ArrayView1<Field>) -> bool {
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
            &points0.iter().cloned().map(i64::from).collect::<Vec<i64>>(),
            self.pss.omega_secrets,
            self.pss.prime,
        ).iter().cloned().map(Field::from).collect::<Array1<Field>>()
    }

    // Take a sequence of `k+1` coefficients of the polynomial `p` and
    // return evaluation points `p(zeta_0) .. p(zeta_{k+1})`.
    pub fn fft2(&self, coeffs: ArrayView1<Field>) -> Array1<Field> {
        debug_assert!(coeffs.len() <= self.k+1);

        let mut coeffs0 = Array1::zeros(self.k + 1);
        coeffs0.slice_mut(ndarray::s!(0 .. coeffs.len())).assign(&coeffs);

        threshold_secret_sharing::numtheory::fft2(
            &coeffs0.iter().cloned().map(i64::from).collect::<Vec<i64>>(),
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
            &points0.iter().cloned().map(i64::from).collect::<Vec<i64>>(),
            self.pss.omega_shares,
            self.pss.prime,
        ).iter().cloned().map(Field::from).collect::<Array1<Field>>()
    }

    // Take a sequence of `n+1` coefficients of the polynomial `p` and
    // return evaluation points `p(eta_0) .. p(eta_{n+1})`.
    pub fn fft3(&self, coeffs: ArrayView1<Field>) -> Array1<Field> {
        debug_assert!(coeffs.len() <= self.n);

        let mut coeffs0 = Array1::zeros(self.n + 1);
        coeffs0.slice_mut(ndarray::s!(0 .. coeffs.len())).assign(&coeffs);

        threshold_secret_sharing::numtheory::fft3(
            &coeffs0.iter().cloned().map(i64::from).collect::<Vec<i64>>(),
            self.pss.omega_shares,
            self.pss.prime,
        )[1..].iter().cloned().map(Field::from).collect::<Array1<Field>>()
    }

    pub fn peval2(&self, p: ArrayView1<Field>, ix: usize) -> Field {
        peval(p, Field::from(self.pss.omega_secrets).pow(ix as i64))
    }

    pub fn peval3(&self, p: ArrayView1<Field>, ix: usize) -> Field {
        peval(p, Field::from(self.pss.omega_shares).pow(ix as i64))
    }

    pub fn codeword_to_coeffs(&self, U: ArrayView2<Field>) -> Array2<Field> {
        let mut p = Array2::zeros((self.m, self.n+1));

        Zip::from(p.genrows_mut())
            .and(U.genrows())
            .apply(|mut pi, Ui| pi.assign(&self.fft3_inverse(Ui.view())));

        p
    }
}

#[cfg(test)]
impl Arbitrary for Public {
    type Parameters = <Ckt as Arbitrary>::Parameters;
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(p: Self::Parameters) -> Self::Strategy {
        Ckt::arbitrary_with(p).prop_flat_map(|c| Just(Self::new(&c))).boxed()
    }
}

#[test]
fn test_decode_encode() {
    let p = Public::test_value();

    use proptest::collection::vec;
    proptest!(|(v in vec(any::<Field>(), p.l))| {
        let ve = p.encode(ArrayView1::from(&v));
        let vd = p.decode(ve.view()).to_vec();

        prop_assert_eq!(vd, v);
    })
}

#[test]
fn test_codeword_is_valid_accepts_valid() {
    let p = Public::test_value();

    use proptest::collection::vec;
    proptest!(|(v in vec(any::<Field>(), p.l))| {
        let ve = p.encode(Array1::from(v).view());

        prop_assert!(p.codeword_is_valid(ve.view()));
    })
}

#[test]
fn test_codeword_is_valid_detects_invalid() {
    let p = Public::test_value();

    use proptest::collection::vec;
    proptest!(|(v in vec(any::<Field>(), p.l), ix in 0..p.l)| {
        let mut ve = p.encode(Array1::from(v).view());
        ve[ix] += Field::ONE;

        prop_assert!(!p.codeword_is_valid(ve.view()));
    })
}

#[test]
fn test_codeword_is_valid_accepts_sum() {
    let p = Public::new(&Ckt { inp_size: 1000, ops: vec![] });

    use proptest::collection::vec;
    proptest!(|(v in vec(any::<Field>(), p.m * p.l))| {
        let ve = p.encode_interleaved(Array1::from(v).view());
        let vs = ve.genrows().into_iter()
            .fold(Array1::zeros(p.n), |acc, row| acc + row);

        prop_assert!(p.codeword_is_valid(vs.view()));
    })
}

#[test]
fn test_codeword_is_valid_detects_invalid_sum() {
    let p = Public::test_value();

    use proptest::collection::vec;
    proptest!(|(
            v in vec(any::<Field>(), p.m * p.l),
            r in 0..p.m,
            c in 0..p.l,
    )| {
        let mut ve = p.encode_interleaved(Array1::from(v).view());
        ve[(r,c)] += Field::ONE;

        let vs = ve.genrows().into_iter()
            .fold(Array1::zeros(p.n), |acc, row| acc + row);

        prop_assert!(!p.codeword_is_valid(vs.view()));
    })
}

#[test]
fn test_peval2() {
    let p = Public::test_value();

    let v = (0 .. (p.k+1) as i64).collect::<Vec<i64>>();
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
fn test_peval3() {
    let p = Public::test_value();

    let v = (0 .. (p.n+1) as i64).collect::<Vec<i64>>();
    let v_coeffs = threshold_secret_sharing::numtheory::fft3_inverse(
        &v,
        p.pss.omega_shares,
        p.pss.prime,
    ).iter().cloned().map(Field::from).collect::<Array1<Field>>();

    for i in 0 .. v.len() {
        assert_eq!(p.peval3(v_coeffs.view(), i), Field::from(v[i]));
    }
}


// Proof information available only to the prover.
#[allow(non_snake_case)]
struct Secret {
    public: Public,

    // XXX: w is not sparse, but x, y, z likely are. Use CsVec?
    w: Array1<Field>, // Extended witness padded to k*m elements
    x: Array1<Field>, // Multiplication left inputs
    y: Array1<Field>, // Multiplication right inputs
    z: Array1<Field>, // Multiplication outputs

    Uw: Array2<Field>,
    Ux: Array2<Field>,
    Uy: Array2<Field>,
    Uz: Array2<Field>,

    Uw_hash: merkle::Tree,
    Ux_hash: merkle::Tree,
    Uy_hash: merkle::Tree,
    Uz_hash: merkle::Tree,
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Secret")
            .field("w", &self.w)
            .field("x", &self.x)
            .field("y", &self.y)
            .field("z", &self.z)
            .field("Uw", &self.Uw)
            .field("Ux", &self.Ux)
            .field("Uy", &self.Uy)
            .field("Uz", &self.Uz)
            .finish()
    }
}

#[allow(non_snake_case)]
impl Secret {
    fn new(c: &Ckt, inp: &[Field]) -> Self {
        assert_eq!(c.inp_size, inp.len());

        let public = Public::new(&c);

        let ml = public.m * public.l;
        let mut x = Array1::zeros(ml);
        let mut y = Array1::zeros(ml);
        let mut z = Array1::zeros(ml);
        let w: Array1<Field> = ndarray::stack![ndarray::Axis(0),
            c.eval(&inp).iter(), Array1::zeros(ml - c.size())];

        for (s, op) in c.ops.iter().enumerate() {
            if let Op::Mul(i, j) = *op {
                // x[s] * y[s] + -1 * z[s] = 0
                x[s] = w[i];
                y[s] = w[j];
                z[s] = w[s + c.inp_size];
            }
        }

        let Uw = public.encode_interleaved(w.view());
        let Ux = public.encode_interleaved(x.view());
        let Uy = public.encode_interleaved(y.view());
        let Uz = public.encode_interleaved(z.view());

        let Uw_hash = merkle::make_tree(Uw.view());
        let Ux_hash = merkle::make_tree(Ux.view());
        let Uy_hash = merkle::make_tree(Uy.view());
        let Uz_hash = merkle::make_tree(Uz.view());

        Secret {
            public,
            w, x, y, z,
            Uw, Ux, Uy, Uz,
            Uw_hash, Ux_hash, Uy_hash, Uz_hash,
        }
    }

    #[cfg(test)]
    pub fn test_value() -> Self {
        Self::new(&Ckt::test_value(),
            &vec![5.into(), 7.into(), 11.into(), 13.into()])
    }
}

#[cfg(test)]
impl Arbitrary for Secret {
    type Parameters = (usize, usize);
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(p: Self::Parameters) -> Self::Strategy {
        (
            any_with::<Ckt>(p),
            proptest::collection::vec(any::<Field>(), p.0),
        ).prop_map(|(ckt, inp)|
            Secret::new(&ckt, &inp)
        ).boxed()
    }
}

#[cfg(test)]
proptest! {
    #[test]
    #[allow(non_snake_case)]
    fn test_Px(s in Secret::arbitrary_with((20, 1000))) {
        prop_assert_eq!(&s.public.Px * &s.w.t(), s.x);
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_Py(s in Secret::arbitrary_with((20, 1000))) {
        prop_assert_eq!(&s.public.Py * &s.w.t(), s.y);
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_Pz(s in Secret::arbitrary_with((20, 1000))) {
        prop_assert_eq!(&s.public.Pz * &s.w.t(), s.z);
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_Padd(s in Secret::arbitrary_with((20, 1000))) {
        prop_assert_eq!(&s.public.Padd * &s.w.t(),
            Array1::from(vec![0.into(); s.w.len()]));
    }
}

mod proof {
    use super::*;

    // Proof that a committed matrix U is an interleaved codeword given a
    // random vector `r` in `F^m` and a random size `t` subset `Q` of
    // columns.
    #[allow(non_snake_case)]
    struct InterleavedCodeCheck {
        w: Array1<Field>,
        Q_lemma: merkle::Lemma,
    }

    impl InterleavedCodeCheck {
        #[allow(non_snake_case)]
        pub fn new(
            U: ArrayView2<Field>,
            U_hash: &merkle::Tree,
            r: ArrayView1<Field>,
            Q: &Vec<usize>,
        ) -> Self {
            debug_assert_eq!(r.len(), U.nrows());

            let Q_columns = Q.iter()
                .map(|&j| U.column(j as usize).to_owned())
                .collect::<Vec<Array1<Field>>>();
            let Q_lemma = merkle::Lemma::new(&U_hash, &Q_columns, Q);

            Self { Q_lemma, w: r.dot(&U) }
        }

        #[allow(non_snake_case)]
        pub fn verify(&self,
            publ: &Public,
            root: &merkle::Digest,
            r: ArrayView1<Field>,
            Q: &Vec<usize>
        ) -> bool {
            let codeword_check = publ.codeword_is_valid(self.w.view());
            let leaves_check = self.Q_lemma.verify(root);
            let columns_check = self.Q_lemma.columns().iter().zip(Q)
                .fold(true, |acc, (cj, &j)|
                    acc && (r.dot(cj) == self.w[j as usize]));

            codeword_check && leaves_check && columns_check
        }
    }

    #[cfg(test)]
    #[allow(non_snake_case)]
    fn interleaved_code_check_strategy(
        input_size: usize,
        circuit_size: usize
    ) -> impl Strategy<Value = (Ckt, Vec<Field>, Vec<Field>, Vec<usize>)> {
        any_with::<Ckt>((input_size, circuit_size))
            .prop_flat_map(|c| {
                let p = Public::new(&c);
                let i = proptest::collection::vec(any::<Field>(), c.inp_size);
                let r = proptest::collection::vec(any::<Field>(), p.m);
                //let Q = vec_without_replacement(&vec![0..p.n as u32], p.t);
                let Q = Just((0 .. p.t).collect());
                // ^ XXX: Need a vec strategy that samples w/o replacement

                (Just(c), i, r, Q)
            })
    }

    #[cfg(test)]
    proptest! {
        #[test]
        #[allow(non_snake_case)]
        fn test_interleaved_code_Uw(
            (c, i, r, Q) in interleaved_code_check_strategy(20, 100),
        ) {
            let s = Secret::new(&c, &i);
            let proof = InterleavedCodeCheck::new(
                s.Uw.view(),
                &s.Uw_hash,
                ArrayView1::from(&r),
                &Q
            );

            prop_assert!(proof.verify(
                &s.public,
                &s.Uw_hash.root(),
                ArrayView1::from(&r),
                &Q,
            ))
        }
    }

    // Proof that an interleaved codeword `U` encodes a vector `x` in `F^k`
    // satisfying `Ax = b`, given a public matrix `A`, a public vector `b`, 
    // a random vector `r` in `F^m`, and a random size `t` subset of
    // columns.
    #[allow(non_snake_case)]
    struct LinearConstraintsCheck {
        q: Array1<Field>,
        U_Q: Vec<Array1<Field>>,
    }

    // TODO: Use sparse matrix for A.
    impl LinearConstraintsCheck {
        #[allow(non_snake_case)]
        pub fn new(
            p: &Public,
            A: ArrayView2<Field>,
            U: ArrayView2<Field>,
            r: ArrayView1<Field>,
            Q: &Vec<usize>,
        ) -> Self {
            debug_assert_eq!(r.len(), p.m * p.l);
            debug_assert_eq!(A.nrows(), p.m * p.l);
            debug_assert_eq!(Q.len(), p.t);

            let a_coeffs = Self::make_a_coeffs(p, A, r)
                .expect("r*A is wrong size in linear constraint proof");

            // XXX: There should be k coefficients, not n+1. Can we just take k?
            // The need for k is due to using fft3_inverse. We could reduce
            // communication by avoiding it. Computation tradeoff?
            let mut p_coeffs = Array2::zeros((p.m, p.n+1));
            Zip::from(p_coeffs.genrows_mut())
                .and(U.genrows())
                .apply(|mut pi_coeffs, Ui| {
                    pi_coeffs.assign(&p.fft3_inverse(Ui.view()));
                });

            // XXX: There should be l+k+1 coefficients, not k+n+2. Related to the above.
            let q_coeffs = Zip::from(a_coeffs.genrows())
                .and(p_coeffs.genrows())
                .fold(Array1::zeros(p.k + p.n + 2),
                    |acc: Array1<Field>, ai_coeffs, pi_coeffs| {
                        acc + pmul(ai_coeffs.view(), pi_coeffs.view())
                    });

            let mut U_Q = vec![];
            for &j in Q {
                U_Q.push(U.column(j).to_owned());
            }

            //debug_assert_eq!(
            //    p.peval2(q_coeffs.view(), 1),
            //    Zip::from(a_coeffs.genrows())
            //        .and(p_coeffs.genrows())
            //        .fold(Field::ZERO, |acc, ai, pi|
            //            acc + p.peval2(ai, 1) * p.peval2(pi, 1)));
            //debug_assert_eq!((0..p.l).fold(Field::ZERO,
            //        |acc, ix| acc + p.peval2(q_coeffs.view(), ix)),
            //        Field::ZERO);
            Self { U_Q, q: q_coeffs }
        }

        #[allow(non_snake_case)]
        pub fn verify(&self,
            p: &Public,
            A: ArrayView2<Field>,
            r: ArrayView1<Field>,
            b: ArrayView1<Field>,
            Q: &Vec<usize>,
        ) -> bool {
            debug_assert_eq!(r.len(), p.m * p.l);
            debug_assert_eq!(b.len(), p.m * p.l);
            debug_assert_eq!(A.nrows(), p.m * p.l);
            debug_assert_eq!(Q.len(), p.t);

            let a_coeffs = Self::make_a_coeffs(p, A, r)
                .expect("r*A is wrong size in linear constraint check");
            let q_points = (0 .. p.l).map(|ix|
                p.peval2(self.q.view(), ix)).collect::<Array1<Field>>();
            let q_sum = q_points.scalar_sum();
            let rb_sum = r.dot(&b);

            let sum_check = q_sum == rb_sum;

            let columns_check = Q.iter()
                .zip(&self.U_Q)
                .fold(true, |acc, (&j, Uj)| {
                    let q_eta_j = p.peval3(self.q.view(), j+1);
                    let r_eta_j_Uj = (0..p.m)
                        .fold(Field::ZERO, |acc, i| {
                            let ai_eta_j = p.peval3(a_coeffs.row(i), j+1);
                            let U_i_j = Uj[i];

                            acc + ai_eta_j*U_i_j
                        });

                    acc && (r_eta_j_Uj == q_eta_j)
                });

            sum_check && columns_check
        }

        #[allow(non_snake_case)]
        fn make_a_coeffs(
            p: &Public,
            A: ArrayView2<Field>,
            r: ArrayView1<Field>,
        ) -> Result<Array2<Field>, ndarray::ShapeError> {
            let a = r.dot(&A).into_shape((p.m, p.l))?;

            // XXX: There should be l coefficients here, not (k+1). Can we just take l?
            let mut a_coeffs = Array2::zeros((p.m, p.k+1));
            Zip::from(a_coeffs.genrows_mut())
                .and(a.genrows())
                .apply(|mut ai_coeffs, ai| {
                    ai_coeffs.assign(&p.fft2_inverse(ai));
                });

            Ok(a_coeffs)
        }
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_linear_constraints() {
        let c = Ckt::test_value();
        let i = vec![3i64, 5, 7, 9].iter().cloned().map(Field::from).collect::<Vec<Field>>();
        let s = Secret::new(&c, &i);
        let r = (0 .. (s.public.m * s.public.l) as i64).map(Field::from).collect::<Vec<Field>>();
        let Q = (0 .. s.public.t).collect();
        let A = s.public.Padd.to_dense();
        let b = Array1::zeros(s.public.m * s.public.l);
        let proof = LinearConstraintsCheck::new(
            &s.public,
            A.view(),
            s.Uw.view(),
            ArrayView1::from(&r),
            &Q
        );

        assert!(proof.verify(
            &s.public,
            A.view(),
            ArrayView1::from(&r),
            b.view(),
            &Q,
        ));
    }

    //#[cfg(test)]
    //#[allow(non_snake_case)]
    //fn linear_constraints_check_strategy(
    //    input_size: usize,
    //    circuit_size: usize
    //) -> impl Strategy<Value = (Ckt, Vec<Field>, Vec<Field>, Vec<usize>)> {
    //    any_with::<Ckt>((input_size, circuit_size))
    //        .prop_flat_map(|c| {
    //            let p = Public::new(&c);
    //            let i = proptest::collection::vec(any::<Field>(), c.inp_size);
    //            let r = proptest::collection::vec(any::<Field>(), p.m * p.l);
    //            //let Q = vec_without_replacement(&vec![0..p.n as u32], p.t);
    //            let Q = Just((0 .. p.t).collect());
    //            // ^ XXX: Need a vec strategy that samples w/o replacement

    //            (Just(c), i, r, Q)
    //        })
    //}

    //#[cfg(test)]
    //proptest! {
    //    #[test]
    //    #[allow(non_snake_case)]
    //    fn test_linear_constraints_Uw(
    //        (c, i, r, Q) in linear_constraints_check_strategy(20, 100),
    //    ) {
    //        let s = Secret::new(&c, &i);
    //        let A = s.public.Padd.to_dense();
    //        let b = Array1::zeros(s.public.m * s.public.l);
    //        let proof = LinearConstraintsCheck::new(
    //            &s.public,
    //            A.view(),
    //            s.Uw.view(),
    //            ArrayView1::from(&r),
    //            &Q
    //        );
    //
    //        prop_assert!(proof.verify(
    //            &s.public,
    //            A.view(),
    //            ArrayView1::from(&r),
    //            b.view(),
    //            &Q,
    //        ))
    //    }
    //}

    // Proof that a triple of interleaved codewords `Ux`, `Uy`, and `Uz`,
    // encoding vectors `x`, `y`, and `z`, satisfy `xi*yi + ai*zi = bi`
    // for all `i`, given public vectors `a` and `b`, a random vector `r`,
    // and a random size `t` subset of columns.
    #[allow(non_snake_case)]
    struct QuadraticConstraintsCheck {
        p0: Array1<Field>,
        Ux_Q: Vec<Array1<Field>>,
        Uy_Q: Vec<Array1<Field>>,
        Uz_Q: Vec<Array1<Field>>,
    }

    impl QuadraticConstraintsCheck {
        #[allow(non_snake_case)]
        pub fn new(
            p: &Public,
            a: ArrayView1<Field>,
            b: ArrayView1<Field>,
            Ux: ArrayView2<Field>,
            Uy: ArrayView2<Field>,
            Uz: ArrayView2<Field>,
            r: ArrayView1<Field>,
            Q: &Vec<usize>,
        ) -> Self {
            debug_assert_eq!(a.len(), p.m * p.l);
            debug_assert_eq!(b.len(), p.m * p.l);
            debug_assert_eq!(r.len(), p.m);
            debug_assert_eq!(Q.len(), p.t);

            let Ua = p.encode_interleaved(a);
            let Ub = p.encode_interleaved(b);

            // XXX: These are all (n+1) coefficients long, but they should
            // really be l (pa and pb) or k (the rest).
            let pa = p.codeword_to_coeffs(Ua.view());
            let pb = p.codeword_to_coeffs(Ub.view());
            let px = p.codeword_to_coeffs(Ux);
            let py = p.codeword_to_coeffs(Uy);
            let pz = p.codeword_to_coeffs(Ux);

            // XXX: This has (2n+2) coefficients, whereas it should have
            // (2k-1). Related to the above.
            let mut p = Array2::zeros((p.m, 2*p.n + 2));
            Zip::from(p.genrows_mut())
                .and(pa.genrows())
                .and(pb.genrows())
                .and(px.genrows())
                .and(py.genrows())
                .and(pz.genrows())
                .apply(|mut p_i, pa_i, pb_i, px_i, py_i, pz_i| {
                    let pxy_i = pmul(px_i, py_i);
                    let paz_i = pmul(pa_i, pz_i);
                    let mut pb_i0 = Array1::zeros(pxy_i.len());
                    pb_i0.slice_mut(ndarray::s!(0 .. pb_i.len())).assign(&pb_i);

                    p_i.assign(&(pxy_i + paz_i - pb_i0));
                });

            let p0 = r.dot(&p);

            let Ux_Q = Q.iter().map(|&j| Ux.column(j).to_owned()).collect();
            let Uy_Q = Q.iter().map(|&j| Uy.column(j).to_owned()).collect();
            let Uz_Q = Q.iter().map(|&j| Uz.column(j).to_owned()).collect();

            Self { Ux_Q, Uy_Q, Uz_Q, p0 }
        }

        #[allow(non_snake_case)]
        pub fn verify(&self,
            p: &Public,
            a: ArrayView1<Field>,
            b: ArrayView1<Field>,
            r: ArrayView1<Field>,
            Q: &Vec<usize>,
        ) -> bool {
            debug_assert_eq!(a.len(), p.m * p.l);
            debug_assert_eq!(b.len(), p.m * p.l);
            debug_assert_eq!(r.len(), p.m);
            debug_assert_eq!(Q.len(), p.t);

            let Ua = p.encode_interleaved(a);
            let Ub = p.encode_interleaved(b);

            let zero_check = (0 .. p.l).fold(true, |acc, c| {
                let p0_c = p.peval2(self.p0.view(), c);

                acc && (p0_c == Field::ZERO)
            });

            let column_check = Q.iter()
                .zip(&self.Ux_Q)
                .zip(&self.Uy_Q)
                .zip(&self.Uz_Q)
                .fold(true, |acc, (((&j, Ux_j), Uy_j), Uz_j)| {
                    let Uxy_j = point_product(Ux_j.view(), Uy_j.view());
                    let Uaz_j = point_product(Ua.column(j), Uz_j.view());
                    let Uxy_az_b_j = Uxy_j + Uaz_j - Ub.column(j);
                    let p0_j = p.peval3(self.p0.view(), j);

                    acc && (r.dot(&Uxy_az_b_j) == p0_j)
                });

            zero_check && column_check
        }
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_quadratic_constraints() {
        let c = Ckt::test_value();
        let i = vec![3i64, 5, 7, 9].iter().cloned().map(Field::from).collect::<Vec<Field>>();
        let s = Secret::new(&c, &i);
        let r = (0 .. s.public.m as i64).map(Field::from).collect::<Array1<Field>>();
        let Q = (0 .. s.public.t).collect();
        let a = Array1::from(vec![Field::ZERO-Field::ONE; s.public.m * s.public.l]);
        let b = Array1::zeros(s.public.m * s.public.l);
        let proof = QuadraticConstraintsCheck::new(
            &s.public,
            a.view(),
            b.view(),
            s.Ux.view(),
            s.Uy.view(),
            s.Uz.view(),
            r.view(),
            &Q,
        );

        assert!(proof.verify(
            &s.public,
            a.view(),
            b.view(),
            r.view(),
            &Q,
        ));
    }

    //pub fn next_pow_2(n: usize) -> usize { 2.pow((n as f64).log2().ceil() as u32) }
    //pub fn next_pow_3(n: usize) -> usize { 3.pow((n as f64).log(3).ceil() as u32) }
}
