use ndarray::{Array1, Array2, ArrayView1, ArrayView2, Zip};
use sprs::{CsMat, TriMat};
use threshold_secret_sharing::packed::PackedSecretSharing as PSS;

use proptest::{*, prelude::*};

use crate::circuit::{Op, Ckt};
use crate::merkle;

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
    // XXX: In the following, can we eliminate some of the
    // intermediate vectors?
    //

    // TODO: Append a random codeword.
    #[inline]
    fn encode(&self, wf: ArrayView1<Field>) -> Array1<Field> {
        debug_assert!(wf.shape() == [self.l]);

        let w: Vec<i64> = wf.iter().cloned().map(i64::from).collect();
        let c: Vec<i64> = self.pss.share(&w);

        c.iter().cloned().map(Field::from).collect()
    }

    #[inline]
    fn decode(&self, cf: ArrayView1<Field>) -> Array1<Field> {
        debug_assert!(cf.shape() == [self.n]);

        let c: Vec<i64> = cf.iter().take(self.l + self.t).cloned().map(i64::from).collect();
        let ixs: Vec<usize> = (0 .. self.l + self.t).collect();
        let w: Vec<i64> = self.pss.reconstruct(&ixs, &c);

        w.iter().cloned().map(Field::from).collect()
    }

    #[inline]
    fn codeword_is_valid(&self, cf: ArrayView1<Field>) -> bool {
        debug_assert!(cf.shape() == [self.n]);

        self.encode(self.decode(cf).view()).view() == cf
    }

    pub fn encode_interleaved(&self, ws: ArrayView1<Field>) -> Array2<Field> {
        debug_assert!(ws.shape() == [self.l * self.m]);

        let mut res = Vec::with_capacity(self.n * self.m);

        for w in ws.exact_chunks(self.pss.secret_count) {
            res.append(&mut self.encode(w).to_vec());
        }

        Array2::from_shape_vec((self.m, self.n), res)
            .expect("Unreachable: encoded array is wrong size")
    }

    pub fn decode_interleaved(&self, cs: ArrayView2<Field>) -> Array1<Field> {
        debug_assert!(cs.shape() == [self.m, self.n]);

        let mut res = Vec::with_capacity(self.l * self.m);

        for c in 0 .. cs.nrows() {
            res.append(&mut self.decode(cs.row(c)).to_vec());
        }

        From::from(res)
    }

    pub fn zeta_interp(&self, points: ArrayView1<Field>) -> Array1<Field> {
        debug_assert!(points.shape() == [self.l]);

        let coeffs = threshold_secret_sharing::numtheory::fft2_inverse(
            &points.iter().cloned().map(i64::from).collect::<Vec<i64>>(),
            self.pss.omega_secrets,
            self.pss.prime,
        ).iter().cloned().map(Field::from).collect::<Vec<Field>>();

        Array1::from(coeffs)
    }

    pub fn zeta_eval(&self, coeffs: ArrayView1<Field>) -> Array1<Field> {
        let zeros = Array1::zeros(self.l - coeffs.len());
        let coeffs0 = ndarray::stack!(ndarray::Axis(0), coeffs, zeros);
        let points = threshold_secret_sharing::numtheory::fft2(
            &coeffs0.iter().cloned().map(i64::from).collect::<Vec<i64>>(),
            self.pss.omega_secrets,
            self.pss.prime,
        ).iter().cloned().map(Field::from).collect::<Vec<Field>>();

        Array1::from(points)
    }

    pub fn eta_interp(&self, points: ArrayView1<Field>) -> Array1<Field> {
        debug_assert!(points.shape() == [self.n]);

        let coeffs = threshold_secret_sharing::numtheory::fft3_inverse(
            &points.iter().cloned().map(i64::from).collect::<Vec<i64>>(),
            self.pss.omega_shares,
            self.pss.prime,
        ).iter().cloned().map(Field::from).collect::<Vec<Field>>();

        Array1::from(coeffs)
    }

    pub fn eta_eval(&self, coeffs: ArrayView1<Field>) -> Array1<Field> {
        let zeros = Array1::zeros(self.n - coeffs.len());
        let coeffs0 = ndarray::stack!(ndarray::Axis(0), coeffs, zeros);
        let points = threshold_secret_sharing::numtheory::fft3(
            &coeffs0.iter().cloned().map(i64::from).collect::<Vec<i64>>(),
            self.pss.omega_shares,
            self.pss.prime,
        ).iter().cloned().map(Field::from).collect::<Vec<Field>>();

        Array1::from(points)
    }
}

#[test]
fn test_decode_encode() {
    let p = Public::test_value();
    let vs: Array1<Field> = (0 .. p.l as i64).map(Field::from).collect();

    assert_eq!(p.decode(p.encode(vs.view()).view()), vs);
}

#[test]
fn test_decode_detects_errors() {
    let p = Public::test_value();
    let vs: Array1<Field> = (0 .. p.l as i64).map(Field::from).collect();

    let mut cs = p.encode(vs.view());
    cs[0] += Field::ONE;

    assert!(!p.codeword_is_valid(cs.view()));
}

proptest! {
    #[test]
    fn test_decode_encode_prop(c in Ckt::arbitrary_with((20, 1000))) {
        let p = Public::new(&c);
        let vs: Array1<Field> = (0 .. p.l as i64).map(Field::from).collect();

        assert_eq!(p.decode(p.encode(vs.view()).view()), vs);
    }

    #[test]
    fn test_decode_detects_errors_prop(c in Ckt::arbitrary_with((20, 1000))) {
        let p = Public::new(&c);
        let vs: Array1<Field> = (0 .. p.l as i64).map(Field::from).collect();

        let mut cs = p.encode(vs.view());
        cs[0] += Field::ONE;

        assert!(!p.codeword_is_valid(cs.view()));
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

#[test]
#[allow(non_snake_case)]
fn test_P_matrices() {
    let s = Secret::test_value();

    assert_eq!(&s.public.Px * &s.w.t(), s.x);
    assert_eq!(&s.public.Py * &s.w.t(), s.y);
    assert_eq!(&s.public.Pz * &s.w.t(), s.z);
    assert_eq!(&s.public.Padd * &s.w.t(),
        Array1::from(vec![0.into(); s.w.len()]));
}

#[test]
#[allow(non_snake_case)]
fn test_U_matrices() {
    let s = Secret::test_value();

    assert_eq!(s.public.decode_interleaved(s.Uw.view()), s.w);
    assert_eq!(s.public.decode_interleaved(s.Ux.view()), s.x);
    assert_eq!(s.public.decode_interleaved(s.Uy.view()), s.y);
    assert_eq!(s.public.decode_interleaved(s.Uz.view()), s.z);
}

proptest! {
    #[test]
    #[allow(non_snake_case)]
    fn test_P_matrices_prop(c in Ckt::arbitrary_with((20, 1000))) {
        let s = Secret::new(&c,
            &(0 .. 20).map(Field::from).collect::<Vec<Field>>());

        assert_eq!(&s.public.Px * &s.w.t(), s.x);
        assert_eq!(&s.public.Py * &s.w.t(), s.y);
        assert_eq!(&s.public.Pz * &s.w.t(), s.z);
        assert_eq!(&s.public.Padd * &s.w.t(),
            Array1::from(vec![0.into(); s.w.len()]));
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_U_matrices_prop(c in Ckt::arbitrary_with((20, 100))) {
        let s = Secret::new(&c,
            &(0 .. 20).map(Field::from).collect::<Vec<Field>>());

        assert_eq!(s.public.decode_interleaved(s.Uw.view()), s.w);
        assert_eq!(s.public.decode_interleaved(s.Ux.view()), s.x);
        assert_eq!(s.public.decode_interleaved(s.Uy.view()), s.y);
        assert_eq!(s.public.decode_interleaved(s.Uz.view()), s.z);
    }
}

mod proof {
    use super::*;

    // Proof that a committed matrix U is an interleaved codeword given a
    // random vector `r` in `F^m` and a random size `t` subset `Q` of
    // columns.
    struct InterleavedCodeCheck {
        w: Array1<Field>,
        Q: Vec<Array1<Field>>,
        // XXX: This is horribly inefficient. We should really be
        // cherry-picking the tree nodes to send, but how do we do this
        // using the `merkletree` API?
        Q_proofs: Vec<merkle::Proof>,
    }

    impl InterleavedCodeCheck {
        #[allow(non_snake_case)]
        pub fn new(
            U: ArrayView2<Field>,
            U_hash: &merkle::Tree,
            r: ArrayView1<Field>,
            Q_ixs: &Vec<usize>,
        ) -> Self {
            debug_assert!(r.len() == U.nrows());

            let mut Q = vec![];
            let mut Q_proofs = vec![];

            for &j in Q_ixs {
                Q.push(U.column(j).to_owned());
                Q_proofs.push(U_hash.gen_proof(j) // XXX: When does this fail?
                    .expect("Error generating merkle proof"));
            }

            Self { Q, Q_proofs, w: r.dot(&U) }
        }

        #[allow(non_snake_case)]
        pub fn verify(&self,
            publ: &Public,
            root: merkle::Digest,
            r: ArrayView1<Field>,
            Q_ixs: &Vec<usize>
        ) -> bool {
            self.Q.iter()
                .zip(&self.Q_proofs)
                .zip(Q_ixs)
                .fold(true, |acc, ((col, proof), &j)| {
                    let h = merkle::hash_col(col.view());
                    let res0 = proof.root() == root;
                    let res1 = proof
                        .validate_with_data::<merkle::HashAlgo>(&h)
                        .expect("Error validating Merkle proof");
                        // XXX: When does this fail?
                    let res2 = r.dot(col) == self.w[j];

                    // XXX: These fail right now. Why?
                    acc && res0 /*&& res1*/ && res2
                }) //&& publ.codeword_is_valid(self.w.view())
        }
    }

    proptest! {
        // XXX: Need a better way to generate the fields r0 and Q0. The
        // problem is that we don't know the length (m) of r or the length
        // (t) of Q or range (n) of its fields until we've processed c.
        #[test]
        #[allow(non_snake_case)]
        fn test_interleaved_code_proof_Uw(
            c in Ckt::arbitrary_with((20, 10)),
            i in proptest::collection::vec(any::<Field>(), 20),
            r0 in proptest::collection::vec(any::<Field>(), 100),
            Q0 in proptest::collection::vec(any::<usize>(), 100),
        ) {
            let s = Secret::new(&c, &i);
            let r = r0.iter().take(s.public.m)
                .cloned().collect::<Array1<Field>>();
            let Q = Q0.iter().take(s.public.t)
                .map(|&i| i % s.public.n).collect();
            let proof = InterleavedCodeCheck::new(
                s.Uw.view(),
                &s.Uw_hash,
                r.view(),
                &Q
            );

            assert!(proof.verify(
                &s.public,
                s.Uw_hash.root(),
                r.view(),
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

    impl LinearConstraintsCheck {
        #[allow(non_snake_case)]
        pub fn new(
            p: &Public,
            A: ArrayView2<Field>,
            U: ArrayView2<Field>,
            r: ArrayView1<Field>,
            Q: &Vec<usize>,
        ) -> Self {
            debug_assert!(r.len() == p.m * p.l);
            debug_assert!(A.nrows() == p.m * p.l);
            debug_assert!(Q.len() == p.t);

            let r_eta = Self::compute_r_eta_points(p, A, r);

            let mut q_eta = Array1::zeros(p.n);
            for j in 0 .. p.n {
                q_eta[j] = r_eta.column(j).dot(&U.column(j));
            }

            let q_coeffs = p.eta_interp(q_eta.view())
                .slice(ndarray::s![1 .. p.l + p.k]).to_owned();

            let mut U_Q = vec![];
            for &j in Q {
                U_Q.push(U.column(j).to_owned());
            }

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
            debug_assert!(r.len() == p.m * p.l);
            debug_assert!(A.nrows() == p.m * p.l);
            debug_assert!(Q.len() == p.t);

            let r_eta = Self::compute_r_eta_points(p, A, r);

            // XXX: We don't need all n points. Would it be faster to
            // evaluate these individually for j in Q?
            let q_eta = p.eta_eval(self.q.view());

            let mut columns_check = true;
            for (&j, U_Qj) in Q.iter().zip(&self.U_Q) {
                columns_check &=
                    self.q[j] == r_eta.column(j).dot(U_Qj);
            }

            let sum_check = q_eta.scalar_sum() == r.dot(&b);

            sum_check && columns_check
        }

        // Evaluate the polynomials `r_i`, `i \in [m]`, on inputs
        // `eta_j`, `j \in [n]`, where `r_i(zeta_c) = (r * A)_c`,
        // `c \in [l]`. This is recomputed in both proof and verifier,
        // rather than being sent in the proof, to keep the proof small.
        #[allow(non_snake_case)]
        fn compute_r_eta_points(
            p: &Public,
            A: ArrayView2<Field>,
            r: ArrayView1<Field>,
        ) -> Array2<Field> {
            let r_zeta = (&r * &A).into_shape((p.m, p.l))
                .expect("r*A is wrong shape in linear-constraints proof");

            let mut r_coeffs = Array2::zeros((p.m, p.l));
            Zip::from(r_coeffs.genrows_mut())
                .and(r_zeta.genrows())
                .apply(|mut ri_coeffs, ri_zeta|
                    ri_coeffs.assign(&p.zeta_interp(ri_zeta.view()))
                );

            let mut r_eta = Array2::zeros((p.m, p.n));
            Zip::from(r_eta.genrows_mut())
                .and(r_coeffs.genrows())
                .apply(|mut ri_eta, ri_coeffs|
                    ri_eta.assign(&p.eta_eval(ri_coeffs))
                );

            r_eta
        }
    }

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
            p: Public,
            a: ArrayView1<Field>,
            b: ArrayView1<Field>,
            Ux: ArrayView2<Field>,
            Uy: ArrayView2<Field>,
            Uz: ArrayView2<Field>,
            r: ArrayView1<Field>,
            Q: Vec<usize>,
        ) -> Self {
            debug_assert!(a.len() == p.m * p.l);
            debug_assert!(b.len() == p.m * p.l);
            debug_assert!(r.len() == p.m);
            debug_assert!(Q.len() == p.t);

            let Ua = p.encode_interleaved(a);
            let Ub = p.encode_interleaved(b);

            let mut p_eta = Array2::zeros((p.m, p.n));
            Zip::from(&mut p_eta)
                .and(&Ux).and(&Uy).and(&Uz).and(&Ua).and(&Ub)
                .apply(|p_ij, &px_ij, &py_ij, &pz_ij, &pa_ij, &pb_ij|
                    *p_ij = px_ij*py_ij + pa_ij*pz_ij - pb_ij
                );

            let p0_eta = &r * &p_eta;

            let p0_coeffs = p.eta_interp(p0_eta.view())
                .slice(ndarray::s![1 .. 2*p.k]).to_owned();

            let mut Ux_Q = vec![];
            let mut Uy_Q = vec![];
            let mut Uz_Q = vec![];
            for j in Q {
                Ux_Q.push(Ux.column(j).to_owned());
                Uy_Q.push(Uy.column(j).to_owned());
                Uz_Q.push(Uz.column(j).to_owned());
            }

            Self { Ux_Q, Uy_Q, Uz_Q, p0: p0_coeffs }
        }

        #[allow(non_snake_case)]
        pub fn verify(&self,
            p: Public,
            a: ArrayView1<Field>,
            b: ArrayView1<Field>,
            r: ArrayView1<Field>,
            Q: Vec<usize>,
        ) -> bool {
            debug_assert!(a.len() == p.m * p.l);
            debug_assert!(b.len() == p.m * p.l);
            debug_assert!(r.len() == p.m);
            debug_assert!(Q.len() == p.t);

            let Ua = p.encode_interleaved(a);
            let Ub = p.encode_interleaved(b);

            let p0_zeta = p.zeta_eval(self.p0.view());

            let zero_check = p0_zeta == Array1::zeros(p.l);

            // XXX: We don't need all n points. Would it be faster to
            // evaluate these individually for j in Q?
            let p0_eta = p.eta_eval(self.p0.view());

            let mut eq_check = true;
            for j in Q {
                let Uxy_j = Self::pointwise_product(
                    self.Ux_Q[j].view(),
                    self.Uy_Q[j].view(),
                );
                let Uaz_j = Self::pointwise_product(
                    Ua.column(j).view(),
                    self.Uz_Q[j].view(),
                );

                eq_check &=
                    r.dot(&(Uxy_j + Uaz_j - Ub.column(j))) == p0_eta[j];
            }

            zero_check && eq_check
        }

        fn pointwise_product(
            u: ArrayView1<Field>,
            v: ArrayView1<Field>
        ) -> Array1<Field> {
            debug_assert!(u.len() == v.len());

            Array1::from_shape_fn(u.len(), |i| u[i] * v[i])
        }
    }

    //pub fn next_pow_2(n: usize) -> usize { 2.pow((n as f64).log2().ceil() as u32) }
    //pub fn next_pow_3(n: usize) -> usize { 3.pow((n as f64).log(3).ceil() as u32) }
}
