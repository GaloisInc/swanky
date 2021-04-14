use ndarray::{Array1, Array2};
use sprs::{CsMat, TriMat};
use rand::{SeedableRng, rngs::StdRng};

#[cfg(test)]
use proptest::{*, prelude::*, collection::vec as pvec};

use crate::circuit::{Op, Ckt};
use crate::merkle;
use crate::util::*;
use crate::params::Params;

//
// XXX: Use a silly field for now.
//
type Field = crate::f2_19x3_26::F;

// Proof information available to both the prover and the verifier.
#[derive(Debug, Clone)]
#[allow(non_snake_case)]
struct Public {
    params: crate::params::Params,

    Px: CsMat<Field>,
    Py: CsMat<Field>,
    Pz: CsMat<Field>,
    Padd: CsMat<Field>,
}

impl Public {
    #[allow(non_snake_case)]
    fn new(c: &Ckt) -> Self {
        let params = Params::new(c.size() + 1 /* for the final zero check */);

        let ml = params.m * params.l; // padded circuit size

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

        // XXX: According Sec. 4.4 of the Ligero paper, checking the circuit
        // output is done by adding (or replacing?) a constraint based on the
        // last gate in c:
        // * w[i] + w[j] - 1 = 1    if the last gate is an addition
        // * x[s] + y[s] - 1 = 0    if the last gate is a multiplication
        // It's unclear to me how to do this without adding extra gates. So
        // instead, we add a constraint directly asserting the last wire in
        // the extended witness to be zero.
        Padd.add_triplet(c.size(), c.size() - 1, Field::ONE);

        Public {params,
            Px: Px.to_csc(),
            Py: Py.to_csc(),
            Pz: Pz.to_csc(),
            Padd: Padd.to_csc(),
        }
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

    u: Array1<Field>,
    ux: Array1<Field>,
    uy: Array1<Field>,
    uz: Array1<Field>,
    u0: Array1<Field>,
    uadd: Array1<Field>,

    U_hash: merkle::Tree,
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
        let mut rng = StdRng::from_entropy();

        let ml = public.params.m * public.params.l;
        let mut x = Array1::zeros(ml);
        let mut y = Array1::zeros(ml);
        let mut z = Array1::zeros(ml);
        let w: Array1<_> = c.eval(&inp)
            .iter()
            .cloned()
            .chain(vec![Field::ZERO; ml - c.size()])
            .collect();

        for (s, op) in c.ops.iter().enumerate() {
            if let Op::Mul(i, j) = *op {
                // x[s] * y[s] + -1 * z[s] = 0
                x[s] = w[i];
                y[s] = w[j];
                z[s] = w[s + c.inp_size];
                debug_assert_eq!(x[s] * y[s] - z[s], Field::ZERO);
            }
        }

        let Uw = public.params.encode_interleaved(w.view());
        let Ux = public.params.encode_interleaved(x.view());
        let Uy = public.params.encode_interleaved(y.view());
        let Uz = public.params.encode_interleaved(z.view());

        let u = public.params.random_codeword(&mut rng);
        let ux = public.params.random_zero_codeword(&mut rng);
        let uy = public.params.random_zero_codeword(&mut rng);
        let uz = public.params.random_zero_codeword(&mut rng);
        let u0 = public.params.encode(Array1::zeros(public.params.l).view());
        let uadd = public.params.random_zero_codeword(&mut rng);

        let U_hash = merkle::make_tree(ndarray::stack(
            ndarray::Axis(0),
            &[Uw.view(), Ux.view(), Uy.view(), Uz.view()]
        ).expect("Unequal matrix rows when generating Merkle tree").view());

        Secret {
            public,
            w, x, y, z,
            Uw, Ux, Uy, Uz,
            u, ux, uy, uz, u0, uadd,
            U_hash
        }
    }
}

#[cfg(test)]
impl Arbitrary for Secret {
    type Parameters = (usize, usize);
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with((w,c): Self::Parameters) -> Self::Strategy {
        (
            crate::circuit::arb_ckt(w,c),
            pvec(any::<Field>(), w),
        ).prop_map(|(ckt, inp)|
            Secret::new(&ckt, &inp)
        ).boxed()
    }
}

#[cfg(test)]
proptest! {
    #[test]
    #[allow(non_snake_case)]
    fn test_Px(s in Secret::arbitrary_with((20, 100))) {
        prop_assert_eq!(&s.public.Px * &s.w.t(), s.x);
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_Py(s in Secret::arbitrary_with((20, 100))) {
        prop_assert_eq!(&s.public.Py * &s.w.t(), s.y);
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_Pz(s in Secret::arbitrary_with((20, 100))) {
        prop_assert_eq!(&s.public.Pz * &s.w.t(), s.z);
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_Padd(
        (c,i) in crate::circuit::arb_ckt(20, 100).prop_flat_map(|c| {
            (Just(c), pvec(any::<Field>(), 20))
        })
    ) {
        let s = Secret::new(&c, &i);
        let output = *c.eval(&i).last().unwrap();
        let zeros = Array1::from(vec![Field::ZERO; s.w.len()]);
        prop_assert_eq!(
            output == Field::ZERO,
            &s.public.Padd * &s.w.t() == zeros
        );
    }
}

// Trait for collections that allow taking `n` initial elements while ensuring
// that only zero-elements are dropped from the end.
trait TakeNZ where Self: Sized {
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

pub mod interactive {
    use super::*;

    #[derive(Debug, Clone, Copy)]
    #[allow(non_snake_case)]
    pub struct Round0 {
        U_root: merkle::Digest,
    }

    impl Round0 {
        pub fn size(&self) -> usize {
            std::mem::size_of::<merkle::Digest>()
        }
    }

    #[derive(Debug, Clone)]
    pub struct Round1 {
        // Testing interleaved Reed-Solomon codes
        r: Array1<Field>,
        // Testing addition gates
        radd: Array1<Field>,
        // Testing multiplication gates
        rx: Array1<Field>,
        ry: Array1<Field>,
        rz: Array1<Field>,
        rq: Array1<Field>,
    }

    impl Round1 {
        pub fn size(&self) -> usize {
            self.r.len() * Field::BYTES +
            self.radd.len() * Field::BYTES +
            self.rx.len() * Field::BYTES +
            self.ry.len() * Field::BYTES +
            self.rz.len() * Field::BYTES +
            self.rq.len() * Field::BYTES
        }
    }

    #[derive(Debug, Clone)]
    pub struct Round2 {
        // Testing interleaved Reed-Solomon codes
        v: Array1<Field>,
        // Testing addition gates
        qadd: Array1<Field>,
        // Testing multiplication gates
        qx: Array1<Field>,
        qy: Array1<Field>,
        qz: Array1<Field>,
        p0: Array1<Field>,
    }

    impl Round2 {
        pub fn size(&self) -> usize {
            self.v.len() * Field::BYTES +
            self.qadd.len() * Field::BYTES +
            self.qx.len() * Field::BYTES +
            self.qy.len() * Field::BYTES +
            self.qz.len() * Field::BYTES +
            self.p0.len() * Field::BYTES
        }
    }

    #[derive(Debug, Clone)]
    #[allow(non_snake_case)]
    pub struct Round3 {
        Q: Vec<usize>,
    }

    impl Round3 {
        pub fn size(&self) -> usize {
            self.Q.len() * std::mem::size_of::<usize>()
        }
    }

    #[derive(Debug, Clone)]
    #[allow(non_snake_case)]
    pub struct Round4 {
        U_lemma: merkle::Lemma,

        ux: Vec<Field>,
        uy: Vec<Field>,
        uz: Vec<Field>,
        uadd: Vec<Field>,
        u: Vec<Field>,
        u0: Vec<Field>,
    }

    impl Round4 {
        pub fn size(&self) -> usize {
            self.U_lemma.size() +
            self.ux.len() * Field::BYTES +
            self.uy.len() * Field::BYTES +
            self.uz.len() * Field::BYTES +
            self.uadd.len() * Field::BYTES +
            self.u.len() * Field::BYTES +
            self.u0.len() * Field::BYTES
        }
    }

    fn rows_to_mat(rows: Vec<Array1<Field>>) -> Array2<Field> {
        let nrows = rows.len();
        let ncols = rows[0].len();

        Array2::from_shape_vec((nrows, ncols),
            rows.iter()
                .map(|r| r.into_iter().cloned())
                .flatten()
                .collect::<Vec<Field>>()
        ).expect("Unequal matrix rows")
    }

    fn expected_proof_size(
        sigma: usize,
        n: usize,
        k: usize,
        l: usize,
        m: usize,
        t: usize,
        f_bytes: usize,
        h_bytes: usize,
    ) -> usize {
        let log_n = (n as f64).log2().ceil() as usize;

        // This is according to Section 5.3
        (n*sigma + 4*sigma*(k + l - 1) + sigma*(2*k - 1)
            + t*(4*m + 6*sigma)) * f_bytes + t*log_n*h_bytes
        // Note:       ^ Sec. 5.3 says this should be 5, but I think they're
        //               failing to count u0. It's missing from the random
        //               codewords sent in step (3) of the protocol in Sec. 4.7,
        //               but it seems to be required for the verifier to
        //               check p0 on the last line of the protocol.
    }

    #[allow(non_snake_case)]
    fn make_ra(
        P: &Params,
        ra: &Array1<Field>,
        Pa: &CsMat<Field>,
    ) -> Vec<Array1<Field>> {
        let r_dot_P = &Pa.clone().transpose_into() * ra;
        r_dot_P.exact_chunks(P.l)
            .into_iter()
            .map(|points| P.fft2_inverse(points))
            .collect()
    }

    #[allow(non_snake_case)]
    fn make_ra_Iml_Pa_neg(
        P: &Params,
        ra: &Array1<Field>,
        Pa: &CsMat<Field>,
    ) -> Vec<Array1<Field>> {
        use sprs::hstack;

        let Iml = CsMat::eye_csc(P.m * P.l);
        let Pa_neg = Pa.map(|f| f.neg());
        let IPa = hstack(&[Iml.view(), Pa_neg.view()]);

        make_ra(P, ra, &IPa)
    }

    pub struct Prover {
        secret: Secret,
    }

    impl Prover {
        pub fn new(c: &Ckt, w: &Vec<Field>) -> Self {
            Self {
                secret: Secret::new(c, w),
            }
        }

        pub fn expected_proof_size(&self) -> usize {
            let p = &self.secret.public.params;
            expected_proof_size(1,
                p.n, p.k + 1, p.l, p.m, p.t,
                Field::BYTES, std::mem::size_of::<merkle::Digest>())
        }

        pub fn round0(&self) -> Round0 {
            Round0 {
                U_root: self.secret.U_hash.root(),
            }
        }

        #[allow(non_snake_case)]
        fn make_pa(&self, Ua: &Array2<Field>) -> Vec<Array1<Field>> {
            let P = &self.secret.public.params;

            Ua.genrows()
                .into_iter()
                .map(|points|
                    P.fft3_inverse(points) // deg < k + 1
                    .iter()
                    .cloned()
                    .take_nz(P.k+1)
                    .collect::<Array1<Field>>())
                .collect::<Vec<_>>()
        }

        #[allow(non_snake_case)]
        fn make_qadd(&self,
            p: &Vec<Array1<Field>>, // deg < k + 1
            Padd: &CsMat<Field>,
            r1_radd: Array1<Field>,
        ) -> Array1<Field> {
            let s = &self.secret;
            let P = &s.public.params;

            let radd_blind = P.fft3_inverse(s.uadd.view()) // deg < k + l
                .iter()
                .cloned()
                .take_nz(P.k + P.l)
                .collect::<Array1<Field>>();
            let radd = make_ra(&P, &r1_radd, &Padd) // deg < l
                .iter()
                .map(|ra_i| ra_i.iter()
                    .cloned()
                    .take_nz(P.k+1) // XXX: Should be l
                    .collect::<Array1<_>>())
                .collect::<Vec<_>>();

            radd.iter().zip(p.clone())
                .fold(radd_blind, |acc, (radd_i, p_i)|
                    padd(
                        acc.view(),
                        P.pmul2(
                            radd_i.view(),
                            p_i.view()).view())) // deg < k + l
        }

        #[allow(non_snake_case)]
        fn make_qa(&self,
            p: &Vec<Array1<Field>>, // deg < k + 1
            Pa: &CsMat<Field>,
            Ua: &Array2<Field>,
            ua: &Array1<Field>,
            r1_ra: Array1<Field>,
        ) -> Array1<Field> {
            let P = &self.secret.public.params;

            let ra = make_ra_Iml_Pa_neg(&P, &r1_ra, &Pa) // deg < l
                .iter()
                .map(|ra_i| ra_i
                    .iter()
                    .cloned()
                    .take_nz(P.k+1) // XXX: Should be l
                    .collect::<Array1<Field>>())
                .collect::<Vec<_>>();
            let pa = Ua.genrows()
                .into_iter()
                .map(|points| P.fft3_inverse(points) // deg < k + 1
                    .iter()
                    .cloned()
                    .take_nz(P.k+1)
                    .collect::<Array1<Field>>())
                .collect::<Vec<_>>();
            let ra_blind = P.fft3_inverse(ua.view()) // deg < k + l
                .iter()
                .cloned()
                .take_nz(P.k + P.l)
                .collect::<Array1<Field>>();

            ra.iter()
                .zip(pa.iter().chain(p.clone().iter()))
                .fold(ra_blind, |acc, (ri, pi)|
                    padd(
                        acc.view(),
                        P.pmul2(
                            ri.view(),
                            pi.view()).view())) // deg < k + l
        }

        #[allow(non_snake_case)]
        fn make_p0(&self,
            u0: &Array1<Field>,
            px: &Vec<Array1<Field>>, // deg < k + 1
            py: &Vec<Array1<Field>>, // deg < k + 1
            pz: &Vec<Array1<Field>>, // deg < k + 1
            rq: Array1<Field>,
        ) -> Array1<Field> {
            let P = &self.secret.public.params;

            let r0_blind = P.fft3_inverse(u0.view()) // deg < 2k + 1
                .iter()
                .cloned()
                .take_nz(2*P.k + 1)
                .collect::<Array1<Field>>();

            rq.iter()
                .zip(px)
                .zip(py)
                .zip(pz)
                .fold(r0_blind, |acc, (((&rq_i, px_i), py_i), pz_i)| {
                    padd(
                        acc.view(),
                        std::ops::Mul::mul(
                            psub(
                                P.pmul2(
                                    px_i.view(),
                                    py_i.view()).view(),
                                pz_i.view()),
                            rq_i).view()) // deg < 2k + 1
                })
        }

        #[allow(non_snake_case)]
        pub fn round2(&self, r1: Round1) -> Round2 {
            use ndarray::{Axis, stack};

            let s = &self.secret;
            let P = &s.public.params;

            // Testing interleaved Reed-Solomon codes
            let U = stack![Axis(0), s.Uw, s.Ux, s.Uy, s.Uz];
            let p = self.make_pa(&s.Uw);
            let px = self.make_pa(&s.Ux);
            let py = self.make_pa(&s.Uy);
            let pz = self.make_pa(&s.Uz);

            let r2 = Round2 {
                v: r1.r.dot(&U) + s.u.view(),
                qadd: self.make_qadd(&p, &s.public.Padd, r1.radd),
                qx: self.make_qa(&p, &s.public.Px, &s.Ux, &s.ux, r1.rx),
                qy: self.make_qa(&p, &s.public.Py, &s.Uy, &s.uy, r1.ry),
                qz: self.make_qa(&p, &s.public.Pz, &s.Uz, &s.uz, r1.rz),
                p0: self.make_p0(&s.u0, &px, &py, &pz, r1.rq.clone()),
            };

            debug_assert_eq!(r2.v.len(), P.n);
            debug_assert_eq!(r2.qadd.len(), 2*P.k + 1); // XXX: Should be k + l
            debug_assert_eq!(r2.qx.len(), 2*P.k + 1); // XXX: Should be k + l
            debug_assert_eq!(r2.qy.len(), 2*P.k + 1); // XXX: Should be k + l
            debug_assert_eq!(r2.qz.len(), 2*P.k + 1); // XXX: Should be k + l
            debug_assert_eq!(r2.p0.len(), 2*P.k + 1);
            r2
        }

        #[allow(non_snake_case)]
        pub fn round4(&self, r3: Round3) -> Round4 {
            let s = &self.secret;
            let U = ndarray::stack(
                ndarray::Axis(0),
                &[s.Uw.view(), s.Ux.view(), s.Uy.view(), s.Uz.view()],
            ).expect("Unequal rows in round 4");

            let r4 = Round4 {
                U_lemma: merkle::Lemma::new(&s.U_hash, U.view(), &r3.Q),
                ux: r3.Q.iter().map(|&j| s.ux[j]).collect(),
                uy: r3.Q.iter().map(|&j| s.uy[j]).collect(),
                uz: r3.Q.iter().map(|&j| s.uz[j]).collect(),
                uadd: r3.Q.iter().map(|&j| s.uadd[j]).collect(),
                u: r3.Q.iter().map(|&j| s.u[j]).collect(),
                u0: r3.Q.iter().map(|&j| s.u0[j]).collect(),
            };

            let P = &s.public.params;
            let log_n = (P.n as f64).log2().ceil() as usize;
            debug_assert_eq!(r4.U_lemma.columns().len(), P.t);
            debug_assert_eq!(r4.U_lemma.columns()[0].len(), 4*P.m);
            debug_assert!(r4.U_lemma.lemmas.len() <= P.t*log_n);
            debug_assert_eq!(r4.ux.len(), P.t);
            debug_assert_eq!(r4.uy.len(), P.t);
            debug_assert_eq!(r4.uz.len(), P.t);
            debug_assert_eq!(r4.uadd.len(), P.t);
            debug_assert_eq!(r4.u.len(), P.t);
            debug_assert_eq!(r4.u0.len(), P.t);
            r4
        }
    }

    pub struct Verifier {
        public: Public,
        rng: StdRng,
        r0: Option<Round0>,
        r1: Option<Round1>,
        r2: Option<Round2>,
        r3: Option<Round3>,
    }

    impl Verifier {
        pub fn new(c: &Ckt) -> Self {
            Self {
                public: Public::new(&c),
                rng: StdRng::from_entropy(),
                r0: None,
                r1: None,
                r2: None,
                r3: None,
            }
        }

        pub fn param_info(&self) -> String {
            let p = &self.public.params;

            format!(
                "Verifier parameters: l={} t={} n={} k={} m={} e=(n-k)/4={}",
                p.l, p.t, p.n, p.k, p.m, (p.n-p.k) as f64 / 4f64)
        }

        pub fn expected_proof_size(&self) -> usize {
            let p = &self.public.params;
            expected_proof_size(1,
                p.n, p.k + 1, p.l, p.m, p.t,
                Field::BYTES, std::mem::size_of::<merkle::Digest>())
        }

        pub fn round1(&mut self, r0: Round0) -> Round1 {
            let params = &self.public.params;
            let r1 = Round1 {
                r: random_field_array(&mut self.rng, 4*params.m),
                radd: random_field_array(&mut self.rng, params.m * params.l),
                rx: random_field_array(&mut self.rng, params.m * params.l),
                ry: random_field_array(&mut self.rng, params.m * params.l),
                rz: random_field_array(&mut self.rng, params.m * params.l),
                rq: random_field_array(&mut self.rng, params.m),
            };

            self.r0 = Some(r0);
            self.r1 = Some(r1.clone());

            r1
        }

        pub fn round3(&mut self, r2: Round2) -> Round3 {
            let r3 = Round3 {
                Q: self.public.params.random_indices(&mut self.rng),
            };

            self.r2 = Some(r2);
            self.r3 = Some(r3.clone());

            r3
        }

        #[allow(non_snake_case)]
        pub fn verify(&self, r4: Round4) -> bool {
            use ndarray::{stack, Axis};

            let P = self.public.params;
            let r0 = self.r0.expect("Round 0 skipped");
            let r1 = self.r1.clone().expect("Round 1 skipped");
            let r2 = self.r2.clone().expect("Round 2 skipped");
            let r3 = self.r3.clone().expect("Round 3 skipped");

            // ra_i(zeta_c) = (ra * Pa)[m*i + c]
            let radd = rows_to_mat(make_ra(&P, &r1.radd, &self.public.Padd));
            let rx = rows_to_mat(make_ra_Iml_Pa_neg(&P, &r1.rx, &self.public.Px));
            let ry = rows_to_mat(make_ra_Iml_Pa_neg(&P, &r1.ry, &self.public.Py));
            let rz = rows_to_mat(make_ra_Iml_Pa_neg(&P, &r1.rz, &self.public.Pz));

            let Ux = r4.Ux_lemma.columns();
            let Uy = r4.Uy_lemma.columns();
            let Uz = r4.Uz_lemma.columns();
            let Uw = r4.Uw_lemma.columns();
            let U = Ux.iter().zip(Uy).zip(Uz).zip(Uw)
                .map(|(((x, y), z), w)|
                    stack!(Axis(0), x.to_owned(), y.to_owned(), z.to_owned(), w.to_owned()));

            // Testing interleaved Reed-Solomon codes
            //      for every j in Q, r*U[j] + u[j] = v[j]
            U.zip(r4.u.iter()).zip(r2.v.iter())
                .all(|((U_j, &u_j), &v_j)|
                    r1.r.dot(&U_j.to_owned()) + u_j == v_j) &&
            // Testing addition gates
            //      sum_{c in [l]} qadd(zeta_c) = 0
            (1..=P.l).map(|c|
                P.peval2(r2.qadd.view(), c)).sum::<Field>() == Field::ZERO &&
            //      for every j in Q,
            //      uadd[j] + sum_{i in [m]} radd_i(eta_j)*Uw[i,j] = qadd(eta_j)
            r3.Q.iter().zip(Uw.clone()).zip(r4.uadd.iter())
                .all(|((&j, Uw_j), &uadd_j)|
                    uadd_j + radd.column(j).dot(Uw_j)
                                == P.peval3(r2.qadd.view(), j)) &&
            // Testing multiplication gates
            //      for every a in {x,y,z}, sum_{c in [l]} qa(zeta_c) = 0
            (1..=P.l).map(|c| P.peval2(r2.qx.view(), c))
                            .sum::<Field>() == Field::ZERO &&
            (1..=P.l).map(|c| P.peval2(r2.qy.view(), c))
                            .sum::<Field>() == Field::ZERO &&
            (1..=P.l).map(|c| P.peval2(r2.qz.view(), c))
                            .sum::<Field>() == Field::ZERO &&
            //          for every j in Q,
            //          ua[j] + sum_{i in [m]} ra_i(eta_j)*Ua[i,j]
            //                + sum_{i in [m]} ra_{m+i}(eta_j)*Uw[i,j] = qa(eta_j)
            r3.Q.iter().zip(Ux.iter().chain(Uw.clone())).zip(r4.ux.iter())
                .all(|((&j, Uxw_j), &ux_j)|
                    ux_j + rx.column(j).dot(Uxw_j)
                                == P.peval3(r2.qx.view(), j)) &&
            r3.Q.iter().zip(Uy.iter().chain(Uw.clone())).zip(r4.uy.iter())
                .all(|((&j, Uyw_j), &uy_j)|
                    uy_j + ry.column(j).dot(Uyw_j)
                                == P.peval3(r2.qy.view(), j)) &&
            r3.Q.iter().zip(Uz.iter().chain(Uw.clone())).zip(r4.uz.iter())
                .all(|((&j, Uzw_j), &uz_j)|
                    uz_j + rz.column(j).dot(Uzw_j)
                                == P.peval3(r2.qz.view(), j)) &&
            //      for every c in [l], p0(zeta_c) = 0
            (1..=P.l).all(|c| P.peval2(r2.p0.view(), c) == Field::ZERO) &&
            //      for every j in Q,
            //      u0[j] + rq * (Ux[j] (.) Uy[j] - Uz[j]) = p0(eta_j)
            r3.Q.iter().zip(r4.u0.iter()).zip(Ux).zip(Uy).zip(Uz)
                .all(|((((&j, &u0_j), Ux_j), Uy_j), Uz_j)| {
                    let Uxyz = point_product(Ux_j.view(), Uy_j.view()) + Uz_j;
                    u0_j + r1.rq.dot(&Uxyz) == P.peval3(r2.p0.view(), j)
                }) &&
            // Check column hashes
            r4.Uw_lemma.verify(&r0.Uw_root) &&
            r4.Ux_lemma.verify(&r0.Ux_root) &&
            r4.Uy_lemma.verify(&r0.Uy_root) &&
            r4.Uz_lemma.verify(&r0.Uz_root)
        }
    }

    #[cfg(test)]
    proptest! {
        #[test]
        fn test_interactive_proof(
            (ckt, w) in any_with::<Ckt>((20, 1000)).prop_flat_map(|ckt| {
                let w = pvec(any::<Field>(), ckt.inp_size);
                (Just(ckt), w)
            })
        ) {
            let output = *ckt.eval(&w).last().unwrap();
            let p = Prover::new(&ckt, &w);
            let mut v = Verifier::new(&ckt);

            let r0 = p.round0();
            let r1 = v.round1(r0);
            let r2 = p.round2(r1);
            let r3 = v.round3(r2);
            let r4 = p.round4(r3);

            prop_assert_eq!(v.verify(r4), output == Field::ZERO);
        }

        #[test]
        fn test_interactive_proof_true(
            (ckt, w) in crate::circuit::arb_ckt_zero(20, 100)
        ) {
            let p = Prover::new(&ckt, &w);
            let mut v = Verifier::new(&ckt);

            let r0 = p.round0();
            let r1 = v.round1(r0);
            let r2 = p.round2(r1);
            let r3 = v.round3(r2);
            let r4 = p.round4(r3);

            prop_assert!(v.verify(r4));
        }
    }
}
