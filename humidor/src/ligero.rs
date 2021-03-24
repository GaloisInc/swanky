use ndarray::{Array1, Array2, ArrayView1};
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

#[cfg(test)]
impl Arbitrary for Public {
    type Parameters = <Ckt as Arbitrary>::Parameters;
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(p: Self::Parameters) -> Self::Strategy {
        Ckt::arbitrary_with(p).prop_flat_map(|c| Just(Self::new(&c))).boxed()
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
        let mut rng = StdRng::from_entropy();

        let ml = public.params.m * public.params.l;
        let mut x = Array1::zeros(ml);
        let mut y = Array1::zeros(ml);
        let mut z = Array1::zeros(ml);
        let w = pad_array(ArrayView1::from(&c.eval(&inp)), ml);

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

        let Uw_hash = merkle::make_tree(Uw.view());
        let Ux_hash = merkle::make_tree(Ux.view());
        let Uy_hash = merkle::make_tree(Uy.view());
        let Uz_hash = merkle::make_tree(Uz.view());

        Secret {
            public,
            w, x, y, z,
            Uw, Ux, Uy, Uz,
            u, ux, uy, uz, u0, uadd,
            Uw_hash, Ux_hash, Uy_hash, Uz_hash,
        }
    }
}

#[cfg(test)]
impl Arbitrary for Secret {
    type Parameters = (usize, usize);
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(p: Self::Parameters) -> Self::Strategy {
        (
            any_with::<Ckt>(p),
            pvec(any::<Field>(), p.0),
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
    fn test_Padd(
        (c,i) in any_with::<Ckt>((20, 1000)).prop_flat_map(|c| {
            (Just(c), pvec(any::<Field>(), 20))
        })
    ) {
        let s = Secret::new(&c, &i);
        let output = *c.eval(&i).last().unwrap();
        let zeros = Array1::from(vec![0.into(); s.w.len()]);
        prop_assert_eq!(
            output == Field::ZERO,
            &s.public.Padd * &s.w.t() == zeros
        );
    }
}

pub mod interactive {
    use super::*;

    #[derive(Debug, Clone, Copy)]
    #[allow(non_snake_case)]
    pub struct Round0 {
        Uw_root: merkle::Digest,
        Ux_root: merkle::Digest,
        Uy_root: merkle::Digest,
        Uz_root: merkle::Digest,
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

    #[derive(Debug, Clone)]
    #[allow(non_snake_case)]
    pub struct Round3 {
        Q: Vec<usize>,
    }

    #[derive(Debug, Clone)]
    #[allow(non_snake_case)]
    pub struct Round4 {
        Uw_lemma: merkle::Lemma,
        Ux_lemma: merkle::Lemma,
        Uy_lemma: merkle::Lemma,
        Uz_lemma: merkle::Lemma,

        ux: Array1<Field>,
        uy: Array1<Field>,
        uz: Array1<Field>,
        uadd: Array1<Field>,
        u: Array1<Field>,
        u0: Array1<Field>,
    }

    #[allow(non_snake_case)]
    fn make_ra(
        P: &Params,
        r1_ra: &Array1<Field>,
        Pa: &CsMat<Field>,
    ) -> Vec<Array1<Field>> {
        let r_dot_P = &Pa.clone().transpose_into() * r1_ra;
        r_dot_P.exact_chunks(P.l)
            .into_iter()
            .map(|points| P.fft2_inverse(points))
            .collect()
    }

    #[allow(non_snake_case)]
    fn make_ra_Iml_Pa_neg(
        P: &Params,
        r1_ra: &Array1<Field>,
        Pa: &CsMat<Field>,
    ) -> Vec<Array1<Field>> {
        use sprs::hstack;

        let Iml = CsMat::eye_csc(P.m * P.l);
        let Pa_neg = Pa.map(|f| f.neg());
        let IPa = hstack(&[Iml.view(), Pa_neg.view()]);

        make_ra(P, r1_ra, &IPa)
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

    pub struct Prover {
        secret: Secret,
    }

    impl Prover {
        pub fn new(c: &Ckt, w: &Vec<Field>) -> Self {
            Self {
                secret: Secret::new(c, w),
            }
        }

        pub fn round0(&self) -> Round0 {
            Round0 {
                Uw_root: self.secret.Uw_hash.root(),
                Ux_root: self.secret.Ux_hash.root(),
                Uy_root: self.secret.Uy_hash.root(),
                Uz_root: self.secret.Uz_hash.root(),
            }
        }

        #[allow(non_snake_case)]
        fn make_pa(&self, Ua: &Array2<Field>) -> Vec<Array1<Field>> {
            let P = self.secret.public.params;

            Ua.genrows()
                .into_iter()
                .map(|points|
                    pad_or_unpad(P.fft3_inverse(points).view(), P.k+1)) // deg < l - 1
                .collect::<Vec<Array1<Field>>>()
        }

        #[allow(non_snake_case)]
        fn make_qadd(&self,
            p: &Vec<Array1<Field>>,
            Padd: &CsMat<Field>,
            r1_radd: Array1<Field>,
        ) -> Array1<Field> {
            let s = &self.secret;
            let P = s.public.params;

            // Testing addition gates
            let radd_blind = P.fft3_inverse(s.uadd.view()); // deg < k + l - 1 (?)
            let radd = make_ra(&P, &r1_radd, &Padd);
            let radd_p = radd.iter().zip(p.clone())
                .fold(Array1::zeros(2*(P.k+1)), |acc, (radd_i, p_i)|
                    acc + pmul(radd_i.view(), p_i.view()));

            pad_or_unpad(radd_blind.view(), 2*(P.k+1)) + radd_p
        }

        #[allow(non_snake_case)]
        fn make_qa(&self,
            p: &Vec<Array1<Field>>,
            Pa: &CsMat<Field>,
            Ua: &Array2<Field>,
            ua: &Array1<Field>,
            r1_ra: Array1<Field>,
        ) -> Array1<Field> {
            let P = self.secret.public.params;

            let ra = make_ra_Iml_Pa_neg(&P, &r1_ra, &Pa);
            let pa = Ua.genrows()
                .into_iter()
                .map(|points|
                    pad_or_unpad(P.fft3_inverse(points).view(), P.k+1)) // deg < l - 1
                .collect::<Vec<Array1<Field>>>();
            let ra_blind = P.fft3_inverse(ua.view());
            let ra_pa_p = ra.iter()
                .zip(pa.iter().chain(p.clone().iter()))
                .fold(Array1::zeros(2*(P.k+1)), |acc: Array1<Field>, (ri, pi)|
                    acc + pmul(ri.view(), pi.view()));

            pad_or_unpad(ra_blind.view(), 2*(P.k+1)) + ra_pa_p
        }

        #[allow(non_snake_case)]
        fn make_p0(&self,
            u0: &Array1<Field>,
            px: &Vec<Array1<Field>>,
            py: &Vec<Array1<Field>>,
            pz: &Vec<Array1<Field>>,
            r1_rq: Array1<Field>,
        ) -> Array1<Field> {
            let P = self.secret.public.params;

            let r0_blind = pad_or_unpad(P.fft3_inverse(u0.view()).view(), 2*(P.k+1));
            let rq_px_py_pz = r1_rq.iter()
                .zip(px.iter())
                .zip(py.iter())
                .zip(pz.iter())
                .fold(Array1::zeros(2*(P.k+1)),
                    |acc, (((&rq_i, px_i), py_i), pz_i)| {
                        let pxy_i = pmul(px_i.view(), py_i.view());
                        let pz0_i = pad_or_unpad(pz_i.view(), 2*(P.k+1));

                        acc + ((pxy_i - pz0_i) * rq_i)
                    });

            r0_blind + rq_px_py_pz
        }

        #[allow(non_snake_case)]
        pub fn round2(&self, r1: Round1) -> Round2 {
            use ndarray::{Axis, stack};

            let s = &self.secret;

            // Testing interleaved Reed-Solomon codes
            let U = stack![Axis(0), s.Uw, s.Ux, s.Uy, s.Uz];
            let p = self.make_pa(&self.secret.Uw);
            let px = self.make_pa(&self.secret.Ux);
            let py = self.make_pa(&self.secret.Uy);
            let pz = self.make_pa(&self.secret.Uz);

            Round2 {
                v: r1.r.dot(&U),
                qadd: self.make_qadd(&p, &s.public.Padd, r1.radd),
                qx: self.make_qa(&p, &s.public.Px, &s.Ux, &s.ux, r1.rx),
                qy: self.make_qa(&p, &s.public.Py, &s.Uy, &s.uy, r1.ry),
                qz: self.make_qa(&p, &s.public.Pz, &s.Uz, &s.uz, r1.rz),
                p0: self.make_p0(&s.u0, &px, &py, &pz, r1.rq),
            }
        }

        #[allow(non_snake_case)]
        pub fn round4(&self, r3: Round3) -> Round4 {
            let s = &self.secret;

            Round4 {
                Uw_lemma: merkle::Lemma::new(&s.Uw_hash, s.Uw.view(), &r3.Q),
                Ux_lemma: merkle::Lemma::new(&s.Ux_hash, s.Ux.view(), &r3.Q),
                Uy_lemma: merkle::Lemma::new(&s.Uy_hash, s.Uy.view(), &r3.Q),
                Uz_lemma: merkle::Lemma::new(&s.Uz_hash, s.Uz.view(), &r3.Q),
                ux: s.ux.clone(),
                uy: s.uy.clone(),
                uz: s.uz.clone(),
                uadd: s.uadd.clone(),
                u: s.u.clone(),
                u0: s.u0.clone(),
            }
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

        pub fn round1(&mut self, r0: Round0) -> Round1 {
            let params = self.public.params;
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
            (ckt, w) in any_with::<Ckt>((5, 5)).prop_flat_map(|ckt| {
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
    }
}
