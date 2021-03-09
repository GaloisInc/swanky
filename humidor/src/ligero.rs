use ndarray::{Array1, Array2, ArrayView1, ArrayView2, Zip};
use sprs::{CsMat, TriMat};

#[cfg(test)]
use proptest::{*, prelude::*, collection::vec as pvec};

use crate::circuit::{Op, Ckt};
use crate::merkle;
use crate::util::*;
use crate::params::Params;

//
// XXX: Use a silly field for now.
//
type Field = crate::f5038849::F;

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
        let params = Params::new(c.size());

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

        Public {params,
            Px: Px.to_csc(),
            Py: Py.to_csc(),
            Pz: Pz.to_csc(),
            Padd: Padd.to_csc(),

        }
    }

    #[cfg(test)]
    fn test_value() -> Self {
        Self::new(&Ckt::test_value())
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
            let codeword_check = publ.params.codeword_is_valid(self.w.view());
            let leaves_check = self.Q_lemma.verify(root);
            let columns_check = self.Q_lemma.columns().iter().zip(Q)
                .fold(true, |acc, (cj, &j)|
                    acc && (r.dot(cj) == self.w[j as usize]));

            codeword_check && leaves_check && columns_check
        }
    }

    #[cfg(test)]
    fn arb_ixs(max: usize, count: usize) -> impl Strategy<Value = Vec<usize>> {
        Strategy::prop_shuffle(Just((0..max).collect::<Vec<usize>>()))
            .prop_map(move |ixs| {
                ixs.iter().take(count).cloned().collect()
            })
    }

    #[cfg(test)]
    proptest! {
        #[test]
        #[allow(non_snake_case)]
        fn test_interleaved_code_Uw(
            (c, i, r, Q) in any_with::<Ckt>((20, 1000)).prop_flat_map(|c| {
                let p = Public::new(&c);
                let i = pvec(any::<Field>(), c.inp_size);
                let r = pvec(any::<Field>(), p.params.m);
                let Q = arb_ixs(p.params.n, p.params.t);
                (Just(c), i, r, Q)
            })
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
            p: &Params,
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

            // XXX: There should be k coefficients, not n+1. Should be able
            // to take the first k, since the rest should be zeros.
            let mut p_coeffs = Array2::zeros((p.m, p.n+1));
            Zip::from(p_coeffs.genrows_mut())
                .and(U.genrows())
                .apply(|mut pi_coeffs, Ui| {
                    pi_coeffs.assign(&p.fft3_inverse(Ui.view()));
                });

            // XXX: There should be l+k+1 coefficients, not k+n+2. Should be
            // able to take the first l+k+1, since the rest should be zeros.
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
            //    (1..=p.l)
            //        .map(|i| p.peval2(q_coeffs.view(), i).positivize())
            //        .collect::<Vec<Field>>(),
            //    (1..=p.l)
            //        .map(|i|
            //            Zip::from(a_coeffs.genrows())
            //                .and(p_coeffs.genrows())
            //                .fold(Field::ZERO, |acc, ai, pi|
            //                    acc + p.peval2(ai, i) * p.peval2(pi, i)).positivize())
            //        .collect::<Vec<Field>>(),
            //);
            //debug_assert_eq!((0..=p.l).fold(Field::ZERO,
            //        |acc, ix| acc + p.peval2(q_coeffs.view(), ix)),
            //        Field::ZERO);
            Self { U_Q, q: q_coeffs }
        }

        #[allow(non_snake_case)]
        pub fn verify(&self,
            p: &Params,
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
            let q_points = (1 ..= p.l).map(|ix|
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
            p: &Params,
            A: ArrayView2<Field>,
            r: ArrayView1<Field>,
        ) -> Result<Array2<Field>, ndarray::ShapeError> {
            let a = r.dot(&A).into_shape((p.m, p.l))?;

            // XXX: There should be l coefficients here, not (k+1). Should be
            // able to take the first l, since the rest should be zeros.
            let mut a_coeffs = Array2::zeros((p.m, p.k+1));
            Zip::from(a_coeffs.genrows_mut())
                .and(a.genrows())
                .apply(|mut ai_coeffs, ai| {
                    ai_coeffs.assign(&p.fft2_inverse(ai));
                });

            Ok(a_coeffs)
        }
    }

    #[cfg(test)]
    proptest! {
        #[test]
        #[allow(non_snake_case)]
        fn test_linear_constraints(
            (c, i, r, Q) in any_with::<Ckt>((5, 5)).prop_flat_map(|c| {
                let p = Params::new(c.size());
                let i = pvec(any::<Field>(), c.inp_size);
                let r = pvec(any::<Field>(), p.m * p.l);
                let Q = arb_ixs(p.n, p.t);
                (Just(c), i, r, Q)
            })
        ) {
            let s = Secret::new(&c, &i);
            let p = s.public.params;
            let A = s.public.Padd.to_dense();
            let b = Array1::zeros(p.m * p.l);
            let proof = LinearConstraintsCheck::new(
                &p,
                A.view(),
                s.Uw.view(),
                ArrayView1::from(&r),
                &Q
            );

            assert!(proof.verify(
                &p,
                A.view(),
                ArrayView1::from(&r),
                b.view(),
                &Q,
            ));
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
            params: &Params,
            a: ArrayView1<Field>,
            b: ArrayView1<Field>,
            Ux: ArrayView2<Field>,
            Uy: ArrayView2<Field>,
            Uz: ArrayView2<Field>,
            r: ArrayView1<Field>,
            Q: &Vec<usize>,
        ) -> Self {
            debug_assert_eq!(a.len(), params.m * params.l);
            debug_assert_eq!(b.len(), params.m * params.l);
            debug_assert_eq!(r.len(), params.m);
            debug_assert_eq!(Q.len(), params.t);

            // XXX: These are all (k+1) coefficients long, wherass pa, pb
            // should be l coefficients and px, py, pz should be k.
            let pa = params.word_to_coeffs(a);
            let pb = params.word_to_coeffs(b);
            let px = params.codeword_to_coeffs(Ux, params.k+1);
            let py = params.codeword_to_coeffs(Uy, params.k+1);
            let pz = params.codeword_to_coeffs(Uz, params.k+1);

            // XXX: This has (2k+1) coefficients, whereas it should have
            // (2k-1). Why?
            let mut p = Array2::zeros((params.m, 2*params.k + 1));
            Zip::from(p.genrows_mut())
                .and(pa.genrows())
                .and(pb.genrows())
                .and(px.genrows())
                .and(py.genrows())
                .and(pz.genrows())
                .apply(|mut p_i, pa_i, pb_i, px_i, py_i, pz_i| {
                    let dim = p_i.len();
                    let pxy_i = pad_or_unpad(pmul(px_i, py_i).view(), dim);
                    let paz_i = pad_or_unpad(pmul(pa_i, pz_i).view(), dim);
                    let pb_i0 = pad_or_unpad(pb_i.view(), dim);

                    //debug_assert_eq!(
                    //    (1 ..= params.l).map(|c| {
                    //        let pa_ic = params.peval2(pa_i.view(), c);
                    //        let pb_ic = params.peval2(pb_i.view(), c);
                    //        let px_ic = params.peval2(px_i.view(), c);
                    //        let py_ic = params.peval2(py_i.view(), c);
                    //        let pz_ic = params.peval2(pz_i.view(), c);
                    //        px_ic*py_ic + pa_ic*pz_ic - pb_ic
                    //    }).collect::<Array1<Field>>(),
                    //    Array1::zeros(params.l),
                    //);
                    p_i.assign(&(pxy_i + paz_i - pb_i0));
                });

            let p0 = r.dot(&p);

            let Ux_Q: Vec<Array1<Field>> = Q.iter().map(|&j| Ux.column(j).to_owned()).collect();
            let Uy_Q: Vec<Array1<Field>> = Q.iter().map(|&j| Uy.column(j).to_owned()).collect();
            let Uz_Q: Vec<Array1<Field>> = Q.iter().map(|&j| Uz.column(j).to_owned()).collect();

            Self { Ux_Q, Uy_Q, Uz_Q, p0 }
        }

        #[allow(non_snake_case)]
        pub fn verify(&self,
            p: &Params,
            a: ArrayView1<Field>,
            b: ArrayView1<Field>,
            r: ArrayView1<Field>,
            Q: &Vec<usize>,
        ) -> bool {
            debug_assert_eq!(a.len(), p.m * p.l);
            debug_assert_eq!(b.len(), p.m * p.l);
            debug_assert_eq!(r.len(), p.m);
            debug_assert_eq!(Q.len(), p.t);

            let zero_check = (1 ..= p.l).fold(true, |acc, c| {
                let p0_c = p.peval2(self.p0.view(), c);

                acc && (p0_c == Field::ZERO)
            });

            let Ua_Q = p.peval3_rows_at(p.word_to_coeffs(a).view(), Q);
            let Ub_Q = p.peval3_rows_at(p.word_to_coeffs(b).view(), Q);
            let r_UxUy_UaUz_Ub_Q = Ua_Q.iter().map(|c| c.view())
                .zip(Ub_Q.iter().map(|c| c.view()))
                .zip(self.Ux_Q.iter().map(|c| c.view()))
                .zip(self.Uy_Q.iter().map(|c| c.view()))
                .zip(self.Uz_Q.iter().map(|c| c.view()))
                .map(|((((a, b), x), y), z)|
                    r.dot(&(point_product(x,y) + point_product(a,z) - b))
                ).collect::<Vec<Field>>();
            let p0_Q = Q.iter()
                .map(|&j| p.peval3(self.p0.view(), j+1))
                .collect::<Vec<Field>>();
            let column_check = r_UxUy_UaUz_Ub_Q == p0_Q;

            zero_check && column_check
        }
    }

    #[cfg(test)]
    proptest! {
        #[test]
        #[allow(non_snake_case)]
        fn test_quadratic_constraints(
            (c, i, r, Q) in any_with::<Ckt>((20, 2000)).prop_flat_map(|c| {
                let p = Params::new(c.size());
                let i = pvec(any::<Field>(), c.inp_size);
                let r = pvec(any::<Field>(), p.m);
                let Q = arb_ixs(p.n, p.t);
                (Just(c), i, r, Q)
            })
        ) {
            let s = Secret::new(&c, &i);
            let p = s.public.params;
            let a = Array1::from(vec![Field::ONE.neg(); p.m * p.l]);
            let b = Array1::zeros(p.m * p.l);
            let proof = QuadraticConstraintsCheck::new(
                &p,
                a.view(),
                b.view(),
                s.Ux.view(),
                s.Uy.view(),
                s.Uz.view(),
                ArrayView1::from(&r),
                &Q,
            );

            assert!(proof.verify(
                &p,
                a.view(),
                b.view(),
                ArrayView1::from(&r),
                &Q,
            ));
        }
    }
}
