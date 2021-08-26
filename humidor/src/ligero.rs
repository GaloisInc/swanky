// This file is part of `humidor`.
// Copyright © 2021 Galois, Inc.
// See LICENSE for licensing information.

//! This module implements Ligero according to section 4.7 of
//! https://dl.acm.org/doi/pdf/10.1145/3133956.3134104

// TODO: Eliminate excessive use of vectors in anonymous functions, function
// return values, etc.

use ndarray::{Array1, Array2};
use sprs::{CsMat, TriMat};
use rand::{SeedableRng, rngs::StdRng};
use scuttlebutt::field::FiniteField;
use scuttlebutt::numtheory::{FieldForFFT2, FieldForFFT3};

#[cfg(test)]
use proptest::{*, prelude::*, collection::vec as pvec};

use crate::circuit::{Op, Ckt};
use crate::merkle;
use crate::util::*;
use crate::params::Params;

/// This is a marker trait consolidating the traits needed for a Ligero field.
/// In addition, it supplies a field-width in bits, to be used in parameter
/// selection.
pub trait FieldForLigero:
    Sized
    + FiniteField
    + FieldForFFT2
    + FieldForFFT3
    + num_traits::Num
    + ndarray::ScalarOperand
    + std::fmt::Debug
{
    /// Minimum bits to represent a field element. This will correspond to the
    /// security parameter `t` during paremeter selection.
    const BITS: usize;
}

impl FieldForLigero for scuttlebutt::field::F2_19x3_26 {
    const BITS: usize = 61;
}

/// Proof information available to both the prover and the verifier.
#[derive(Debug, Clone)]
#[allow(non_snake_case)]
struct Public<Field> {
    params: crate::params::Params<Field>,

    Px: CsMat<Field>,
    Py: CsMat<Field>,
    Pz: CsMat<Field>,
    Padd: CsMat<Field>,
}

impl<Field: FieldForLigero> Public<Field> {
    #[allow(non_snake_case)]
    fn new(c: &Ckt<Field>) -> Self {
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
                    Padd.add_triplet(s, s + c.inp_size, -Field::ONE);
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

/// Proof information available only to the prover.
#[allow(non_snake_case)]
struct Secret<Field, H> {
    public: Public<Field>,

    // XXX: w is not sparse, but x, y, z likely are (with linear sparsity).
    // Use CsVec?
    w: Array1<Field>, // Extended witness padded to l*m elements
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

    U_hash: merkle::Tree<H>,
}

impl<Field, H> std::fmt::Debug for Secret<Field, H>
    where Field: std::fmt::Debug
{
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
impl<Field: FieldForLigero, H: merkle::MerkleHash> Secret<Field, H> {
    fn new(c: &Ckt<Field>, inp: &[Field]) -> Self {
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
            .chain(std::iter::repeat(Field::ZERO).take(ml - c.size()))
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
impl<H: merkle::MerkleHash> Arbitrary for Secret<TestField, H> {
    type Parameters = (usize, usize);
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with((w,c): Self::Parameters) -> Self::Strategy {
        (
            crate::circuit::arb_ckt(w,c),
            pvec(arb_test_field(), w),
        ).prop_map(|(ckt, inp)|
            <Secret<TestField, H>>::new(&ckt, &inp)
        ).boxed()
    }
}

#[cfg(test)]
proptest! {
    #[test]
    #[allow(non_snake_case)]
    fn test_Px(s in <Secret<TestField, merkle::Sha256>>
        ::arbitrary_with((20, 100))) {
            prop_assert_eq!(&s.public.Px * &s.w.t(), s.x);
        }

    #[test]
    #[allow(non_snake_case)]
    fn test_Py(s in <Secret<TestField, merkle::Sha256>>
        ::arbitrary_with((20, 100))) {
            prop_assert_eq!(&s.public.Py * &s.w.t(), s.y);
        }

    #[test]
    #[allow(non_snake_case)]
    fn test_Pz(s in <Secret<TestField, merkle::Sha256>>
        ::arbitrary_with((20, 100))) {
            prop_assert_eq!(&s.public.Pz * &s.w.t(), s.z);
        }

    #[test]
    #[allow(non_snake_case)]
    fn test_Padd(
        (c,i) in crate::circuit::arb_ckt(20, 100).prop_flat_map(|c| {
            (Just(c), pvec(arb_test_field(), 20))
        })
    ) {
        let s: Secret<_, merkle::Sha256> = Secret::new(&c, &i);
        let output = *c.eval(&i).last().unwrap();
        let zeros = Array1::from(vec![TestField::ZERO; s.w.len()]);
        prop_assert_eq!(
            output == TestField::ZERO,
            &s.public.Padd * &s.w.t() == zeros
        );
    }
}

/// The theoretical proof size according to Section 5.3 of
/// https://dl.acm.org/doi/pdf/10.1145/3133956.3134104
pub fn expected_proof_size(
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

/// Round 0: Prover -> Verifier
/// * Merkle-tree digest of interleaved codewords.
#[derive(Debug, Clone, Copy)]
#[allow(non_snake_case)]
pub struct Round0 {
    U_root: merkle::Digest,
}

impl Round0 {
    /// Actual size of this round of communication.
    pub fn size(&self) -> usize {
        std::mem::size_of::<merkle::Digest>()
    }
}

/// Round 1: Verifier -> Prover
/// * Random linear-combination challenges for interleaved codewords.
#[derive(Debug, Clone)]
pub struct Round1<Field> {
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

impl<Field: FieldForLigero> Round1<Field> {
    /// Generate verifier's random linear-combination challenges.
    fn new(params: &Params<Field>, rng: &mut impl rand::Rng) -> Self {
        Round1 {
            r: random_field_array(rng, 4*params.m),
            radd: random_field_array(rng, params.m * params.l),
            rx: random_field_array(rng, params.m * params.l),
            ry: random_field_array(rng, params.m * params.l),
            rz: random_field_array(rng, params.m * params.l),
            rq: random_field_array(rng, params.m),
        }
    }

    /// Actual size of this round of communication.
    pub fn size(&self) -> usize {
        self.r.len() * std::mem::size_of::<Field>() +
        self.radd.len() * std::mem::size_of::<Field>() +
        self.rx.len() * std::mem::size_of::<Field>() +
        self.ry.len() * std::mem::size_of::<Field>() +
        self.rz.len() * std::mem::size_of::<Field>() +
        self.rq.len() * std::mem::size_of::<Field>()
    }
}

/// Round 2: Prover -> Verifier
/// * Linear combinations corresponding to verifier's challenges.
#[derive(Debug, Clone)]
pub struct Round2<Field> {
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

impl<Field> Round2<Field> {
    /// Actual size of this round of communication.
    pub fn size(&self) -> usize {
        self.v.len() * std::mem::size_of::<Field>() +
        self.qadd.len() * std::mem::size_of::<Field>() +
        self.qx.len() * std::mem::size_of::<Field>() +
        self.qy.len() * std::mem::size_of::<Field>() +
        self.qz.len() * std::mem::size_of::<Field>() +
        self.p0.len() * std::mem::size_of::<Field>()
    }
}

/// Round 3: Verifier -> Prover
/// * Verifier's random choice of t columns do view.
#[derive(Debug, Clone)]
#[allow(non_snake_case)]
pub struct Round3<Field> {
    phantom: std::marker::PhantomData<Field>,

    Q: Vec<usize>,
}

impl<Field: FieldForLigero> Round3<Field> {
    /// Pick Verifier's columns to view.
    fn new(params: &Params<Field>, rng: &mut impl rand::Rng) -> Self {
        Round3 {
            phantom: std::marker::PhantomData,

            Q: params.random_indices(rng),
        }
    }

    /// Actual size of this round of communication.
    pub fn size(&self) -> usize {
        self.Q.len() * std::mem::size_of::<usize>()
    }
}

/// Round 4: Prover -> Verifier
/// * Revealed columns.
/// * Merkle proof of revealed columns.
#[derive(Debug, Clone)]
#[allow(non_snake_case)]
pub struct Round4<Field, H> {
    U_lemma: merkle::Lemma<Field, H>,

    ux: Vec<Field>,
    uy: Vec<Field>,
    uz: Vec<Field>,
    uadd: Vec<Field>,
    u: Vec<Field>,
    u0: Vec<Field>, // This is missing in Sec. 4.7, but I think it's needed
}

impl<Field: FieldForLigero, H: merkle::MerkleHash> Round4<Field, H> {
    /// Actual size of this round of communication.
    pub fn size(&self) -> usize {
        self.U_lemma.size() +
        self.ux.len() * std::mem::size_of::<Field>() +
        self.uy.len() * std::mem::size_of::<Field>() +
        self.uz.len() * std::mem::size_of::<Field>() +
        self.uadd.len() * std::mem::size_of::<Field>() +
        self.u.len() * std::mem::size_of::<Field>() +
        self.u0.len() * std::mem::size_of::<Field>()
    }
}

// The following code corresponds as closely as possible (with a few
// optimizations) to the pseudocode in Section 4.7 of
// https://dl.acm.org/doi/pdf/11.1145/3133956.3134104.
//
// Note: In order to increase the visual similarity to this pseudocode, some
// variables are not in snake case.

#[allow(non_snake_case)]
fn make_ra<Field: FieldForLigero>(
    P: &Params<Field>,
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
fn make_ra_Iml_Pa_neg<Field: FieldForLigero>(
    P: &Params<Field>,
    ra: &Array1<Field>,
    Pa: &CsMat<Field>,
) -> Vec<Array1<Field>> {
    use sprs::hstack;

    let Iml = CsMat::eye_csc(P.m * P.l);
    let Pa_neg = Pa.map(|f| -(*f));
    let IPa = hstack(&[Iml.view(), Pa_neg.view()]);

    make_ra(P, ra, &IPa)
}

#[allow(non_snake_case)]
fn make_pa<Field: FieldForLigero>(
    P: &Params<Field>,
    Ua: &Array2<Field>,
) -> Vec<Array1<Field>>
{
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
fn make_qadd<Field: FieldForLigero, H>(
    s: &Secret<Field, H>,
    p: &Vec<Array1<Field>>, // deg < k + 1
    Padd: &CsMat<Field>,
    r1_radd: Array1<Field>,
) -> Array1<Field> {
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
            .take_nz(P.k+1) // XXX: Should be l, per Sec. 4.7
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
fn make_qa<Field: FieldForLigero>(
    P: &Params<Field>,
    p: &Vec<Array1<Field>>, // deg < k + 1
    Pa: &CsMat<Field>,
    Ua: &Array2<Field>,
    ua: &Array1<Field>,
    r1_ra: Array1<Field>,
) -> Array1<Field> {
    let ra = make_ra_Iml_Pa_neg(&P, &r1_ra, &Pa) // deg < l
        .iter()
        .map(|ra_i| ra_i
            .iter()
            .cloned()
            .take_nz(P.k+1) // XXX: Should be l, per Sec. 4.7
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
fn make_p0<Field: FieldForLigero>(
    P: &Params<Field>,
    u0: &Array1<Field>,
    px: &Vec<Array1<Field>>, // deg < k + 1
    py: &Vec<Array1<Field>>, // deg < k + 1
    pz: &Vec<Array1<Field>>, // deg < k + 1
    rq: Array1<Field>,
) -> Array1<Field> {
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
fn verify<Field: FieldForLigero, H: merkle::MerkleHash>(
    public: &Public<Field>,
    r0: Round0,
    r1: Round1<Field>,
    r2: Round2<Field>,
    r3: Round3<Field>,
    r4: Round4<Field, H>,
) -> bool {
    use ndarray::{s, stack, Axis};

    let P = &public.params;

    // ra_i(zeta_c) = (ra * Pa)[m*i + c]
    let radd = rows_to_mat(make_ra(&P, &r1.radd, &public.Padd)
        .iter().map(|r| P.fft3(r.view())).collect::<Vec<_>>());
    let rx = rows_to_mat(make_ra_Iml_Pa_neg(&P, &r1.rx, &public.Px)
        .iter().map(|r| P.fft3(r.view())).collect::<Vec<_>>());
    let ry = rows_to_mat(make_ra_Iml_Pa_neg(&P, &r1.ry, &public.Py)
        .iter().map(|r| P.fft3(r.view())).collect::<Vec<_>>());
    let rz = rows_to_mat(make_ra_Iml_Pa_neg(&P, &r1.rz, &public.Pz)
        .iter().map(|r| P.fft3(r.view())).collect::<Vec<_>>());

    let U = r4.U_lemma.columns.clone();
    let Uw: Vec<Array1<Field>> = U.iter()
        .map(|c| c.slice(s![0*P.m..1*P.m]).to_owned()).collect();
    let Ux: Vec<Array1<Field>> = U.iter()
        .map(|c| c.slice(s![1*P.m..2*P.m]).to_owned()).collect();
    let Uy: Vec<Array1<Field>> = U.iter()
        .map(|c| c.slice(s![2*P.m..3*P.m]).to_owned()).collect();
    let Uz: Vec<Array1<Field>> = U.iter()
        .map(|c| c.slice(s![3*P.m..4*P.m]).to_owned()).collect();

    // Testing interleaved Reed-Solomon codes
    //      for every j in Q, r*U[j] + u[j] = v[j]
    r3.Q.iter().zip(U).zip(r4.u)
        .all(|((&j, U_j), u_j)|
            r1.r.dot(&U_j.to_owned()) + u_j == r2.v[j]) &&
    // Testing addition gates
    //      sum_{c in [l]} qadd(zeta_c) = 0
    P.fft2_peval(r2.qadd.view()).slice(s![1..=P.l]).to_owned()
        .sum() == Field::ZERO &&
    //      for every j in Q,
    //      uadd[j] + sum_{i in [m]} radd_i(eta_j)*Uw[i,j] = qadd(eta_j)
    r3.Q.iter().zip(Uw.clone()).zip(r4.uadd)
        .all(|((&j, Uw_j), uadd_j)|
            uadd_j + radd.column(j).dot(&Uw_j)
                        == P.peval3(r2.qadd.view(), j+1)) &&
    // Testing multiplication gates
    //      for every a in {x,y,z}, sum_{c in [l]} qa(zeta_c) = 0
    P.fft2_peval(r2.qx.view()).slice(s![1..=P.l]).to_owned()
        .sum() == Field::ZERO &&
    P.fft2_peval(r2.qy.view()).slice(s![1..=P.l]).to_owned()
        .sum() == Field::ZERO &&
    P.fft2_peval(r2.qz.view()).slice(s![1..=P.l]).to_owned()
        .sum() == Field::ZERO &&
    //       for every j in Q,
    //       ua[j] + sum_{i in [m]} ra_i(eta_j)*Ua[i,j]
    //             + sum_{i in [m]} ra_{m+i}(eta_j)*Uw[i,j] = qa(eta_j)
    r3.Q.iter().zip(Ux.clone()).zip(Uw.clone()).zip(r4.ux)
        .all(|(((&j, Ux_j), Uw_j), ux_j)|
            ux_j + rx.column(j).dot(&stack![Axis(0), Ux_j, Uw_j])
                        == P.peval3(r2.qx.view(), j+1)) &&
    r3.Q.iter().zip(Uy.clone()).zip(Uw.clone()).zip(r4.uy)
        .all(|(((&j, Uy_j), Uw_j), uy_j)|
            uy_j + ry.column(j).dot(&stack![Axis(0), Uy_j, Uw_j])
                        == P.peval3(r2.qy.view(), j+1)) &&
    r3.Q.iter().zip(Uz.clone()).zip(Uw.clone()).zip(r4.uz)
        .all(|(((&j, Uz_j), Uw_j), uz_j)|
            uz_j + rz.column(j).dot(&stack![Axis(0), Uz_j, Uw_j])
                        == P.peval3(r2.qz.view(), j+1)) &&
    //      for every c in [l], p0(zeta_c) = 0
    P.fft2_peval(r2.p0.view()).slice(s![1..P.l]).into_iter()
        .all(|&f| f == Field::ZERO) &&
    //      for every j in Q,
    //      u0[j] + rq * (Ux[j] (.) Uy[j] - Uz[j]) = p0(eta_j)
    r3.Q.iter().zip(r4.u0.iter()).zip(Ux).zip(Uy).zip(Uz)
        .all(|((((&j, &u0_j), Ux_j), Uy_j), Uz_j)| {
            let Uxyz_j = ndarray::Zip::from(&Ux_j)
                .and(&Uy_j)
                .and(&Uz_j)
                .apply_collect(|&x, &y, &z| x*y - z);
            u0_j + r1.rq.dot(&Uxyz_j)
                == P.peval3(r2.p0.view(), j+1)
        }) &&
    // Checking column hashes
    r4.U_lemma.verify(&r0.U_root) &&
    P.codeword_is_valid(r2.v.view())
}

/// Interactive Ligero implementation.
pub mod interactive {
    use super::*;

    /// Interactive Ligero prover.
    pub struct Prover<Field, H> {
        secret: Secret<Field, H>,
    }

    impl<Field: FieldForLigero, H: merkle::MerkleHash> Prover<Field, H> {
        /// Create an interactive prover out of a circuit and witness.
        pub fn new(c: &Ckt<Field>, w: &Vec<Field>) -> Self {
            Self {
                secret: Secret::new(c, w),
            }
        }

        /// Get the prover's parameters.
        pub fn params(&self) -> Params<Field> {
            self.secret.public.params
        }

        /// Theoretical proof size, according to Section 5.3.
        pub fn expected_proof_size(&self) -> usize {
            let p = &self.secret.public.params;
            expected_proof_size(1,
                p.n, p.k + 1, p.l, p.m, p.t,
                std::mem::size_of::<Field>(), std::mem::size_of::<merkle::Digest>())
        }

        /// Generate round-0 prover message.
        pub fn round0(&self) -> Round0 {
            Round0 {
                U_root: self.secret.U_hash.root(),
            }
        }

        /// Generate round-2 prover message.
        #[allow(non_snake_case)]
        pub fn round2(&self, r1: Round1<Field>) -> Round2<Field> {
            use ndarray::{Axis, stack};

            let s = &self.secret;
            let P = &s.public.params;

            // Testing interleaved Reed-Solomon codes
            let U = stack![Axis(0), s.Uw, s.Ux, s.Uy, s.Uz];
            let p = make_pa(P, &s.Uw);
            let px = make_pa(P, &s.Ux);
            let py = make_pa(P, &s.Uy);
            let pz = make_pa(P, &s.Uz);

            let r2 = Round2 {
                v: r1.r.dot(&U) + s.u.view(),
                qadd: make_qadd(s, &p, &s.public.Padd, r1.radd),
                qx: make_qa(P, &p, &s.public.Px, &s.Ux, &s.ux, r1.rx),
                qy: make_qa(P, &p, &s.public.Py, &s.Uy, &s.uy, r1.ry),
                qz: make_qa(P, &p, &s.public.Pz, &s.Uz, &s.uz, r1.rz),
                p0: make_p0(P, &s.u0, &px, &py, &pz, r1.rq.clone()),
            };

            debug_assert_eq!(r2.v.len(), P.n);
            debug_assert_eq!(r2.qadd.len(), 2*P.k + 1); // XXX: Should be k + l
            debug_assert_eq!(r2.qx.len(), 2*P.k + 1); // XXX: Should be k + l
            debug_assert_eq!(r2.qy.len(), 2*P.k + 1); // XXX: Should be k + l
            debug_assert_eq!(r2.qz.len(), 2*P.k + 1); // XXX: Should be k + l
            debug_assert_eq!(r2.p0.len(), 2*P.k + 1);
            r2
        }

        /// Generate round-4 prover message.
        #[allow(non_snake_case)]
        pub fn round4(&self, r3: Round3<Field>) -> Round4<Field, H> {
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
            debug_assert_eq!(r4.U_lemma.columns.len(), P.t);
            debug_assert_eq!(r4.U_lemma.columns[0].len(), 4*P.m);
            debug_assert!(r4.U_lemma.nlemmas() <= P.t*log_n);
            debug_assert_eq!(r4.ux.len(), P.t);
            debug_assert_eq!(r4.uy.len(), P.t);
            debug_assert_eq!(r4.uz.len(), P.t);
            debug_assert_eq!(r4.uadd.len(), P.t);
            debug_assert_eq!(r4.u.len(), P.t);
            debug_assert_eq!(r4.u0.len(), P.t);
            r4
        }
    }

    /// Ligero interactive verifier.
    pub struct Verifier<Field, H> {
        phantom: std::marker::PhantomData<H>,

        public: Public<Field>,
        rng: StdRng,
        r0: Option<Round0>,
        r1: Option<Round1<Field>>,
        r2: Option<Round2<Field>>,
        r3: Option<Round3<Field>>,
    }

    impl<Field: FieldForLigero, H: merkle::MerkleHash> Verifier<Field, H> {
        /// Create a new verifier from a circuit.
        pub fn new(c: &Ckt<Field>) -> Self {
            Self {
                phantom: std::marker::PhantomData,

                public: Public::new(&c),
                rng: StdRng::from_entropy(),
                r0: None,
                r1: None,
                r2: None,
                r3: None,
            }
        }

        /// Get the verifier's parameters.
        pub fn params(&self) -> Params<Field> {
            self.public.params
        }

        /// Theoretical proof size, according to Section 5.3.
        pub fn expected_proof_size(&self) -> usize {
            let p = &self.public.params;
            expected_proof_size(
                1, p.n, p.k + 1, p.l, p.m, p.t,
                std::mem::size_of::<Field>(),
                std::mem::size_of::<merkle::Digest>(),
            )
        }

        /// Generate round-1 verifier message.
        pub fn round1(&mut self, r0: Round0) -> Round1<Field> {
            let r1 = Round1::new(&self.public.params, &mut self.rng);

            self.r0 = Some(r0);
            self.r1 = Some(r1.clone());

            r1
        }

        /// Generate round-3 verifier message.
        pub fn round3(&mut self, r2: Round2<Field>) -> Round3<Field> {
            let r3 = Round3::new(&self.public.params, &mut self.rng);

            self.r2 = Some(r2);
            self.r3 = Some(r3.clone());

            r3
        }

        /// Run final verification procedure.
        pub fn verify(&self, r4: Round4<Field, H>) -> bool {
            let r0 = self.r0.expect("Round 0 skipped");
            let r1 = self.r1.clone().expect("Round 1 skipped");
            let r2 = self.r2.clone().expect("Round 2 skipped");
            let r3 = self.r3.clone().expect("Round 3 skipped");

            verify(&self.public, r0, r1, r2, r3, r4)
        }
    }

    #[test]
    fn test_small() {
        type Field = TestField;

        let ckt = Ckt::test_value();
        let w = vec![3u64.into(), 1u64.into(), 5u64.into(),
                        -(Field::from(3u64) * Field::from(5u64))];

        let output = *ckt.eval(&w).last().unwrap();
        assert_eq!(output, Field::ZERO);

        let p: Prover<_, merkle::Sha256> = Prover::new(&ckt, &w);
        let mut v = Verifier::new(&ckt);

        let r0 = p.round0();
        let r1 = v.round1(r0);
        let r2 = p.round2(r1);
        let r3 = v.round3(r2);
        let r4 = p.round4(r3);

        assert!(v.verify(r4))
    }

    #[cfg(test)]
    proptest! {
        #[test]
        fn test_false(
            (ckt, w) in crate::circuit::arb_ckt(20, 100).prop_flat_map(|ckt| {
                let w = pvec(arb_test_field(), ckt.inp_size);
                (Just(ckt), w)
            })
        ) {
            let output = *ckt.eval(&w).last().unwrap();
            let p: Prover<_, merkle::Sha256> = Prover::new(&ckt, &w);
            let mut v = Verifier::new(&ckt);

            let r0 = p.round0();
            let r1 = v.round1(r0);
            let r2 = p.round2(r1);
            let r3 = v.round3(r2);
            let r4 = p.round4(r3);

            prop_assert_eq!(v.verify(r4), output == TestField::ZERO);
        }

        #[test]
        fn test_true(
            (ckt, w) in crate::circuit::arb_ckt_zero(20, 100)
        ) {
            let p: Prover<TestField, merkle::Sha256> = Prover::new(&ckt, &w);
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

/// Non-interactive Ligero implementation, created by applying Fiat-Shamir to
/// the interactive implementation.
// XXX: This uses Fiat-Shamir. The following are to-do:
//      * Check that we're hashing the right things. We hash the columns of U
//        to seed the r vectors; we hash the columns along with the sent linear
//        combos of codewords to seed the Q indices.
//      * Fiat-Shamir comes with additional soundness error. Check that this
//        leads to acceptable security. If not, we may need to add repetitions.
//      * We generate the PRG seeds using a random oracle instantiated with the
//        same hash we use for the Merkle tree for convenience. In practice, we
//        should probably use a better RO that results in at least 32 bytes of
//        randomness, per
//        https://docs.rs/rand_core/0.5.1/rand_core/trait.SeedableRng.html.
pub mod noninteractive {
    use super::*;

    /// Complete proof message sent from prover to verifier.
    pub struct Proof<Field, H> {
        phantom: std::marker::PhantomData<H>,

        r0: Round0,
        r2: Round2<Field>,
        r4: Round4<Field, H>,
    }

    impl<Field: FieldForLigero, H: merkle::MerkleHash> Proof<Field, H> {
        /// Actual size of the non-interactive proof message.
        pub fn size(&self) -> usize {
            self.r0.size() + self.r2.size() + self.r4.size()
        }
    }

    fn make_r1<Field: FieldForLigero, H: merkle::MerkleHash>(
        params: &Params<Field>,
        state: &merkle::Digest,
        r0: &Round0
    ) -> (Round1<Field>, merkle::Digest) {
        use rand_chacha::ChaCha20Rng as ChaCha;

        let mut hash = H::new();
        hash.update(&state.to_vec());
        hash.update(&r0.U_root);

        let mut digest = merkle::HZERO;
        hash.finalize(&mut digest);

        (Round1::new(params, &mut ChaCha::from_seed(digest)), digest)
    }

    fn make_r3<Field: FieldForLigero, H: merkle::MerkleHash>(
        params: &Params<Field>,
        state: &merkle::Digest,
        r2: &Round2<Field>
    ) -> Round3<Field> {
        use rand_chacha::ChaCha20Rng as ChaCha;

        let mut hash = H::new();

        hash.update(&state.to_vec());
        r2.p0.into_iter().for_each(|f| hash.update(&f.to_bytes()));
        r2.qadd.into_iter().for_each(|f| hash.update(&f.to_bytes()));
        r2.qx.into_iter().for_each(|f| hash.update(&f.to_bytes()));
        r2.qy.into_iter().for_each(|f| hash.update(&f.to_bytes()));
        r2.qz.into_iter().for_each(|f| hash.update(&f.to_bytes()));
        r2.v.into_iter().for_each(|f| hash.update(&f.to_bytes()));

        let mut digest = merkle::HZERO;
        hash.finalize(&mut digest);

        Round3::new(params, &mut ChaCha::from_seed(digest))
    }

    /// Non-interactive Ligero prover.
    pub struct Prover<Field, H> {
        ip: interactive::Prover<Field, H>,
        ckt_hash: merkle::Digest,
    }

    impl<Field: FieldForLigero, H: merkle::MerkleHash> Prover<Field, H> {
        /// Create a non-interactive prover from a circuit and witness.
        pub fn new(c: &Ckt<Field>, w: &Vec<Field>) -> Self {
            let mut hash = H::new();
            c.ops.iter().for_each(|op| hash.update(&op.bytes()));

            let mut ckt_hash = merkle::HZERO;
            hash.finalize(&mut ckt_hash);

            Self { ckt_hash, ip: interactive::Prover::new(c, w) }
        }

        /// Theoretical proof size from Section 5.3.
        pub fn expected_proof_size(&self) -> usize {
            let p = self.ip.params();

            expected_proof_size(1,
                p.n, p.k + 1, p.l, p.m, p.t,
                std::mem::size_of::<Field>(), std::mem::size_of::<merkle::Digest>())
        }

        /// Generate the proof message.
        pub fn make_proof(&self) -> Proof<Field, H> {
            let r0 = self.ip.round0();
            let (r1,state) = make_r1::<_,H>(&self.ip.params(), &self.ckt_hash, &r0);
            let r2 = self.ip.round2(r1);
            let r3 = make_r3::<_,H>(&self.ip.params(), &state, &r2);
            let r4 = self.ip.round4(r3);

            Proof { r0, r2, r4,
                phantom: std::marker::PhantomData,
            }
        }
    }

    /// Non-interactive Ligero verifier.
    pub struct Verifier<Field, H> {
        phantom: std::marker::PhantomData<H>,

        public: Public<Field>,
        ckt_hash: merkle::Digest,
    }

    impl<Field: FieldForLigero, H: merkle::MerkleHash> Verifier<Field, H> {
        /// Create a verifier out of a circuit.
        pub fn new(ckt: &Ckt<Field>) -> Self {
            let mut hash = H::new();
            ckt.ops.iter().for_each(|op| hash.update(&op.bytes()));

            let mut ckt_hash = merkle::HZERO;
            hash.finalize(&mut ckt_hash);

            Self { ckt_hash,
                phantom: std::marker::PhantomData,

                public: Public::new(ckt),
            }
        }

        /// Theoretical proof size from Section 5.3.
        pub fn expected_proof_size(&self) -> usize {
            let p = &self.public.params;

            expected_proof_size(
                1, p.n, p.k + 1, p.l, p.m, p.t,
                std::mem::size_of::<Field>(),
                std::mem::size_of::<merkle::Digest>())
        }

        /// Run the final verification procedure.
        pub fn verify(&self, p: Proof<Field, H>) -> bool {
            let (r1,state) = make_r1::<_,H>(&self.public.params, &self.ckt_hash, &p.r0);
            let r3 = make_r3::<_,H>(&self.public.params, &state, &p.r2);

            verify(&self.public, p.r0, r1, p.r2, r3, p.r4)
        }
    }

    #[test]
    fn test_small() {
        type Field = TestField;

        let ckt = Ckt::test_value();
        let w = vec![3u64.into(), 1u64.into(), 5u64.into(),
                        -(Field::from(3u64) * Field::from(5u64))];

        let output = *ckt.eval(&w).last().unwrap();
        assert_eq!(output, Field::ZERO);

        let p = <Prover<_, merkle::Sha256>>::new(&ckt, &w);
        let v = Verifier::new(&ckt);

        let proof = p.make_proof();
        assert!(v.verify(proof))
    }

    #[cfg(test)]
    proptest! {
        #[test]
        fn test_false(
            (ckt, w) in crate::circuit::arb_ckt(20, 100).prop_flat_map(|ckt| {
                let w = pvec(arb_test_field(), ckt.inp_size);
                (Just(ckt), w)
            })
        ) {
            let output = *ckt.eval(&w).last().unwrap();
            let p = <Prover<_, merkle::Sha256>>::new(&ckt, &w);
            let v = Verifier::new(&ckt);

            let proof = p.make_proof();
            prop_assert_eq!(v.verify(proof), output == TestField::ZERO);
        }

        #[test]
        fn test_true(
            (ckt, w) in crate::circuit::arb_ckt_zero(20, 100)
        ) {
            let p = <Prover<TestField, merkle::Sha256>>::new(&ckt, &w);
            let v = <Verifier<TestField, merkle::Sha256>>::new(&ckt);

            let proof = p.make_proof();
            prop_assert!(v.verify(proof))
        }
    }
}
