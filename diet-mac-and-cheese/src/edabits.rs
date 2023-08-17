#![allow(clippy::needless_range_loop)]
#![allow(clippy::type_complexity)]
#![allow(clippy::too_many_arguments)]

//! Field switching functionality based on protocol with Edabuts.

use crate::homcom::{FComProver, FComVerifier, MacProver, MacVerifier};
use eyre::{eyre, Result};
use generic_array::typenum::Unsigned;
#[allow(unused)]
use log::{debug, info, warn};
use ocelot::svole::LpnParams;
use rand::{Rng, SeedableRng};
use scuttlebutt::{AbstractChannel, AesRng, Block, SyncChannel};
use std::io::{BufReader, BufWriter};
use std::net::TcpStream;
use std::time::Instant;
use subtle::{ConditionallySelectable, ConstantTimeEq};
use swanky_field::{FiniteField, FiniteRing};
use swanky_field_binary::{F40b, F2};

/// EdabitsProver struct
#[derive(Clone)]
pub struct EdabitsProver<FE: FiniteField> {
    #[allow(missing_docs)]
    pub bits: Vec<MacProver<F2, F40b>>,
    #[allow(missing_docs)]
    pub value: MacProver<FE::PrimeField, FE>,
}

#[allow(unused)]
fn copy_edabits_prover<FE: FiniteField>(edabits: &EdabitsProver<FE>) -> EdabitsProver<FE> {
    let num_bits = edabits.bits.len();
    let mut bits_par = Vec::with_capacity(num_bits);
    for j in 0..num_bits {
        bits_par.push(edabits.bits[j]);
    }
    EdabitsProver {
        bits: bits_par,
        value: edabits.value,
    }
}

/// EdabitsVerifier struct
#[derive(Clone)]
pub struct EdabitsVerifier<FE: FiniteField> {
    #[allow(missing_docs)]
    pub bits: Vec<MacVerifier<F40b>>,
    #[allow(missing_docs)]
    pub value: MacVerifier<FE>,
}

#[allow(unused)]
fn copy_edabits_verifier<FE: FiniteField>(edabits: &EdabitsVerifier<FE>) -> EdabitsVerifier<FE> {
    let num_bits = edabits.bits.len();
    let mut bits_par = Vec::with_capacity(num_bits);
    for j in 0..num_bits {
        bits_par.push(edabits.bits[j]);
    }
    EdabitsVerifier {
        bits: bits_par,
        value: edabits.value,
    }
}

#[derive(Clone)]
struct DabitProver<FE: FiniteField> {
    bit: MacProver<F2, F40b>,
    value: MacProver<FE::PrimeField, FE>,
}

/// DabitVerifier struct
#[derive(Clone)]
struct DabitVerifier<FE: FiniteField> {
    bit: MacVerifier<F40b>,
    value: MacVerifier<FE>,
}

const FDABIT_SECURITY_PARAMETER: usize = 38;

/// bit to field element
fn f2_to_fe<FE: FiniteField>(b: F2) -> FE {
    let choice = b.ct_eq(&F2::ZERO);
    FE::conditional_select(&FE::ONE, &FE::ZERO, choice)
}

fn convert_bits_to_field<FE: FiniteField>(v: &[F2]) -> FE {
    let mut res = FE::ZERO;

    for b in v.iter().rev() {
        res += res; // double
        res += f2_to_fe(*b);
    }
    res
}

fn convert_bits_to_field_mac<FE: FiniteField>(v: &[MacProver<F2, F40b>]) -> FE {
    let mut res = FE::ZERO;

    for b in v.iter().rev() {
        res += res; // double
        res += f2_to_fe(b.value());
    }
    res
}

fn power_two<FE: FiniteField>(m: usize) -> FE {
    let mut res = FE::ONE;

    for _ in 0..m {
        res += res;
    }

    res
}

// Permutation pseudorandomly generated following Fisher-Yates method
// `https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle`
fn generate_permutation<T: Clone>(rng: &mut AesRng, v: &mut Vec<T>) {
    let size = v.len();
    if size == 0 {
        return;
    }

    let mut i = size - 1;
    while i > 0 {
        let idx = rng.gen_range(0..i);
        v.swap(idx, i);
        i -= 1;
    }
}

fn check_parameters<FE: FiniteField>(n: usize, gamma: usize) -> Result<()> {
    // Because the modulus of the field might be large, we currently only store ceil(log_2(modulus))
    // for the field.
    // Let M be the modulus of the field.
    // We can use an alternate check (as follows):
    /*
    $$
    \begin{array}{ccc}
      \textsf{Invalid}& \impliedby  &  (n+1) \cdot 2^\gamma \geq \frac{M-1}{2} \\
      & \iff &  \log_2(n+1) + \gamma \geq \log_2(M-1)-1 \\
      & \impliedby &  \log_2(n+1) + \gamma \geq \lceil log_2(M) \rceil - 1 \\
      & \impliedby & \lfloor \log_2(n+1) \rfloor + \gamma \geq \lceil log_2(M) \rceil - 1
    \end{array}
    $$
    */
    // TODO: can we get away with just using the log ceiling of the modulus in this fashion?
    fn log2_floor(x: usize) -> usize {
        std::mem::size_of::<usize>() * 8
            - 1
            - usize::try_from(x.leading_zeros()).expect("sizeof(usize) >= sizeof(u32)")
    }
    if log2_floor(n + 1) + gamma >= FE::NumberOfBitsInBitDecomposition::USIZE - 1 {
        Err(eyre!(
            "Fdabit invalid parameter configuration: n={}, gamma={}, FE={}",
            n,
            gamma,
            std::any::type_name::<FE>(),
        ))
    } else {
        Ok(())
    }
}

/// Prover for the edabits conversion protocol
pub struct ProverConv<FE: FiniteField> {
    #[allow(missing_docs)]
    pub fcom_f2: FComProver<F2, F40b>,
    fcom_fe: FComProver<FE::PrimeField, FE>,
}

// The Finite field is required to be a prime field because of the fdabit
// protocol working only for prime finite fields.
impl<FE: FiniteField<PrimeField = FE>> ProverConv<FE> {
    /// initialize the prover
    pub fn init<C: AbstractChannel>(
        channel: &mut C,
        rng: &mut AesRng,
        lpn_setup: LpnParams,
        lpn_extend: LpnParams,
    ) -> Result<Self> {
        let a = FComProver::init(channel, rng, lpn_setup, lpn_extend)?;
        let b = FComProver::init(channel, rng, lpn_setup, lpn_extend)?;
        Ok(Self {
            fcom_f2: a,
            fcom_fe: b,
        })
    }

    #[allow(missing_docs)]
    pub fn init_zero(
        fcom_f2: &FComProver<F2, F40b>,
        fcom_fe: &FComProver<FE::PrimeField, FE>,
    ) -> Result<Self> {
        Ok(Self {
            fcom_f2: fcom_f2.duplicate()?,
            fcom_fe: fcom_fe.duplicate()?,
        })
    }

    fn convert_bit_2_field<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        r_batch: &[DabitProver<FE>],
        x_batch: &[MacProver<F2, F40b>],
        c_batch: &mut Vec<MacProver<F2, F40b>>,
        x_m_batch: &mut Vec<MacProver<FE::PrimeField, FE>>,
    ) -> Result<()> {
        let n = r_batch.len();
        assert_eq!(n, x_batch.len());
        c_batch.clear();
        x_m_batch.clear();

        for i in 0..n {
            c_batch.push(self.fcom_f2.add(r_batch[i].bit, x_batch[i]));
        }
        self.fcom_f2.open(channel, c_batch)?;

        for i in 0..n {
            let c = c_batch[i].value();

            let c_m = f2_to_fe::<FE::PrimeField>(c);

            let choice = c.ct_eq(&F2::ONE);
            let x = self.fcom_fe.neg(r_batch[i].value);
            let beq = self.fcom_fe.affine_add_cst(c_m, x);
            let bneq = self.fcom_fe.affine_add_cst(c_m, r_batch[i].value);
            let x_m = MacProver::conditional_select(&bneq, &beq, choice);

            x_m_batch.push(x_m);
        }

        assert_eq!(n, x_m_batch.len());
        Ok(())
    }

    // This function applies the bit_add_carry to a batch of bits,
    // contrary to the one in the paper that applies it on a pair of
    // bits. This allows to the keep the rounds of communication equal
    // to m for any vector of additions
    fn bit_add_carry<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
        x_batch: &[EdabitsProver<FE>],
        y_batch: &[EdabitsProver<FE>],
    ) -> Result<Vec<(Vec<MacProver<F2, F40b>>, MacProver<F2, F40b>)>> {
        let num = x_batch.len();
        if num != y_batch.len() {
            return Err(eyre!("incompatible input vectors in bit_add_carry"));
        }

        let m = x_batch[0].bits.len();

        // input c0
        let mut ci_batch = vec![F2::ZERO; num];
        let mut ci_mac_batch = self.fcom_f2.input(channel, rng, &ci_batch)?;

        // loop on the m bits over the batch of n addition
        let mut triples = Vec::with_capacity(num * m);
        let mut aux_batch = Vec::with_capacity(num);
        let mut and_res_batch = Vec::with_capacity(num);
        let mut z_batch = vec![Vec::with_capacity(m); num];
        let mut and_res_mac_batch = Vec::with_capacity(num);
        for i in 0..m {
            and_res_batch.clear();
            aux_batch.clear();
            for n in 0..num {
                let ci_clr = ci_batch[n];
                let ci_mac = ci_mac_batch[n];

                let ci = MacProver::new(ci_clr, ci_mac);

                let x = &x_batch[n].bits;
                let y = &y_batch[n].bits;

                assert_eq!(x.len(), m);
                assert_eq!(y.len(), m);

                let xi = x[i];
                let yi = y[i];

                let and1 = self.fcom_f2.add(xi, ci);
                let and1_clr = and1.value();
                let and2 = self.fcom_f2.add(yi, ci);

                let and_res = and1_clr * and2.value();

                let c = ci_clr + and_res;
                // let c_mac = ci_mac + and_res_mac; // is done in the next step
                ci_batch[n] = c;

                let z = self.fcom_f2.add(and1, yi); // xi + yi + ci ;
                z_batch[n].push(z);

                and_res_batch.push(and_res);
                aux_batch.push((and1, and2));
            }
            and_res_mac_batch.clear();
            self.fcom_f2
                .input_low_level(channel, rng, &and_res_batch, &mut and_res_mac_batch)?;

            for n in 0..num {
                let (and1, and2) = aux_batch[n];
                let and_res = and_res_batch[n];
                let and_res_mac = and_res_mac_batch[n];
                triples.push((and1, and2, MacProver::new(and_res, and_res_mac)));

                let ci_mac = ci_mac_batch[n];
                let c_mac = ci_mac + and_res_mac;

                ci_mac_batch[n] = c_mac;
            }
        }

        // check all the multiplications in one batch
        channel.flush()?;
        self.fcom_f2
            .quicksilver_check_multiply(channel, rng, &triples)?;

        // reconstruct the solution
        let mut res = Vec::with_capacity(num);

        for (i, zs) in z_batch.into_iter().enumerate() {
            res.push((zs, MacProver::new(ci_batch[i], ci_mac_batch[i])));
        }

        Ok(res)
    }

    /// input edabits
    pub fn input_edabits<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
        aux_bits: Vec<Vec<MacProver<F2, F40b>>>,
    ) -> Result<Vec<EdabitsProver<FE>>> {
        let num = aux_bits.len();
        debug!("HOW MANY {:?}", num);
        debug!("SIZE {:?}", aux_bits[0].len());
        let mut edabits_vec = Vec::with_capacity(num);

        for bits in aux_bits.into_iter() {
            let r_m: FE::PrimeField = convert_bits_to_field::<FE>(
                bits.iter()
                    .map(|x| x.value())
                    .collect::<Vec<F2>>()
                    .as_slice(),
            );
            let r_m_mac = self.fcom_fe.input(channel, rng, &[r_m])?[0];

            edabits_vec.push(EdabitsProver {
                bits,
                value: MacProver::new(r_m, r_m_mac),
            });
        }

        Ok(edabits_vec)
    }

    /// generate random edabits
    pub fn random_edabits<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
        nb_bits: usize,
        num: usize, // in the paper: NB + C
    ) -> Result<Vec<EdabitsProver<FE>>> {
        let mut edabits_vec = Vec::with_capacity(num);

        let mut aux_bits = Vec::with_capacity(num);
        let mut aux_r_m = Vec::with_capacity(num);
        for _ in 0..num {
            let mut bits = Vec::with_capacity(nb_bits);
            for _ in 0..nb_bits {
                bits.push(self.fcom_f2.random(channel, rng)?);
            }
            let r_m: FE::PrimeField = convert_bits_to_field::<FE::PrimeField>(
                bits.iter()
                    .map(|x| x.value())
                    .collect::<Vec<F2>>()
                    .as_slice(),
            );
            aux_bits.push(bits);
            aux_r_m.push(r_m);
        }

        let aux_r_m_mac: Vec<FE> = self.fcom_fe.input(channel, rng, &aux_r_m)?;

        for (i, aux_bits) in aux_bits.into_iter().enumerate() {
            edabits_vec.push(EdabitsProver {
                bits: aux_bits,
                value: MacProver::new(aux_r_m[i], aux_r_m_mac[i]),
            });
        }
        Ok(edabits_vec)
    }

    /// generate random edabits
    pub fn random_edabits_b2a<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
        nb_bits: usize,
        num: usize, // in the paper: NB + C
    ) -> Result<Vec<EdabitsProver<FE>>> {
        let mut edabits_vec = Vec::with_capacity(num);

        let mut aux_r_m = Vec::with_capacity(num);
        for _ in 0..num {
            aux_r_m.push(FE::random(rng));
        }
        let aux_r_m_mac: Vec<FE> = self.fcom_fe.input(channel, rng, &aux_r_m)?;

        let mut aux_bits = Vec::with_capacity(num);
        for r_m in aux_r_m.iter() {
            let bits = r_m
                .bit_decomposition()
                .iter()
                .map(|b| F2::from(*b))
                .collect::<Vec<F2>>();
            assert_eq!(*r_m, convert_bits_to_field(&bits));
            let mut bits_mac = Vec::with_capacity(nb_bits);
            for &bit in bits.iter() {
                let bit_mac = self.fcom_f2.input1(channel, rng, bit)?;
                bits_mac.push(MacProver::new(bit, bit_mac));
            }
            aux_bits.push(bits_mac);
        }

        for (i, aux_bits) in aux_bits.into_iter().enumerate() {
            edabits_vec.push(EdabitsProver {
                bits: aux_bits,
                value: MacProver::new(aux_r_m[i], aux_r_m_mac[i]),
            });
        }
        Ok(edabits_vec)
    }

    fn random_dabits<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
        num: usize,
    ) -> Result<Vec<DabitProver<FE>>> {
        let mut dabit_vec = Vec::with_capacity(num);
        let mut b_batch = Vec::with_capacity(num);
        let mut b_m_batch = Vec::with_capacity(num);

        for _ in 0..num {
            let b = self.fcom_f2.random(channel, rng)?;
            b_batch.push(b);
            let b_m = f2_to_fe(b.value());
            b_m_batch.push(b_m);
        }

        let b_m_mac_batch = self.fcom_fe.input(channel, rng, &b_m_batch)?;

        for i in 0..num {
            dabit_vec.push(DabitProver {
                bit: b_batch[i],
                value: MacProver::new(b_m_batch[i], b_m_mac_batch[i]),
            });
        }
        Ok(dabit_vec)
    }

    /// Generate random triples
    pub fn random_triples<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
        num: usize,
        out: &mut Vec<(
            MacProver<F2, F40b>,
            MacProver<F2, F40b>,
            MacProver<F2, F40b>,
        )>,
    ) -> Result<()> {
        let mut pairs = Vec::with_capacity(num);
        let mut zs = Vec::with_capacity(num);
        for _ in 0..num {
            let x = self.fcom_f2.random(channel, rng)?;
            let y = self.fcom_f2.random(channel, rng)?;
            let z = x.value() * y.value();
            pairs.push((x, y));
            zs.push(z);
        }
        let mut zs_mac = Vec::with_capacity(num);
        self.fcom_f2
            .input_low_level(channel, rng, &zs, &mut zs_mac)?;

        for i in 0..num {
            let (x, y) = pairs[i];
            let z = zs[i];
            let z_mac = zs_mac[i];
            out.push((x, y, MacProver::new(z, z_mac)));
        }
        channel.flush()?;
        Ok(())
    }

    fn fdabit<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
        dabits: &Vec<DabitProver<FE>>,
    ) -> Result<()> {
        let s = FDABIT_SECURITY_PARAMETER;
        let n = dabits.len();

        let num_bits = std::mem::size_of::<usize>() * 8;
        let gamma = num_bits - ((n + 1).leading_zeros() as usize) - 1 + 1;

        check_parameters::<FE>(n, gamma)?;

        let mut res = true;

        for i in 0..n {
            // making sure the faulty dabits are not faulty
            debug_assert!(
                ((dabits[i].bit.value() == F2::ZERO)
                    & (dabits[i].value.value() == FE::PrimeField::ZERO))
                    | ((dabits[i].bit.value() == F2::ONE)
                        & (dabits[i].value.value() == FE::PrimeField::ONE))
            );
        }

        // step 1)
        let mut c_m: Vec<Vec<FE::PrimeField>> = vec![Vec::with_capacity(gamma); s];
        let mut c_m_mac: Vec<Vec<FE>> = Vec::with_capacity(s);
        for k in 0..s {
            for _ in 0..gamma {
                let b: F2 = F2::random(rng);
                let b_m = f2_to_fe(b);
                c_m[k].push(b_m);
            }
        }

        for k in 0..s {
            let b_m_mac = self.fcom_fe.input(channel, rng, c_m[k].as_slice())?;
            c_m_mac.push(b_m_mac);
        }

        let mut c1: Vec<F2> = Vec::with_capacity(s);
        for k in 0..s {
            if c_m[k][0] == FE::PrimeField::ZERO {
                c1.push(F2::ZERO);
            } else {
                c1.push(F2::ONE);
            }
        }
        let c1_mac = self.fcom_f2.input(channel, rng, &c1)?;

        // step 2)
        let mut triples = Vec::with_capacity(gamma * s);
        let mut andl_batch = Vec::with_capacity(gamma * s);
        let mut andl_mac_batch = Vec::with_capacity(gamma * s);
        let mut one_minus_ci_batch = Vec::with_capacity(gamma * s);
        let mut one_minus_ci_mac_batch = Vec::with_capacity(gamma * s);
        let mut and_res_batch = Vec::with_capacity(gamma * s);
        for k in 0..s {
            for i in 0..gamma {
                let andl: FE::PrimeField = c_m[k][i];
                let andl_mac: FE = c_m_mac[k][i];
                let (minus_ci, minus_ci_mac) = // -ci
                    self.fcom_fe.affine_mult_cst(-FE::PrimeField::ONE, MacProver::new(andl, andl_mac)).decompose();
                let (one_minus_ci, one_minus_ci_mac) = // 1 - ci
                    self.fcom_fe.affine_add_cst(FE::PrimeField::ONE, MacProver::new(minus_ci, minus_ci_mac)).decompose();
                let and_res = andl * one_minus_ci;
                andl_batch.push(andl);
                andl_mac_batch.push(andl_mac);
                one_minus_ci_batch.push(one_minus_ci);
                one_minus_ci_mac_batch.push(one_minus_ci_mac);
                and_res_batch.push(and_res);
            }
        }
        let and_res_mac_batch = self.fcom_fe.input(channel, rng, &and_res_batch)?;

        for j in 0..s * gamma {
            triples.push((
                MacProver::new(andl_batch[j], andl_mac_batch[j]),
                MacProver::new(one_minus_ci_batch[j], one_minus_ci_mac_batch[j]),
                MacProver::new(and_res_batch[j], and_res_mac_batch[j]),
            ));
        }

        // step 3)
        channel.flush()?;
        let seed = channel.read_block()?;
        let mut e_rng = AesRng::from_seed(seed);
        let mut e = vec![Vec::with_capacity(n); s];
        for k in 0..s {
            for _i in 0..n {
                let b = F2::random(&mut e_rng);
                e[k].push(b);
            }
        }

        // step 4)
        let mut r_batch = Vec::with_capacity(s);
        for k in 0..s {
            let (mut r, mut r_mac) = (c1[k], c1_mac[k]);
            for i in 0..n {
                // TODO: do not need to do it when e[i] is ZERO
                let (tmp, tmp_mac) = self
                    .fcom_f2
                    .affine_mult_cst(e[k][i], dabits[i].bit)
                    .decompose();
                debug_assert!(
                    ((e[k][i] == F2::ONE) & (tmp == dabits[i].bit.value())) | (tmp == F2::ZERO)
                );
                r += tmp;
                r_mac += tmp_mac;
            }
            r_batch.push(MacProver::new(r, r_mac));
        }

        // step 5) TODO: move this to the end
        self.fcom_f2.open(channel, &r_batch)?;

        // step 6)
        let mut r_prime_batch = Vec::with_capacity(s);
        for k in 0..s {
            // step 6)
            // NOTE: for performance maybe step 4 and 6 should be combined in one loop
            let (mut r_prime, mut r_prime_mac) = (FE::PrimeField::ZERO, FE::ZERO);
            for i in 0..n {
                // TODO: do not need to do it when e[i] is ZERO
                let b = f2_to_fe(e[k][i]);
                let (tmp, tmp_mac) = self.fcom_fe.affine_mult_cst(b, dabits[i].value).decompose();
                debug_assert!(
                    ((b == FE::PrimeField::ONE) & (tmp == dabits[i].value.value()))
                        | (tmp == FE::PrimeField::ZERO)
                );
                r_prime += tmp;
                r_prime_mac += tmp_mac;
            }
            r_prime_batch.push((r_prime, r_prime_mac));
        }

        // step 7)
        let mut tau_batch = Vec::with_capacity(s);
        for k in 0..s {
            let (mut tau, mut tau_mac) = r_prime_batch[k];
            let mut twos = FE::PrimeField::ONE;
            for i in 0..gamma {
                let (tmp, tmp_mac) = self
                    .fcom_fe
                    .affine_mult_cst(twos, MacProver::new(c_m[k][i], c_m_mac[k][i]))
                    .decompose();
                if i == 0 {
                    debug_assert!(c_m[k][i] == tmp);
                }
                tau += tmp;
                tau_mac += tmp_mac;
                twos += twos;
            }
            tau_batch.push(MacProver::new(tau, tau_mac));
        }

        self.fcom_fe.open(channel, &tau_batch)?;

        // step 8)
        for k in 0..s {
            // step 8)
            // NOTE: This is not needed for the prover,
            let b =
                // mod2 is computed using the first bit of the bit decomposition.
                // NOTE: This scales linearly with the size of the bit decomposition and could lead to potential inefficiencies
                (r_batch[k].value() == F2::ONE) == tau_batch[k].value().bit_decomposition()[0];
            res &= b;
        }
        self.fcom_fe
            .quicksilver_check_multiply(channel, rng, &triples)?;

        if res {
            Ok(())
        } else {
            Err(eyre!("fail fdabit prover"))
        }
    }

    fn conv_loop<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
        edabits_vector: &[EdabitsProver<FE>],
        r: &[EdabitsProver<FE>],
        dabits: &[DabitProver<FE>],
        convert_bit_2_field_aux: &mut Vec<MacProver<F2, F40b>>,
        e_m_batch: &mut Vec<MacProver<FE::PrimeField, FE>>,
    ) -> Result<()> {
        let n = edabits_vector.len();
        let nb_bits = edabits_vector[0].bits.len();
        let power_two_nb_bits = power_two::<FE::PrimeField>(nb_bits);
        // step 6)b) batched and moved up
        let e_batch = self.bit_add_carry(channel, rng, edabits_vector, r)?;

        // step 6)c) batched and moved up
        let mut e_carry_batch = Vec::with_capacity(n);
        for (_, e_carry) in e_batch.iter() {
            e_carry_batch.push(*e_carry);
        }

        self.convert_bit_2_field(
            channel,
            dabits,
            &e_carry_batch,
            convert_bit_2_field_aux,
            e_m_batch,
        )?;

        // 6)a)
        let mut e_prime_batch = Vec::with_capacity(n);
        // 6)d)
        let mut ei_batch = Vec::with_capacity(n * nb_bits);
        for i in 0..n {
            // 6)a)
            let c_m = edabits_vector[i].value;
            let r_m = r[i].value;
            let c_plus_r = self.fcom_fe.add(c_m, r_m);

            // 6)c) done earlier
            let e_m = e_m_batch[i];

            // 6)d)
            let tmp = self.fcom_fe.affine_mult_cst(-power_two_nb_bits, e_m);
            let e_prime = self.fcom_fe.add(c_plus_r, tmp);
            e_prime_batch.push(e_prime);
            ei_batch.extend(&e_batch[i].0);
        }

        // 6)e)
        self.fcom_f2.open(channel, &ei_batch)?;

        let mut e_prime_minus_sum_batch = Vec::with_capacity(n);
        for i in 0..n {
            let sum = convert_bits_to_field_mac::<FE>(&ei_batch[i * nb_bits..(i + 1) * nb_bits]);
            e_prime_minus_sum_batch.push(self.fcom_fe.affine_add_cst(-sum, e_prime_batch[i]));
        }

        // Remark this is not necessary for the prover, bc cst addition dont show up in mac
        // let s = convert_f2_to_field(ei);
        self.fcom_fe.check_zero(channel, &e_prime_minus_sum_batch)?;
        Ok(())
    }

    /// conversion checking
    pub fn conv<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
        num_bucket: usize,
        num_cut: usize,
        edabits_vector: &[EdabitsProver<FE>],
        bucket_channels: Option<Vec<SyncChannel<BufReader<TcpStream>, BufWriter<TcpStream>>>>,
    ) -> Result<()> {
        let n = edabits_vector.len();
        if n == 0 {
            info!("conversion check on no conversions");
            return Ok(());
        }
        let nb_bits = edabits_vector[0].bits.len();
        info!(
            "conversion check, field:{:?}, nb_bits:{:?} vector_size:{:?}",
            (-FE::ONE).to_bytes(),
            nb_bits,
            edabits_vector.len()
        );

        let nb_random_edabits = n * num_bucket + num_cut;
        let nb_random_dabits = n * num_bucket;

        // step 1)a): commit random edabit
        let mut r = self.random_edabits(channel, rng, nb_bits, nb_random_edabits)?;

        // step 1)b)
        let mut dabits = self.random_dabits(channel, rng, nb_random_dabits)?;

        // step 1)c): multiplication triples
        // unnecessary step with quicksilver mult check

        // step 2)
        self.fdabit(channel, rng, &dabits)?;

        // step 3) get seed for permutation
        let seed = channel.read_block()?;
        let mut shuffle_rng = AesRng::from_seed(seed);

        // step 4): shuffle edabits, dabits and triples
        generate_permutation(&mut shuffle_rng, &mut r);
        generate_permutation(&mut shuffle_rng, &mut dabits);

        // step 5)a):
        let base = n * num_bucket;
        for i in 0..num_cut {
            let idx = base + i;
            let a = &r[idx];
            self.fcom_f2.open(channel, &a.bits)?;
            self.fcom_fe.open(channel, &[a.value])?;
        }

        // step 5) b):
        // unnecessary step with quicksilver mult check

        // step 6)
        if bucket_channels.is_none() {
            let mut convert_bit_2_field_aux = Vec::with_capacity(n);
            let mut e_m_batch = Vec::with_capacity(n);
            for j in 0..num_bucket {
                // base index for the window of `idx_base..idx_base + n` values
                let idx_base = j * n;

                self.conv_loop(
                    channel,
                    rng,
                    edabits_vector,
                    &r[idx_base..idx_base + n],
                    &dabits[idx_base..idx_base + n],
                    &mut convert_bit_2_field_aux,
                    &mut e_m_batch,
                )?;
            }
        } else {
            /*
            let mut j = 0;
            let mut handles = Vec::new();
            for mut bucket_channel in bucket_channels.unwrap().into_iter() {
                // splitting the vectors to spawn
                let idx_base = j * n;
                let mut edabits_vector_par = Vec::with_capacity(n);
                for edabits in edabits_vector.iter() {
                    edabits_vector_par.push(copy_edabits_prover(edabits));
                }

                let mut r_par = Vec::with_capacity(n);
                for r_elm in r[idx_base..idx_base + n].iter() {
                    r_par.push(copy_edabits_prover(r_elm));
                }

                let mut dabits_par = Vec::with_capacity(n);
                for elm in dabits[idx_base..idx_base + n].iter() {
                    dabits_par.push(elm.clone());
                }

                let mut random_triples_par = Vec::new(); //with_capacity(n * nb_bits);
                if !with_quicksilver {
                    //let mut random_triples_par = Vec::with_capacity(n * nb_bits);
                    for elm in
                        random_triples[idx_base * nb_bits..idx_base * nb_bits + n * nb_bits].iter()
                    {
                        random_triples_par.push(*elm);
                    }
                }

                let mut new_prover = self.duplicate(channel, rng)?;
                let handle = std::thread::spawn(move || {
                    let mut convert_bit_2_field_aux = Vec::with_capacity(n);
                    let mut e_m_batch = Vec::with_capacity(n);
                    new_prover.conv_loop(
                        &mut bucket_channel,
                        &mut AesRng::new(),
                        &edabits_vector_par,
                        &r_par,
                        &dabits_par,
                        &mut convert_bit_2_field_aux,
                        &mut e_m_batch,
                        &random_triples_par,
                    )
                });
                handles.push(handle);

                j += 1;
            }

            for handle in handles {
                handle.join().unwrap().unwrap();
            }
            */
        }

        Ok(())
    }
}

/// Verifier for the edabits conversion protocol
pub struct VerifierConv<FE: FiniteField> {
    #[allow(missing_docs)]
    pub fcom_f2: FComVerifier<F2, F40b>,
    fcom_fe: FComVerifier<FE::PrimeField, FE>,
}

// The Finite field is required to be a prime field because of the fdabit
// protocol working only for prime finite fields.
impl<FE: FiniteField<PrimeField = FE>> VerifierConv<FE> {
    /// initialize the verifier
    pub fn init<C: AbstractChannel>(
        channel: &mut C,
        rng: &mut AesRng,
        lpn_setup: LpnParams,
        lpn_extend: LpnParams,
    ) -> Result<Self> {
        let a = FComVerifier::init(channel, rng, lpn_setup, lpn_extend)?;
        let b = FComVerifier::init(channel, rng, lpn_setup, lpn_extend)?;
        Ok(Self {
            fcom_f2: a,
            fcom_fe: b,
        })
    }

    #[allow(missing_docs)]
    pub fn init_zero(
        fcom_f2: &FComVerifier<F2, F40b>,
        fcom_fe: &FComVerifier<FE::PrimeField, FE>,
    ) -> Result<Self> {
        Ok(Self {
            fcom_f2: fcom_f2.duplicate()?,
            fcom_fe: fcom_fe.duplicate()?,
        })
    }

    fn convert_bit_2_field<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        r_batch: &[DabitVerifier<FE>],
        x_batch: &[MacVerifier<F40b>],
        r_mac_plus_x_mac: &mut Vec<MacVerifier<F40b>>,
        c_batch: &mut Vec<F2>,
        x_m_batch: &mut Vec<MacVerifier<FE>>,
    ) -> Result<()> {
        let n = r_batch.len();
        debug_assert!(n == x_batch.len());
        r_mac_plus_x_mac.clear();
        x_m_batch.clear();

        for i in 0..n {
            r_mac_plus_x_mac.push(self.fcom_f2.add(r_batch[i].bit, x_batch[i]));
        }
        self.fcom_f2.open(channel, r_mac_plus_x_mac, c_batch)?;

        for i in 0..n {
            let c = c_batch[i];

            let c_m = f2_to_fe::<FE::PrimeField>(c);

            let choice = c.ct_eq(&F2::ONE);
            let x_mac = self.fcom_fe.neg(r_batch[i].value);
            let beq = self.fcom_fe.affine_add_cst(c_m, x_mac);
            let bneq = self.fcom_fe.affine_add_cst(c_m, r_batch[i].value);
            let x_m = MacVerifier::conditional_select(&bneq, &beq, choice);

            x_m_batch.push(x_m);
        }

        assert_eq!(n, x_m_batch.len());
        Ok(())
    }

    fn bit_add_carry<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
        x_batch: &[EdabitsVerifier<FE>],
        y_batch: &[EdabitsVerifier<FE>],
    ) -> Result<Vec<(Vec<MacVerifier<F40b>>, MacVerifier<F40b>)>> {
        let num = x_batch.len();
        if num != y_batch.len() {
            return Err(eyre!("incompatible input vectors in bit_add_carry"));
        }

        let m = x_batch[0].bits.len();

        // input c0
        let mut ci_batch = self.fcom_f2.input(channel, rng, num)?;

        // loop on the m bits over the batch of n addition
        let mut triples = Vec::with_capacity(num * m);
        let mut aux_batch = Vec::with_capacity(num);
        let mut z_batch = vec![Vec::with_capacity(m); num];
        let mut and_res_mac_batch = Vec::with_capacity(num);
        for i in 0..m {
            aux_batch.clear();
            for n in 0..num {
                let ci = ci_batch[n];

                let x = &x_batch[n].bits;
                let y = &y_batch[n].bits;

                assert!(x.len() == m && y.len() == m);

                let xi = x[i];
                let yi = y[i];

                let and1 = self.fcom_f2.add(xi, ci);
                let and2 = self.fcom_f2.add(yi, ci);

                let z = self.fcom_f2.add(and1, yi); //xi_mac + yi_mac + ci_mac;
                z_batch[n].push(z);
                aux_batch.push((and1, and2));
            }
            and_res_mac_batch.clear();
            self.fcom_f2
                .input_low_level(channel, rng, num, &mut and_res_mac_batch)?;

            for n in 0..num {
                let (and1_mac, and2_mac) = aux_batch[n];
                let and_res_mac = and_res_mac_batch[n];
                triples.push((and1_mac, and2_mac, and_res_mac));

                let ci = ci_batch[n];
                let c_mac = self.fcom_f2.add(ci, and_res_mac);
                ci_batch[n] = c_mac;
            }
        }
        // check all the multiplications in one batch
        self.fcom_f2
            .quicksilver_check_multiply(channel, rng, &triples)?;

        // reconstruct the solution
        let mut res = Vec::with_capacity(num);
        for (i, zs) in z_batch.into_iter().enumerate() {
            res.push((zs, ci_batch[i]));
        }

        Ok(res)
    }

    /// input edabits
    pub fn input_edabits<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
        aux_bits: Vec<Vec<MacVerifier<F40b>>>,
    ) -> Result<Vec<EdabitsVerifier<FE>>> {
        let num = aux_bits.len();
        debug!("HOW MANY {:?}", num);
        debug!("SIZE {:?}", aux_bits[0].len());
        let mut edabits_vec = Vec::with_capacity(num);

        for bits in aux_bits.into_iter() {
            let r_m_mac = self.fcom_fe.input(channel, rng, 1)?[0];

            edabits_vec.push(EdabitsVerifier {
                bits,
                value: r_m_mac,
            });
        }

        Ok(edabits_vec)
    }

    /// generate random edabits
    pub fn random_edabits<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
        nb_bits: usize,
        num: usize, // in the paper: NB + C
    ) -> Result<Vec<EdabitsVerifier<FE>>> {
        let mut edabits_vec_mac = Vec::with_capacity(num);
        let mut aux_bits = Vec::with_capacity(num);
        for _ in 0..num {
            let mut bits = Vec::with_capacity(nb_bits);
            for _ in 0..nb_bits {
                bits.push(self.fcom_f2.random(channel, rng)?);
            }
            aux_bits.push(bits);
        }

        let aux_r_m_mac = self.fcom_fe.input(channel, rng, num)?;

        for (i, aux_bits) in aux_bits.into_iter().enumerate() {
            edabits_vec_mac.push(EdabitsVerifier {
                bits: aux_bits,
                value: aux_r_m_mac[i],
            });
        }
        Ok(edabits_vec_mac)
    }

    /// generate random edabits
    pub fn random_edabits_b2a<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
        nb_bits: usize,
        num: usize, // in the paper: NB + C
    ) -> Result<Vec<EdabitsVerifier<FE>>> {
        let aux_r_m_mac = self.fcom_fe.input(channel, rng, num)?;
        let mut edabits_vec_mac = Vec::with_capacity(num);
        let mut aux_bits = Vec::with_capacity(num);
        for _ in 0..num {
            let mut bits = Vec::with_capacity(nb_bits);
            for _ in 0..nb_bits {
                bits.push(self.fcom_f2.input1(channel, rng)?);
            }
            aux_bits.push(bits);
        }

        for (i, aux_bits) in aux_bits.into_iter().enumerate() {
            edabits_vec_mac.push(EdabitsVerifier {
                bits: aux_bits,
                value: aux_r_m_mac[i],
            });
        }
        Ok(edabits_vec_mac)
    }

    fn random_dabits<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
        num: usize,
    ) -> Result<Vec<DabitVerifier<FE>>> {
        let mut dabit_vec_mac = Vec::with_capacity(num);
        let mut b_mac_batch = Vec::with_capacity(num);
        for _ in 0..num {
            b_mac_batch.push(self.fcom_f2.random(channel, rng)?);
        }
        let b_m_mac_batch = self.fcom_fe.input(channel, rng, num)?;
        for i in 0..num {
            dabit_vec_mac.push(DabitVerifier {
                bit: b_mac_batch[i],
                value: b_m_mac_batch[i],
            });
        }
        Ok(dabit_vec_mac)
    }

    /// Generate random triples
    pub fn random_triples<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
        num: usize,
        out: &mut Vec<(MacVerifier<F40b>, MacVerifier<F40b>, MacVerifier<F40b>)>,
    ) -> Result<()> {
        let mut pairs = Vec::with_capacity(num);
        for _ in 0..num {
            let x = self.fcom_f2.random(channel, rng)?;
            let y = self.fcom_f2.random(channel, rng)?;
            pairs.push((x, y));
        }
        let mut zs = Vec::with_capacity(num);
        self.fcom_f2.input_low_level(channel, rng, num, &mut zs)?;

        for i in 0..num {
            let (x, y) = pairs[i];
            let z = zs[i];
            out.push((x, y, z));
        }
        Ok(())
    }

    fn fdabit<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
        dabits_mac: &Vec<DabitVerifier<FE>>,
    ) -> Result<()> {
        let s = FDABIT_SECURITY_PARAMETER;
        let n = dabits_mac.len();

        let num_bits = std::mem::size_of::<usize>() * 8;
        let gamma = num_bits - ((n + 1).leading_zeros() as usize) - 1 + 1;

        check_parameters::<FE>(n, gamma)?;

        let mut res = true;

        // step 1)
        let mut c_m_mac: Vec<Vec<MacVerifier<FE>>> = Vec::with_capacity(s);
        for _ in 0..s {
            let b_m_mac = self.fcom_fe.input(channel, rng, gamma)?;
            c_m_mac.push(b_m_mac);
        }

        let c1_mac = self.fcom_f2.input(channel, rng, s)?;

        // step 2)
        let mut triples = Vec::with_capacity(gamma * s);
        let mut andl_mac_batch = Vec::with_capacity(gamma * s);
        let mut one_minus_ci_mac_batch = Vec::with_capacity(gamma * s);
        for k in 0..s {
            for i in 0..gamma {
                let andl_mac = c_m_mac[k][i];
                let minus_ci_mac = // -ci
                    self.fcom_fe.affine_mult_cst(-FE::PrimeField::ONE, andl_mac);
                let one_minus_ci_mac = // 1 - ci
                    self.fcom_fe.affine_add_cst(FE::PrimeField::ONE, minus_ci_mac);
                andl_mac_batch.push(andl_mac);
                one_minus_ci_mac_batch.push(one_minus_ci_mac);
            }
        }

        let and_res_mac_batch = self.fcom_fe.input(channel, rng, gamma * s)?;
        for j in 0..s * gamma {
            triples.push((
                andl_mac_batch[j],
                one_minus_ci_mac_batch[j],
                and_res_mac_batch[j],
            ));
        }

        // step 3)
        let seed = rng.gen::<Block>();
        channel.write_block(&seed)?;
        channel.flush()?;
        let mut e_rng = AesRng::from_seed(seed);
        let mut e = vec![Vec::with_capacity(n); s];
        for k in 0..s {
            for _i in 0..n {
                let b = F2::random(&mut e_rng);
                e[k].push(b);
            }
        }

        // step 4)
        let mut r_mac_batch = Vec::with_capacity(s);
        for k in 0..s {
            let mut r_mac = c1_mac[k].mac();
            for i in 0..n {
                // TODO: do not need to do it when e[i] is ZERO
                let tmp_mac = self
                    .fcom_f2
                    .affine_mult_cst(e[k][i], dabits_mac[i].bit)
                    .mac();
                r_mac += tmp_mac;
            }
            r_mac_batch.push(MacVerifier::new(r_mac));
        }

        // step 5)
        let mut r_batch = Vec::with_capacity(s);
        self.fcom_f2.open(channel, &r_mac_batch, &mut r_batch)?;

        // step 6)
        let mut r_prime_batch = Vec::with_capacity(s);
        for k in 0..s {
            // NOTE: for performance maybe step 4 and 6 should be combined in one loop
            let mut r_prime_mac = FE::ZERO;
            for i in 0..n {
                // TODO: do not need to do it when e[i] is ZERO
                let b = f2_to_fe(e[k][i]);
                let tmp_mac = self.fcom_fe.affine_mult_cst(b, dabits_mac[i].value).mac();
                r_prime_mac += tmp_mac;
            }
            r_prime_batch.push(r_prime_mac);
        }

        // step 7)
        let mut tau_mac_batch = Vec::with_capacity(s);
        for k in 0..s {
            let mut tau_mac = r_prime_batch[k];
            let mut twos = FE::PrimeField::ONE;
            for i in 0..gamma {
                let tmp_mac = self.fcom_fe.affine_mult_cst(twos, c_m_mac[k][i]).mac();
                tau_mac += tmp_mac;
                twos += twos;
            }
            tau_mac_batch.push(MacVerifier::new(tau_mac));
        }

        let mut tau_batch = Vec::with_capacity(s);
        self.fcom_fe.open(channel, &tau_mac_batch, &mut tau_batch)?;

        // step 8)
        for k in 0..s {
            let b =
                // mod2 is computed using the first bit of the bit decomposition.
                // NOTE: This scales linearly with the size of the bit decomposition and could lead to potential inefficiencies
                (r_batch[k] == F2::ONE) == tau_batch[k].bit_decomposition()[0];
            res &= b;
        }
        self.fcom_fe
            .quicksilver_check_multiply(channel, rng, &triples)?;

        if res {
            Ok(())
        } else {
            Err(eyre!("fail fdabit verifier"))
        }
    }

    fn conv_loop<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
        edabits_vector_mac: &[EdabitsVerifier<FE>],
        r_mac: &[EdabitsVerifier<FE>],
        dabits_mac: &[DabitVerifier<FE>],
        convert_bit_2_field_aux1: &mut Vec<MacVerifier<F40b>>,
        convert_bit_2_field_aux2: &mut Vec<F2>,
        e_m_batch: &mut Vec<MacVerifier<FE>>,
        ei_batch: &mut Vec<F2>,
    ) -> Result<()> {
        let n = edabits_vector_mac.len();
        let nb_bits = edabits_vector_mac[0].bits.len();
        let power_two_nb_bits = power_two::<FE::PrimeField>(nb_bits);

        // step 6)b) batched and moved up
        debug!("ADD< ... ");
        let start = Instant::now();
        let e_batch = self.bit_add_carry(channel, rng, edabits_vector_mac, r_mac)?;
        debug!("ADD> {:?}", start.elapsed());

        // step 6)c) batched and moved up
        debug!("A2B< ...");
        let start = Instant::now();
        let mut e_carry_mac_batch = Vec::with_capacity(n);
        for (_, e_carry) in e_batch.iter() {
            e_carry_mac_batch.push(*e_carry);
        }

        self.convert_bit_2_field(
            channel,
            dabits_mac,
            &e_carry_mac_batch,
            convert_bit_2_field_aux1,
            convert_bit_2_field_aux2,
            e_m_batch,
        )?;
        debug!("A2B> {:?}", start.elapsed());

        // 6)a)
        let mut e_prime_mac_batch = Vec::with_capacity(n);
        // 6)d)
        let mut ei_mac_batch = Vec::with_capacity(n * nb_bits);
        for i in 0..n {
            // 6)a)
            let c_m = edabits_vector_mac[i].value;
            let r_m = r_mac[i].value;
            let c_plus_r = self.fcom_fe.add(c_m, r_m);

            // 6)c) done earlier
            let e_m = e_m_batch[i];

            // 6)d)
            let tmp = self.fcom_fe.affine_mult_cst(-power_two_nb_bits, e_m);
            let e_prime = self.fcom_fe.add(c_plus_r, tmp);
            e_prime_mac_batch.push(e_prime);

            // 6)e)
            ei_mac_batch.extend(&e_batch[i].0);
        }
        // 6)e)
        debug!("OPEN< ... ");
        let start = Instant::now();
        self.fcom_f2.open(channel, &ei_mac_batch, ei_batch)?;
        debug!("OPEN> {:?}", start.elapsed());

        let mut e_prime_minus_sum_batch = Vec::with_capacity(n);
        for i in 0..n {
            let sum =
                convert_bits_to_field::<FE::PrimeField>(&ei_batch[i * nb_bits..(i + 1) * nb_bits]);
            e_prime_minus_sum_batch.push(self.fcom_fe.affine_add_cst(-sum, e_prime_mac_batch[i]));
        }
        debug!("CHECK_Z< ... ");
        let start = Instant::now();
        self.fcom_fe
            .check_zero(channel, rng, &e_prime_minus_sum_batch)?;
        debug!("CHECK_Z> {:?}", start.elapsed());

        Ok(())
    }

    /// conversion checking
    pub fn conv<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
        num_bucket: usize,
        num_cut: usize,
        edabits_vector_mac: &[EdabitsVerifier<FE>],
        bucket_channels: Option<Vec<SyncChannel<BufReader<TcpStream>, BufWriter<TcpStream>>>>,
    ) -> Result<()> {
        let n = edabits_vector_mac.len();
        if n == 0 {
            info!("conversion check on no conversions");
            return Ok(());
        }

        let nb_bits = edabits_vector_mac[0].bits.len();
        info!(
            "conversion check, field:{:?}, nb_bits:{:?} vector_size:{:?}",
            (-FE::ONE).to_bytes(),
            nb_bits,
            edabits_vector_mac.len()
        );
        let nb_random_edabits = n * num_bucket + num_cut;
        let nb_random_dabits = n * num_bucket;

        let phase1 = Instant::now();
        // step 1)a)
        debug!("Step 1)a) RANDOM EDABITS ... ");
        let start = Instant::now();
        let mut r_mac = self.random_edabits(channel, rng, nb_bits, nb_random_edabits)?;
        debug!("{:?}", start.elapsed());

        // step 1)b)
        debug!("Step 1)b) RANDOM DABITS ... ");
        let start = Instant::now();
        let mut dabits_mac = self.random_dabits(channel, rng, nb_random_dabits)?;
        debug!("{:?}", start.elapsed());

        // step 1)c):
        debug!("Step 1)c) RANDOM TRIPLES ... ");
        // unnecessary step with quicksilver mult check

        // step 2)
        debug!("Step 2) CHECK DABITS ... ");
        let start = Instant::now();
        self.fdabit(channel, rng, &dabits_mac)?;
        debug!("{:?}", start.elapsed());

        // step 3): get seed for permutation
        let seed = rng.gen::<Block>();
        channel.write_block(&seed)?;
        channel.flush()?;
        let mut shuffle_rng = AesRng::from_seed(seed);

        // step 4): shuffle the edabits, dabits, triples
        debug!("Step 4) SHUFFLE ... ");
        let start = Instant::now();
        generate_permutation(&mut shuffle_rng, &mut r_mac);
        generate_permutation(&mut shuffle_rng, &mut dabits_mac);
        debug!("{:?}", start.elapsed());

        // step 5)a):
        debug!("Step 5)a) OPEN edabits ... ");
        let start = Instant::now();
        let base = n * num_bucket;
        let mut a_vec = Vec::with_capacity(nb_bits);
        let mut a_m = Vec::with_capacity(1);
        for i in 0..num_cut {
            let idx = base + i;
            let a_mac = &r_mac[idx];
            self.fcom_f2.open(channel, &a_mac.bits, &mut a_vec)?;
            self.fcom_fe.open(channel, &[a_mac.value], &mut a_m)?;
            if convert_bits_to_field::<FE::PrimeField>(&a_vec) != a_m[0] {
                return Err(eyre!("Wrong open random edabit"));
            }
        }
        debug!("{:?}", start.elapsed());

        // step 5) b):
        // unnecessary step with quicksilver mult check

        debug!("Total Steps 1-2-3-4-5: {:?}", phase1.elapsed());

        let phase2 = Instant::now();
        // step 6)
        debug!("step 6)a-e) bitADDcarry etc: ... ");

        if bucket_channels.is_none() {
            let mut convert_bit_2_field_aux1 = Vec::with_capacity(n);
            let mut convert_bit_2_field_aux2 = Vec::with_capacity(n);
            let mut e_m_batch = Vec::with_capacity(n);
            let mut ei_batch = Vec::with_capacity(n);
            for j in 0..num_bucket {
                // base index for the window of `idx_base..idx_base + n` values
                let idx_base = j * n;

                self.conv_loop(
                    channel,
                    rng,
                    edabits_vector_mac,
                    &r_mac[idx_base..idx_base + n],
                    &dabits_mac[idx_base..idx_base + n],
                    &mut convert_bit_2_field_aux1,
                    &mut convert_bit_2_field_aux2,
                    &mut e_m_batch,
                    &mut ei_batch,
                )?;
            }
        } else {
            /*
            let mut j = 0;
            let mut handles = Vec::new();
            for mut bucket_channel in bucket_channels.unwrap().into_iter() {
                // base index for the window of `idx_base..idx_base + n` values
                let idx_base = j * n;

                // splitting the vectors to spawn
                let mut edabits_vector_mac_par = Vec::with_capacity(n);
                for edabits in edabits_vector_mac.iter() {
                    edabits_vector_mac_par.push(copy_edabits_verifier(edabits));
                }

                let mut r_mac_par = Vec::with_capacity(n);
                for r_elm in r_mac[idx_base..idx_base + n].iter() {
                    r_mac_par.push(copy_edabits_verifier(r_elm));
                }

                let mut dabits_mac_par = Vec::with_capacity(n);
                for elm in dabits_mac[idx_base..idx_base + n].iter() {
                    dabits_mac_par.push(elm.clone());
                }

                let mut random_triples_par = Vec::new(); //with_capacity(n * nb_bits);
                if !with_quicksilver {
                    //let mut random_triples_par = Vec::with_capacity(n * nb_bits);
                    for elm in
                        random_triples[idx_base * nb_bits..idx_base * nb_bits + n * nb_bits].iter()
                    {
                        random_triples_par.push(*elm);
                    }
                }

                let mut new_verifier = self.duplicate(channel, rng)?;
                let handle = std::thread::spawn(move || {
                    let mut convert_bit_2_field_aux1 = Vec::with_capacity(n);
                    let mut convert_bit_2_field_aux2 = Vec::with_capacity(n);
                    let mut e_m_batch = Vec::with_capacity(n);
                    let mut ei_batch = Vec::with_capacity(n);
                    new_verifier.conv_loop(
                        &mut bucket_channel,
                        &mut AesRng::new(),
                        &edabits_vector_mac_par,
                        &r_mac_par,
                        &dabits_mac_par,
                        &mut convert_bit_2_field_aux1,
                        &mut convert_bit_2_field_aux2,
                        &mut e_m_batch,
                        &mut ei_batch,
                        &random_triples_par,
                    )
                });
                handles.push(handle);

                j += 1;
            }

            for handle in handles {
                handle.join().unwrap().unwrap();
            }
            */
        }
        debug!("step 6)a-e) bitADDcarry etc: {:?}", phase2.elapsed());

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use super::super::homcom::{MacProver, MacVerifier};
    use super::convert_bits_to_field;
    use super::{
        f2_to_fe, DabitProver, DabitVerifier, EdabitsProver, EdabitsVerifier, ProverConv,
        VerifierConv,
    };
    #[allow(unused)]
    use log::{debug, info, warn};
    use ocelot::svole::{LPN_EXTEND_SMALL, LPN_SETUP_SMALL};
    use scuttlebutt::field::F384p;
    use scuttlebutt::ring::FiniteRing;
    use scuttlebutt::{
        field::{F61p, FiniteField, F2},
        AesRng, Channel,
    };
    use std::{
        io::{BufReader, BufWriter},
        os::unix::net::UnixStream,
    };

    const DEFAULT_NUM_BUCKET: usize = 5;
    const DEFAULT_NUM_CUT: usize = 5;
    const NB_BITS: usize = 38;

    fn test_convert_bit_2_field<FE: FiniteField<PrimeField = FE>>() {
        let count = 100;
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut fconv =
                ProverConv::<FE>::init(&mut channel, &mut rng, LPN_SETUP_SMALL, LPN_EXTEND_SMALL)
                    .unwrap();

            let mut res = Vec::new();
            for _ in 0..count {
                let (rb, rb_mac) = fconv
                    .fcom_f2
                    .random(&mut channel, &mut rng)
                    .unwrap()
                    .decompose();
                let rm = f2_to_fe(rb);
                let rm_mac = fconv.fcom_fe.input(&mut channel, &mut rng, &[rm]).unwrap()[0];
                let (x_f2, x_f2_mac) = fconv
                    .fcom_f2
                    .random(&mut channel, &mut rng)
                    .unwrap()
                    .decompose();

                let mut convert_bit_2_field_aux = Vec::new();
                let mut x_m_batch = Vec::new();
                fconv
                    .convert_bit_2_field(
                        &mut channel,
                        &[DabitProver {
                            bit: MacProver::new(rb, rb_mac),
                            value: MacProver::new(rm, rm_mac),
                        }],
                        &[MacProver::new(x_f2, x_f2_mac)],
                        &mut convert_bit_2_field_aux,
                        &mut x_m_batch,
                    )
                    .unwrap();

                fconv.fcom_fe.open(&mut channel, &x_m_batch).unwrap();

                assert_eq!(f2_to_fe::<FE::PrimeField>(x_f2), x_m_batch[0].value());
                res.push((x_f2, x_m_batch[0].value()));
            }
            res
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut fconv =
            VerifierConv::<FE>::init(&mut channel, &mut rng, LPN_SETUP_SMALL, LPN_EXTEND_SMALL)
                .unwrap();

        let mut res = Vec::new();
        for _ in 0..count {
            let rb_mac = fconv.fcom_f2.random(&mut channel, &mut rng).unwrap();
            let r_m_mac = fconv.fcom_fe.input(&mut channel, &mut rng, 1).unwrap()[0];
            let x_f2_mac = fconv.fcom_f2.random(&mut channel, &mut rng).unwrap();

            let mut convert_bit_2_field_aux1 = Vec::new();
            let mut convert_bit_2_field_aux2 = Vec::new();
            let mut x_m_batch = Vec::new();
            fconv
                .convert_bit_2_field(
                    &mut channel,
                    &[DabitVerifier {
                        bit: rb_mac,
                        value: r_m_mac,
                    }],
                    &[x_f2_mac],
                    &mut convert_bit_2_field_aux1,
                    &mut convert_bit_2_field_aux2,
                    &mut x_m_batch,
                )
                .unwrap();

            let mut x_m = Vec::new();
            fconv
                .fcom_fe
                .open(&mut channel, &[x_m_batch[0]], &mut x_m)
                .unwrap();
            res.push(x_m[0]);
        }

        let resprover = handle.join().unwrap();

        for i in 0..count {
            assert_eq!(resprover[i].1, res[i]);
        }
    }

    fn test_bit_add_carry<FE: FiniteField<PrimeField = FE>>() {
        let power = 6;
        let (sender, receiver) = UnixStream::pair().unwrap();

        // adding
        //   110101
        //   101110
        // --------
        //  1100011
        let x = vec![F2::ONE, F2::ZERO, F2::ONE, F2::ZERO, F2::ONE, F2::ONE];
        let y = vec![F2::ZERO, F2::ONE, F2::ONE, F2::ONE, F2::ZERO, F2::ONE];
        let expected = vec![F2::ONE, F2::ONE, F2::ZERO, F2::ZERO, F2::ZERO, F2::ONE];
        let carry = F2::ONE;

        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut fconv =
                ProverConv::<FE>::init(&mut channel, &mut rng, LPN_SETUP_SMALL, LPN_EXTEND_SMALL)
                    .unwrap();

            let x_mac = fconv.fcom_f2.input(&mut channel, &mut rng, &x).unwrap();
            let y_mac = fconv.fcom_f2.input(&mut channel, &mut rng, &y).unwrap();

            let mut vx = Vec::new();
            for i in 0..power {
                vx.push(MacProver::new(x[i], x_mac[i]));
            }

            let mut vy = Vec::new();
            for i in 0..power {
                vy.push(MacProver::new(y[i], y_mac[i]));
            }
            let default_fe = MacProver::new(FE::PrimeField::ZERO, FE::ZERO);
            let (res, c) = fconv
                .bit_add_carry(
                    &mut channel,
                    &mut rng,
                    &[EdabitsProver {
                        bits: vx,
                        value: default_fe,
                    }],
                    &[EdabitsProver {
                        bits: vy,
                        value: default_fe,
                    }],
                )
                .unwrap()[0]
                .clone();

            fconv.fcom_f2.open(&mut channel, &res).unwrap();

            fconv.fcom_f2.open(&mut channel, &[c]).unwrap();
            (res, c)
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut fconv =
            VerifierConv::<FE>::init(&mut channel, &mut rng, LPN_SETUP_SMALL, LPN_EXTEND_SMALL)
                .unwrap();

        let x_mac = fconv.fcom_f2.input(&mut channel, &mut rng, power).unwrap();
        let y_mac = fconv.fcom_f2.input(&mut channel, &mut rng, power).unwrap();

        let default_fe = MacVerifier::new(FE::ZERO);
        let (res_mac, c_mac) = fconv
            .bit_add_carry(
                &mut channel,
                &mut rng,
                &[EdabitsVerifier {
                    bits: x_mac,
                    value: default_fe,
                }],
                &[EdabitsVerifier {
                    bits: y_mac,
                    value: default_fe,
                }],
            )
            .unwrap()[0]
            .clone();

        let mut res = Vec::new();
        fconv
            .fcom_f2
            .open(&mut channel, &res_mac, &mut res)
            .unwrap();

        let mut c = Vec::new();
        fconv.fcom_f2.open(&mut channel, &[c_mac], &mut c).unwrap();

        let _resprover = handle.join().unwrap();

        for i in 0..power {
            assert_eq!(expected[i], res[i]);
        }
        assert_eq!(carry, c[0]);
    }

    fn test_random_edabits_b2a<FE: FiniteField<PrimeField = FE>>(nb_bits: usize) {
        let count = 1000;
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut fconv =
                ProverConv::<FE>::init(&mut channel, &mut rng, LPN_EXTEND_SMALL, LPN_SETUP_SMALL)
                    .unwrap();

            let edabits = fconv
                .random_edabits_b2a(&mut channel, &mut rng, nb_bits, count)
                .unwrap();
            for e in edabits.iter() {
                fconv.fcom_f2.open(&mut channel, &e.bits).unwrap();
                fconv.fcom_fe.open(&mut channel, &[e.value]).unwrap();
            }
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut fconv =
            VerifierConv::<FE>::init(&mut channel, &mut rng, LPN_EXTEND_SMALL, LPN_SETUP_SMALL)
                .unwrap();

        let edabits = fconv
            .random_edabits_b2a(&mut channel, &mut rng, nb_bits, count)
            .unwrap();
        for e in edabits.iter() {
            let mut out_bits = Vec::new();
            fconv
                .fcom_f2
                .open(&mut channel, &e.bits, &mut out_bits)
                .unwrap();
            let x = convert_bits_to_field::<FE::PrimeField>(&out_bits);
            let mut out_value = Vec::new();
            fconv
                .fcom_fe
                .open(&mut channel, &[e.value], &mut out_value)
                .unwrap();
            debug!("{:?} {:?}", x, out_value[0]);
            assert_eq!(x, out_value[0]);
        }

        handle.join().unwrap();
    }

    fn test_fdabit<FE: FiniteField<PrimeField = FE>>() {
        let count = 100;
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut fconv =
                ProverConv::<FE>::init(&mut channel, &mut rng, LPN_SETUP_SMALL, LPN_EXTEND_SMALL)
                    .unwrap();

            let dabits = fconv.random_dabits(&mut channel, &mut rng, count).unwrap();
            fconv.fdabit(&mut channel, &mut rng, &dabits).unwrap();
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut fconv =
            VerifierConv::<FE>::init(&mut channel, &mut rng, LPN_SETUP_SMALL, LPN_EXTEND_SMALL)
                .unwrap();

        let dabits_mac = fconv.random_dabits(&mut channel, &mut rng, count).unwrap();
        fconv.fdabit(&mut channel, &mut rng, &dabits_mac).unwrap();

        handle.join().unwrap();
    }

    fn test_conv<FE: FiniteField<PrimeField = FE>>() {
        let nb_edabits = 50;
        let (sender, receiver) = UnixStream::pair().unwrap();

        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut fconv =
                ProverConv::<FE>::init(&mut channel, &mut rng, LPN_SETUP_SMALL, LPN_EXTEND_SMALL)
                    .unwrap();

            for n in 1..nb_edabits {
                let edabits = fconv
                    .random_edabits(&mut channel, &mut rng, NB_BITS, n)
                    .unwrap();

                fconv
                    .conv(
                        &mut channel,
                        &mut rng,
                        DEFAULT_NUM_BUCKET,
                        DEFAULT_NUM_CUT,
                        &edabits,
                        None,
                    )
                    .unwrap();
            }
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut fconv =
            VerifierConv::<FE>::init(&mut channel, &mut rng, LPN_SETUP_SMALL, LPN_EXTEND_SMALL)
                .unwrap();

        for n in 1..nb_edabits {
            let edabits = fconv
                .random_edabits(&mut channel, &mut rng, NB_BITS, n)
                .unwrap();

            fconv
                .conv(
                    &mut channel,
                    &mut rng,
                    DEFAULT_NUM_BUCKET,
                    DEFAULT_NUM_CUT,
                    &edabits,
                    None,
                )
                .unwrap();
        }

        handle.join().unwrap();
    }

    #[test]
    fn test_convert_bit_2_field_f61p() {
        test_convert_bit_2_field::<F61p>();
    }

    #[test]
    fn test_random_edabits_b2a_f61p() {
        test_random_edabits_b2a::<F61p>(61);
    }

    #[test]
    fn test_random_edabits_b2a_f384p() {
        test_random_edabits_b2a::<F384p>(384);
    }

    #[test]
    fn test_bit_add_carry_f61p() {
        test_bit_add_carry::<F61p>();
    }

    #[test]
    fn test_fdabit_f61p() {
        test_fdabit::<F61p>();
    }

    #[test]
    fn test_conv_f61p() {
        test_conv::<F61p>();
    }
}
