// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2021 Galois, Inc.
// See LICENSE for licensing information.

//! This is the implementation of field conversion

use crate::errors::Error;
use rand::{CryptoRng, Rng, SeedableRng};
use scuttlebutt::{
    field::{FiniteField, Gf40, F2},
    AbstractChannel, AesRng, Block,
};

use super::homcom::{FComReceiver, FComSender};

/// Edabits struct
#[derive(Clone)]
struct Edabits<FE: FiniteField> {
    bits: Vec<F2>,
    value: FE::PrimeField,
}
/// EdabitsMac struct
#[derive(Clone)]
struct EdabitsMac<FE: FiniteField> {
    bits: Vec<Gf40>,
    value: FE,
}

/// Dabit struct
#[derive(Clone)]
struct Dabit<FE: FiniteField> {
    bit: F2,
    value: FE::PrimeField,
}

/// Dabit struct
#[derive(Clone)]
struct DabitMac<FE: FiniteField> {
    bit: Gf40,
    value: FE,
}

/// Conversion protocol sender
struct SenderConv<FE: FiniteField> {
    fcom_f2: FComSender<Gf40>,
    fcom: FComSender<FE>,
}

const NB_BITS: usize = 6;

const B: usize = 5;
const C: usize = 5;

const FDABIT_SECURITY_PARAMETER: usize = 10;

/// bit to field element
fn bit_to_fe<FE: FiniteField>(b: F2) -> FE {
    if b == F2::ZERO {
        FE::ZERO
    } else {
        FE::ONE
    }
}

fn convert_f2_to_field<FE: FiniteField>(v: &Vec<F2>) -> FE::PrimeField {
    let mut res = FE::PrimeField::ZERO;

    for i in 0..v.len() {
        let b = v[v.len() - i - 1];
        res += res; // double
        if b == F2::ONE {
            res += FE::PrimeField::ONE;
        }
    }
    res
}

fn power_two<FE: FiniteField>(m: usize) -> FE {
    let mut res = FE::ONE;

    for _ in 0..m {
        res = res + res;
    }

    res
}

// Permutation pseudorandomly generated following Fisher-Yates method
// `https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle`
fn generate_permutation(seed: Block, size: usize) -> (Vec<usize>, Vec<usize>) {
    let mut rng = AesRng::from_seed(seed);
    let mut permute: Vec<usize> = Vec::with_capacity(size);
    let mut unpermute: Vec<usize> = vec![0; size];

    for i in 0..size {
        permute.push(i);
        //unpermute.push(i);
    }
    let mut i = size - 1;
    while i > 0 {
        let idx = Rng::gen_range(&mut rng, 0, i);
        let tmp: usize = permute[idx];
        permute[idx] = permute[i];
        permute[i] = tmp;
        unpermute[tmp] = i;
        i -= 1;
    }
    (permute, unpermute)
}

// Protocol for checking conversion

impl<FE: FiniteField> SenderConv<FE> {
    pub fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let a = FComSender::init(channel, rng)?;
        let b = FComSender::init(channel, rng)?;
        Ok(Self {
            fcom_f2: a,
            fcom: b,
        })
    }

    fn convert_bit_2_field<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        _rng: &mut RNG,
        r: F2,
        r_mac: Gf40,
        r_m_mac: FE,
        x: F2,
        x_mac: Gf40,
    ) -> Result<(FE::PrimeField, FE), Error> {
        let x_m = bit_to_fe::<FE::PrimeField>(x);
        self.fcom_f2.f_open(channel, r + x, r_mac + x_mac)?;
        let c = r + x;
        let x_m_mac = r_m_mac
            + if c == F2::ONE {
                -(r_m_mac + r_m_mac)
            } else {
                FE::ZERO
            };
        Ok((x_m, x_m_mac))
    }

    fn bit_add_carry<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        x: &[F2],
        x_mac: &[Gf40],
        y: &[F2],
        y_mac: &[Gf40],
    ) -> Result<(Vec<(F2, Gf40)>, (F2, Gf40)), Error> {
        let xl = x.len();
        let yl = y.len();
        if xl != yl {
            return Err(Error::Other(
                "incompatible input vectors in bit_add_carry".to_string(),
            ));
        }

        let mut res = Vec::with_capacity(xl);

        let mut ci = F2::ZERO;
        let mut ci_mac = self.fcom_f2.f_input(channel, rng, ci)?;
        for i in 0..xl {
            let (xi, xi_mac) = (x[i], x_mac[i]);
            let (yi, yi_mac) = (y[i], y_mac[i]);

            let and1 = xi + ci;
            let and1_mac = xi_mac + ci_mac;

            let and2 = yi + ci;
            let and2_mac = yi_mac + ci_mac;

            let and_res = and1 * and2;
            let and_res_mac = self.fcom_f2.f_input(channel, rng, and_res)?;
            self.fcom_f2.f_check_multiply(
                channel,
                rng,
                and1,
                and1_mac,
                and2,
                and2_mac,
                and_res,
                and_res_mac,
            )?;

            let c = ci + and_res;
            let c_mac = ci_mac + and_res_mac;

            let z = xi + yi + ci;
            let z_mac = xi_mac + yi_mac + ci_mac;

            res.push((z, z_mac));

            ci = c;
            ci_mac = c_mac;
        }
        Ok((res, (ci, ci_mac)))
    }

    fn random_edabits<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        num: usize, // in the paper: NB + C
    ) -> Result<(Vec<Edabits<FE>>, Vec<EdabitsMac<FE>>), Error> {
        let mut edabits_vec = Vec::with_capacity(num);
        let mut edabits_vec_mac = Vec::with_capacity(num);
        for _ in 0..num {
            // Generating random edabits
            let mut r = Vec::with_capacity(NB_BITS);
            let mut r_mac = Vec::with_capacity(NB_BITS);
            for _ in 0..NB_BITS {
                let (b, b_mac) = self.fcom_f2.f_random(channel, rng)?;
                r.push(b);
                r_mac.push(b_mac);
            }
            let r_m: FE::PrimeField = convert_f2_to_field::<FE>(&r);
            let r_m_mac: FE = self.fcom.f_input(channel, rng, r_m)?;

            edabits_vec.push(Edabits {
                bits: r,
                value: r_m,
            });

            edabits_vec_mac.push(EdabitsMac {
                bits: r_mac,
                value: r_m_mac,
            });
        }
        Ok((edabits_vec, edabits_vec_mac))
    }

    fn random_dabits<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        num: usize, // in the paper: NB
    ) -> Result<(Vec<Dabit<FE>>, Vec<DabitMac<FE>>), Error> {
        let mut dabit_vec = Vec::with_capacity(num);
        let mut dabit_vec_mac = Vec::with_capacity(num);
        for _ in 0..num {
            let (b, b_mac) = self.fcom_f2.f_random(channel, rng)?;
            let b_m = bit_to_fe(b);
            let b_m_mac = self.fcom.f_input(channel, rng, b_m)?;
            dabit_vec.push(Dabit { bit: b, value: b_m });
            dabit_vec_mac.push(DabitMac {
                bit: b_mac,
                value: b_m_mac,
            });
        }
        Ok((dabit_vec, dabit_vec_mac))
    }

    fn fdabit<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        dabits: &Vec<Dabit<FE>>,
        dabits_mac: &Vec<DabitMac<FE>>,
    ) -> Result<(), Error> {
        let s = FDABIT_SECURITY_PARAMETER;
        let n = dabits.len();
        debug_assert_eq!(n, dabits_mac.len());

        let num_bits = std::mem::size_of::<usize>() * 8;
        let gamma = num_bits - ((n + 1).leading_zeros() as usize) - 1 + 1;

        if !((n + 1) as u128 * u128::pow(2, gamma as u32) < (FE::MODULUS - 1) / 2) {
            return Err(Error::Other(
                "fail fdabit verifier: wrong combination of input size and parameters".to_string(),
            ));
        }

        let mut res = true;

        for i in 0..n {
            // making sure the faulty dabits are not faulty
            debug_assert!(
                ((dabits[i].bit == F2::ZERO) & (dabits[i].value == FE::PrimeField::ZERO))
                    | ((dabits[i].bit == F2::ONE) & (dabits[i].value == FE::PrimeField::ONE))
            );
        }

        for _ in 0..s {
            // step 1)
            let mut c_m = Vec::with_capacity(gamma);
            let mut c_m_mac = Vec::with_capacity(gamma);
            for _ in 0..gamma {
                let b: F2 = F2::random(rng);
                let b_m = bit_to_fe(b);
                let b_m_mac = self.fcom.f_input(channel, rng, b_m)?;
                c_m.push(b_m);
                c_m_mac.push(b_m_mac);
            }
            let c1;

            if c_m[0] == FE::PrimeField::ZERO {
                c1 = F2::ZERO;
            } else {
                c1 = F2::ONE;
            }

            let c1_mac = self.fcom_f2.f_input(channel, rng, c1)?;

            // step 2)
            for i in 0..gamma {
                let andl = c_m[i];
                let andl_mac = c_m_mac[i];
                let (minus_ci, minus_ci_mac) : (FE::PrimeField,FE) = // -ci
                    self.fcom.f_affine_mult_cst(-FE::PrimeField::ONE, andl, andl_mac);
                let (one_minus_ci, one_minus_ci_mac) = // 1 - ci
                    self.fcom.f_affine_add_cst(FE::PrimeField::ONE, minus_ci, minus_ci_mac);
                let and_res = andl * one_minus_ci;
                let and_res_mac = self.fcom.f_input(channel, rng, and_res)?;
                self.fcom.f_check_multiply(
                    channel,
                    rng,
                    andl,
                    andl_mac,
                    one_minus_ci,
                    one_minus_ci_mac,
                    and_res,
                    and_res_mac,
                )?;
            }

            // step 3)
            let seed = channel.read_block()?;
            let mut e_rng = AesRng::from_seed(seed);
            let mut e = Vec::with_capacity(n);
            for _i in 0..n {
                let b = F2::random(&mut e_rng);
                e.push(b);
            }

            // step 4)
            let (mut r, mut r_mac) = (c1, c1_mac);
            for i in 0..n {
                // TODO: do not need to do it when e[i] is ZERO
                let (tmp, tmp_mac) =
                    self.fcom_f2
                        .f_affine_mult_cst(e[i], dabits[i].bit, dabits_mac[i].bit);
                debug_assert!(((e[i] == F2::ONE) & (tmp == dabits[i].bit)) | (tmp == F2::ZERO));
                r += tmp;
                r_mac += tmp_mac;
            }

            // step 5)
            let _ = self.fcom_f2.f_open(channel, r, r_mac)?;

            // step 6)
            // NOTE: for performance maybe step 4 and 6 should be combined in one loop
            let (mut r_prime, mut r_prime_mac) = (FE::PrimeField::ZERO, FE::ZERO);
            for i in 0..n {
                // TODO: do not need to do it when e[i] is ZERO
                let b = bit_to_fe(e[i]);
                let (tmp, tmp_mac) =
                    self.fcom
                        .f_affine_mult_cst(b, dabits[i].value, dabits_mac[i].value);
                debug_assert!(
                    ((b == FE::PrimeField::ONE) & (tmp == dabits[i].value))
                        | (tmp == FE::PrimeField::ZERO)
                );
                r_prime += tmp;
                r_prime_mac += tmp_mac;
            }

            // step 7)
            let (mut tau, mut tau_mac) = (r_prime, r_prime_mac);
            let mut twos = FE::PrimeField::ONE;
            for i in 0..gamma {
                let (tmp, tmp_mac) = self.fcom.f_affine_mult_cst(twos, c_m[i], c_m_mac[i]);
                if i == 0 {
                    debug_assert!(c_m[i] == tmp);
                }
                tau += tmp;
                tau_mac += tmp_mac;
                twos += twos;
            }
            let _ = self.fcom.f_open(channel, tau, tau_mac)?;

            // step 8)
            // NOTE: This is not needed for the prover,
            let b: bool;
            match (r == F2::ONE, tau.modulus2()) {
                (true, true) => {
                    b = true;
                }
                (false, false) => {
                    b = true;
                }
                (true, false) => {
                    b = false;
                }
                (false, true) => {
                    b = false;
                }
            };
            res = res & b;
        }
        if res {
            Ok(())
        } else {
            Err(Error::Other("fail fdabit prover".to_string()))
        }
    }

    fn conv<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        edabits_vector: &[Edabits<FE>],
        edabits_vector_mac: &[EdabitsMac<FE>],
    ) -> Result<(), Error> {
        let nb_random_edabits = edabits_vector.len() * B + C;
        let nb_random_dabits = edabits_vector.len() * B;

        // step 1)a): commit random edabit
        let (r, r_mac) = self.random_edabits(channel, rng, nb_random_edabits)?;

        // step 1)b)
        let (dabits, dabits_mac) = self.random_dabits(channel, rng, nb_random_dabits)?;

        // step 1)c): TODO: random multiplication triples

        // step 2): TODO: verify dabit
        self.fdabit(channel, rng, &dabits, &dabits_mac)?;

        // step 3): TODO: generate pi_2 and pi_3
        let seed = channel.read_block()?;
        let (perm1, _unperm1) = generate_permutation(seed, nb_random_edabits);

        // step 4): TODO: apply the permutation instead of indirections

        // step 5)a):
        let base = edabits_vector_mac.len() * B;
        for i in 0..C {
            let idx = base + i;
            let a = &r[perm1[idx]];
            let a_mac = &r_mac[perm1[idx]];
            for bi in 0..NB_BITS {
                self.fcom_f2.f_open(channel, a.bits[bi], a_mac.bits[bi])?;
            }
            self.fcom.f_open(channel, a.value, a_mac.value)?;
        }
        // step 5) b): TODO: open triples

        // step 6)
        for i in 0..edabits_vector.len() {
            let edabits = &edabits_vector[i];
            let edabits_mac = &edabits_vector_mac[i];

            // mapping arguments to variable names similar to ones in the paper
            let c = &edabits.bits;
            let c_mac = &edabits_mac.bits;
            let c_m_mac = edabits_mac.value;

            let idx_base = i * B;
            for j in 0..B {
                let idx_dabit = idx_base + j;

                // pick the random dabit
                let b = dabits[idx_dabit].bit;
                let b_mac = dabits_mac[idx_dabit].bit;
                let b_m_mac = dabits_mac[idx_dabit].value;

                //pick the random edabit
                let idx_r = idx_base + j;

                // 6)a)
                let r_m_mac = r_mac[idx_r].value;
                let c_plus_r_mac = c_m_mac + r_m_mac;

                // 6)b)
                let (e, e_carry) = self.bit_add_carry(
                    channel,
                    rng,
                    &c,
                    &c_mac,
                    &r[idx_r].bits,
                    &r_mac[idx_r].bits,
                )?;

                // 6)c)
                let (_, e_m_mac) = self
                    .convert_bit_2_field(channel, rng, b, b_mac, b_m_mac, e_carry.0, e_carry.1)?;

                // 6)d)
                let e1_mac = c_plus_r_mac
                    - e_m_mac.multiply_by_prime_subfield(power_two::<FE::PrimeField>(NB_BITS));

                // 6)e)
                let mut ei = Vec::new();
                for i in 0..NB_BITS {
                    let elm = self.fcom_f2.f_open(channel, e[i].0, e[i].1)?;
                    ei.push(elm);
                }

                // Remark this is not necessary for the prover, bc cst addition dont show up in mac
                // let s = convert_f2_to_field(ei);
                let _ = self.fcom.f_check_zero(channel, e1_mac)?;
            }
        }

        Ok(())
    }
}

/// Conversion protocol receiver
struct ReceiverConv<FE: FiniteField> {
    fcom_f2: FComReceiver<Gf40>,
    fcom: FComReceiver<FE>,
}

impl<FE: FiniteField> ReceiverConv<FE> {
    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let a = FComReceiver::init(channel, rng)?;
        let b = FComReceiver::init(channel, rng)?;
        Ok(Self {
            fcom_f2: a,
            fcom: b,
        })
    }

    fn convert_bit_2_field<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        _rng: &mut RNG,
        r_mac: Gf40,
        r_m_mac: FE,
        x_mac: Gf40,
    ) -> Result<FE, Error> {
        let c = self.fcom_f2.f_open(channel, r_mac + x_mac)?;
        let x_m_mac = (if c == F2::ONE {
            -self.fcom.get_delta()
        } else {
            FE::ZERO
        }) + r_m_mac
            + if c == F2::ONE {
                -(r_m_mac + r_m_mac)
            } else {
                FE::ZERO
            };
        Ok(x_m_mac)
    }

    fn bit_add_carry<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        x: &[Gf40],
        y: &[Gf40],
    ) -> Result<(Vec<Gf40>, Gf40), Error> {
        let xl = x.len();
        let yl = y.len();
        if xl != yl {
            return Err(Error::Other(
                "incompatible input vectors in bit_add_carry".to_string(),
            ));
        }

        let mut res = Vec::with_capacity(xl);

        let mut ci_mac = self.fcom_f2.f_input(channel, rng)?;
        for i in 0..xl {
            let xi_mac = x[i];
            let yi_mac = y[i];

            let and1_mac = xi_mac + ci_mac;
            let and2_mac = yi_mac + ci_mac;

            let and_res_mac = self.fcom_f2.f_input(channel, rng)?;

            self.fcom_f2
                .f_check_multiply(channel, rng, and1_mac, and2_mac, and_res_mac)?;

            let c_mac = ci_mac + and_res_mac;

            let z_mac = xi_mac + yi_mac + ci_mac;

            res.push(z_mac);

            ci_mac = c_mac;
        }
        Ok((res, ci_mac))
    }

    fn random_edabits<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        num: usize, // in the paper: NB + C
    ) -> Result<Vec<EdabitsMac<FE>>, Error> {
        let mut edabits_vec_mac = Vec::with_capacity(num);
        for _ in 0..num {
            let mut r_mac = Vec::with_capacity(NB_BITS);
            for _ in 0..NB_BITS {
                let b_mac = self.fcom_f2.f_random(channel, rng)?;
                r_mac.push(b_mac);
            }

            let r_m_mac = self.fcom.f_input(channel, rng)?;
            edabits_vec_mac.push(EdabitsMac {
                bits: r_mac,
                value: r_m_mac,
            });
        }
        Ok(edabits_vec_mac)
    }

    fn random_dabits<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        num: usize, // in the paper: NB
    ) -> Result<Vec<DabitMac<FE>>, Error> {
        let mut dabit_vec_mac = Vec::with_capacity(num);
        for _ in 0..num {
            let b_mac = self.fcom_f2.f_random(channel, rng)?;
            let b_m_mac = self.fcom.f_input(channel, rng)?;
            dabit_vec_mac.push(DabitMac {
                bit: b_mac,
                value: b_m_mac,
            });
        }
        Ok(dabit_vec_mac)
    }

    fn fdabit<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        dabits_mac: &Vec<DabitMac<FE>>,
    ) -> Result<(), Error> {
        let s = FDABIT_SECURITY_PARAMETER;
        let n = dabits_mac.len();

        let num_bits = std::mem::size_of::<usize>() * 8;
        let gamma = num_bits - ((n + 1).leading_zeros() as usize) - 1 + 1;

        if !((n + 1) as u128 * u128::pow(2, gamma as u32) < (FE::MODULUS - 1) / 2) {
            return Err(Error::Other(
                "fail fdabit verifier: wrong combination of input size and parameters".to_string(),
            ));
        }

        let mut res = true;

        for _ in 0..s {
            // step 1)
            let mut c_m_mac = Vec::with_capacity(gamma);
            for _ in 0..gamma {
                let b_m_mac = self.fcom.f_input(channel, rng)?;
                c_m_mac.push(b_m_mac);
            }

            let c1_mac = self.fcom_f2.f_input(channel, rng)?;

            // step 2)
            for i in 0..gamma {
                let andl_mac = c_m_mac[i];
                let minus_ci_mac : FE = // -ci
                    self.fcom.f_affine_mult_cst(-FE::PrimeField::ONE, andl_mac);
                let one_minus_ci_mac = // 1 - ci
                    self.fcom.f_affine_add_cst(FE::PrimeField::ONE, minus_ci_mac);
                let and_res_mac = self.fcom.f_input(channel, rng)?;
                self.fcom.f_check_multiply(
                    channel,
                    rng,
                    andl_mac,
                    one_minus_ci_mac,
                    and_res_mac,
                )?;
            }

            // step 3)

            let seed = rng.gen::<Block>();
            channel.write_block(&seed)?;
            channel.flush()?;

            let mut e_rng = AesRng::from_seed(seed);
            let mut e = Vec::with_capacity(n);
            for _i in 0..n {
                let b = F2::random(&mut e_rng);
                e.push(b);
            }

            // step 4)
            let mut r_mac = c1_mac;
            for i in 0..n {
                // TODO: do not need to do it when e[i] is ZERO
                let tmp_mac = self.fcom_f2.f_affine_mult_cst(e[i], dabits_mac[i].bit);
                r_mac += tmp_mac;
            }

            // step 5)
            let r = self.fcom_f2.f_open(channel, r_mac)?;

            // step 6)
            // NOTE: for performance maybe step 4 and 6 should be combined in one loop
            let mut r_prime_mac = FE::ZERO;
            for i in 0..n {
                // TODO: do not need to do it when e[i] is ZERO
                let b = bit_to_fe(e[i]);
                let tmp_mac = self.fcom.f_affine_mult_cst(b, dabits_mac[i].value);
                r_prime_mac += tmp_mac;
            }

            // step 7)
            let mut tau_mac = r_prime_mac;
            let mut twos = FE::PrimeField::ONE;
            for i in 0..gamma {
                let tmp_mac = self.fcom.f_affine_mult_cst(twos, c_m_mac[i]);
                tau_mac += tmp_mac;
                twos += twos;
            }
            let tau = self.fcom.f_open(channel, tau_mac)?;

            // step 8)
            let b: bool;
            match (r == F2::ONE, tau.modulus2()) {
                (true, true) => {
                    b = true;
                }
                (false, false) => {
                    b = true;
                }
                (true, false) => {
                    b = false;
                }
                (false, true) => {
                    b = false;
                }
            };
            res = res & b;
        }
        if res {
            Ok(())
        } else {
            Err(Error::Other("fail fdabit verifier".to_string()))
        }
    }

    fn conv<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        edabits_vector_mac: &[EdabitsMac<FE>],
    ) -> Result<(), Error> {
        let mut b = true;

        let nb_random_edabits = edabits_vector_mac.len() * B + C;
        let nb_random_dabits = edabits_vector_mac.len() * B;

        // step 1)a)
        let r_mac = self.random_edabits(channel, rng, nb_random_edabits)?;

        // step 1)b)
        let dabits_mac = self.random_dabits(channel, rng, nb_random_dabits)?;

        // step 1)c): TODO: random multiplication triples

        // step 2): TODO: verify dabit
        self.fdabit(channel, rng, &dabits_mac)?;

        // step 3): TODO: generate pi_2 and pi_3
        let seed = rng.gen::<Block>();
        channel.write_block(&seed)?;
        channel.flush()?;
        let (perm1, _unperm1) = generate_permutation(seed, nb_random_edabits);

        // step 4): TODO: apply the permutation instead of indirections

        // step 5)a):
        let base = edabits_vector_mac.len() * B;
        for i in 0..C {
            let idx = base + i;
            let a_mac = &r_mac[perm1[idx]];
            let mut a_vec = Vec::with_capacity(NB_BITS);
            for bi in 0..NB_BITS {
                let a = self.fcom_f2.f_open(channel, a_mac.bits[bi])?;
                a_vec.push(a);
            }
            let a_m = self.fcom.f_open(channel, a_mac.value)?;
            if convert_f2_to_field::<FE>(&a_vec) != a_m {
                return Err(Error::Other("Wrong open random edabit".to_string()));
            }
        }
        // step 5) b): TODO: open triples

        // step 6)
        for i in 0..edabits_vector_mac.len() {
            let edabits_mac = &edabits_vector_mac[i];
            let c_mac = &edabits_mac.bits;
            let c_m_mac = edabits_mac.value;

            let idx_base = i * B;
            for j in 0..B {
                // pick the random dabit
                let idx_dabit = idx_base + j;
                let b_mac = dabits_mac[idx_dabit].bit;
                let b_m_mac = dabits_mac[idx_dabit].value;

                //pick the random edabit
                let idx_r = idx_base + j;

                // 6)a)
                let r_m_mac = r_mac[idx_r].value;
                let c_plus_r_mac = c_m_mac + r_m_mac;

                // 6)b)
                let (e_mac, e_carry_mac) =
                    self.bit_add_carry(channel, rng, &c_mac, &r_mac[idx_r].bits)?;

                // 6)c)
                let e_m_mac =
                    self.convert_bit_2_field(channel, rng, b_mac, b_m_mac, e_carry_mac)?;

                // 6)d)
                let e1_mac = c_plus_r_mac
                    - e_m_mac.multiply_by_prime_subfield(power_two::<FE::PrimeField>(NB_BITS));

                // 6)e)
                let mut ei = Vec::new();
                for i in 0..NB_BITS {
                    let elm = self.fcom_f2.f_open(channel, e_mac[i])?;
                    ei.push(elm);
                }

                let s = convert_f2_to_field::<FE>(&ei);
                b = self.fcom.f_check_zero(
                    channel,
                    e1_mac + self.fcom.get_delta().multiply_by_prime_subfield(s),
                )?;
            }
        }

        if b {
            Ok(())
        } else {
            Err(Error::Other("conversion check failed".to_string()))
        }
    }
}

#[cfg(test)]
mod tests {

    use super::{
        bit_to_fe, convert_f2_to_field, Edabits, EdabitsMac, ReceiverConv, SenderConv, NB_BITS,
    };
    use scuttlebutt::{
        field::{F61p, FiniteField, Gf40, F2},
        AesRng, Channel,
    };
    use std::{
        io::{BufReader, BufWriter},
        os::unix::net::UnixStream,
    };

    fn test_convert_bit_2_field<FE: FiniteField>() -> () {
        let count = 100;
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut fconv = SenderConv::<FE>::init(&mut channel, &mut rng).unwrap();

            let mut res = Vec::new();
            for _ in 0..count {
                let (rb, rb_mac) = fconv.fcom_f2.f_random(&mut channel, &mut rng).unwrap();
                let rm = bit_to_fe(rb);
                let rm_mac = fconv.fcom.f_input(&mut channel, &mut rng, rm).unwrap();
                let (x_f2, x_f2_mac) = fconv.fcom_f2.f_random(&mut channel, &mut rng).unwrap();

                let (x_m, x_m_mac) = fconv
                    .convert_bit_2_field(&mut channel, &mut rng, rb, rb_mac, rm_mac, x_f2, x_f2_mac)
                    .unwrap();

                let _ = fconv.fcom.f_open(&mut channel, x_m, x_m_mac).unwrap();
                assert_eq!(
                    if x_f2 == F2::ZERO {
                        x_m == FE::PrimeField::ZERO
                    } else {
                        x_m == FE::PrimeField::ONE
                    },
                    true
                );
                res.push((x_f2, x_m));
            }
            res
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut fconv = ReceiverConv::<FE>::init(&mut channel, &mut rng).unwrap();

        let mut res = Vec::new();
        for _ in 0..count {
            let rb_mac = fconv.fcom_f2.f_random(&mut channel, &mut rng).unwrap();
            let r_m_mac = fconv.fcom.f_input(&mut channel, &mut rng).unwrap();
            let x_f2_mac = fconv.fcom_f2.f_random(&mut channel, &mut rng).unwrap();

            let x_m_mac = fconv
                .convert_bit_2_field(&mut channel, &mut rng, rb_mac, r_m_mac, x_f2_mac)
                .unwrap();

            let x_m = fconv.fcom.f_open(&mut channel, x_m_mac).unwrap();
            res.push(x_m);
        }

        let resprover = handle.join().unwrap();

        for i in 0..count {
            assert_eq!(resprover[i].1, res[i]);
        }
    }

    fn test_bit_add_carry<FE: FiniteField>() -> () {
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
            let mut fconv = SenderConv::<FE>::init(&mut channel, &mut rng).unwrap();

            let mut x_mac = Vec::new();
            let mut y_mac = Vec::new();

            for i in 0..power {
                let xb_mac = fconv.fcom_f2.f_input(&mut channel, &mut rng, x[i]).unwrap();
                x_mac.push(xb_mac);

                let yb_mac = fconv.fcom_f2.f_input(&mut channel, &mut rng, y[i]).unwrap();
                y_mac.push(yb_mac);
            }

            let mut vx: Vec<F2> = Vec::new();
            let mut vx_mac: Vec<Gf40> = Vec::new();
            for i in 0..6 {
                vx.push(x[i]);
                vx_mac.push(x_mac[i]);
            }

            let mut vy = Vec::new();
            let mut vy_mac = Vec::new();
            for i in 0..6 {
                vy.push(y[i]);
                vy_mac.push(y_mac[i]);
            }
            let (res, c) = fconv
                .bit_add_carry(&mut channel, &mut rng, &vx, &vx_mac, &vy, &vy_mac)
                .unwrap();

            for i in 0..power {
                fconv
                    .fcom_f2
                    .f_open(&mut channel, res[i].0, res[i].1)
                    .unwrap();
            }
            fconv.fcom_f2.f_open(&mut channel, c.0, c.1).unwrap();
            (res, c)
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut fconv = ReceiverConv::<FE>::init(&mut channel, &mut rng).unwrap();

        let mut x_mac = Vec::new();
        let mut y_mac = Vec::new();
        for _ in 0..power {
            let xb_mac = fconv.fcom_f2.f_input(&mut channel, &mut rng).unwrap();
            x_mac.push(xb_mac);

            let yb_mac = fconv.fcom_f2.f_input(&mut channel, &mut rng).unwrap();
            y_mac.push(yb_mac);
        }
        let (res_mac, c_mac) = fconv
            .bit_add_carry(&mut channel, &mut rng, &x_mac, &y_mac)
            .unwrap();

        let mut res = Vec::new();
        for i in 0..power {
            let b = fconv.fcom_f2.f_open(&mut channel, res_mac[i]).unwrap();
            res.push(b);
        }

        let c = fconv.fcom_f2.f_open(&mut channel, c_mac).unwrap();

        let _resprover = handle.join().unwrap();

        for i in 0..power {
            assert_eq!(expected[i], res[i]);
        }
        assert_eq!(carry, c);
    }

    fn test_fdabit<FE: FiniteField>() -> () {
        let count = 100;
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut fconv = SenderConv::<FE>::init(&mut channel, &mut rng).unwrap();

            let (dabits, dabits_mac) = fconv.random_dabits(&mut channel, &mut rng, count).unwrap();
            let _ = fconv
                .fdabit(&mut channel, &mut rng, &dabits, &dabits_mac)
                .unwrap();
            ()
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut fconv = ReceiverConv::<FE>::init(&mut channel, &mut rng).unwrap();

        let dabits_mac = fconv.random_dabits(&mut channel, &mut rng, count).unwrap();
        let _ = fconv.fdabit(&mut channel, &mut rng, &dabits_mac).unwrap();

        handle.join().unwrap();
    }

    fn test_conv<FE: FiniteField>() -> () {
        let nb_edabits = 50;
        let (sender, receiver) = UnixStream::pair().unwrap();

        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut fconv = SenderConv::<FE>::init(&mut channel, &mut rng).unwrap();

            //   110101
            let mut c = vec![F2::ONE, F2::ZERO, F2::ONE, F2::ZERO, F2::ONE, F2::ONE];
            let mut i = 0;
            let mut j = 0;
            let mut edabits = Vec::with_capacity(nb_edabits);
            let mut edabits_mac = Vec::with_capacity(nb_edabits);
            let mut res = Vec::new();
            for _ in 0..nb_edabits {
                i = (i + 1) % NB_BITS;
                j = (j * 5 + 3) % NB_BITS;

                // mutate bit at position i
                c[i] = F2::random(&mut rng);
                let c_m: FE::PrimeField = convert_f2_to_field::<FE>(&c);

                // introduce a potential error at position j
                let saved = c[j];
                c[j] = F2::random(&mut rng);

                edabits.push(Edabits {
                    bits: c.clone(),
                    value: c_m.clone(),
                });
                let mut bits_mac = Vec::with_capacity(NB_BITS);
                for bitpos in 0..NB_BITS {
                    let v = fconv
                        .fcom_f2
                        .f_input(&mut channel, &mut rng, c[bitpos])
                        .unwrap();
                    bits_mac.push(v);
                }
                let value_mac = fconv.fcom.f_input(&mut channel, &mut rng, c_m).unwrap();
                edabits_mac.push(EdabitsMac {
                    bits: bits_mac,
                    value: value_mac,
                });

                fconv
                    .conv(&mut channel, &mut rng, &edabits, &edabits_mac)
                    .unwrap();

                res.push(saved == c[j])
            }
            res
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut fconv = ReceiverConv::<FE>::init(&mut channel, &mut rng).unwrap();

        let mut res = Vec::new();
        let mut edabits_mac = Vec::with_capacity(nb_edabits);
        for _ in 0..nb_edabits {
            let mut bits_mac = Vec::with_capacity(NB_BITS);
            for _ in 0..NB_BITS {
                let v_mac = fconv.fcom_f2.f_input(&mut channel, &mut rng).unwrap();
                bits_mac.push(v_mac);
            }
            let value_mac = fconv.fcom.f_input(&mut channel, &mut rng).unwrap();
            edabits_mac.push(EdabitsMac {
                bits: bits_mac,
                value: value_mac,
            });

            let r = fconv.conv(&mut channel, &mut rng, &edabits_mac);
            res.push(r);
        }

        let resprover = handle.join().unwrap();

        let mut i = 0;
        for b in resprover.iter() {
            let _ = match (b, res[i].as_ref()) {
                (true, Err(_)) => {
                    println!("Break at iteration #{}", i);
                    assert_eq!(true, false)
                }
                (false, Ok(())) => {
                    println!("Break at iteration #{}", i);
                    assert_eq!(true, false)
                }
                (_, _) => (),
            };
            // if *b {
            //     println!("true");
            // } else {
            //     println!("false");
            // }
            i += 1;
        }
    }

    #[test]
    fn test_convert_bit_2_field_f61p() {
        test_convert_bit_2_field::<F61p>();
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
