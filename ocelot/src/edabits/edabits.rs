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

use super::homcom::{FComReceiver, FComSender, MacValue};

/// Edabits struct
#[derive(Clone)]
pub struct EdabitsProver<FE: FiniteField> {
    bits: Vec<(F2, Gf40)>,
    value: (FE::PrimeField, FE),
}
/// EdabitsMac struct
#[derive(Clone)]
pub struct EdabitsVerifier<FE: FiniteField> {
    bits: Vec<Gf40>,
    value: FE,
}

/// Dabit struct
#[derive(Clone)]
struct DabitProver<FE: FiniteField> {
    bit: (F2, Gf40),
    value: (FE::PrimeField, FE),
}

/// Dabit struct
#[derive(Clone)]
struct DabitVerifier<FE: FiniteField> {
    bit: Gf40,
    value: FE,
}

/// Conversion sender
pub struct SenderConv<FE: FiniteField> {
    fcom_f2: FComSender<Gf40>,
    fcom: FComSender<FE>,
}

const NB_BITS: usize = 38; // 2 less than 40 bits, suspicious coincidence

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

fn convert_f2_to_field<FE: FiniteField>(v: &[F2]) -> FE::PrimeField {
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
fn generate_permutation<T: Clone>(seed: Block, v: Vec<T>) -> Vec<T> {
    let size = v.len();
    let mut rng = AesRng::from_seed(seed);
    let mut permute = Vec::with_capacity(size);

    for i in 0..size {
        permute.push(v[i].clone());
    }

    let mut i = size - 1;
    while i > 0 {
        let idx = Rng::gen_range(&mut rng, 0, i);
        let tmp: T = permute[idx].clone();
        permute[idx] = permute[i].clone();
        permute[i] = tmp;
        i -= 1;
    }
    permute
}

impl<FE: FiniteField> SenderConv<FE> {
    /// initialize conversion sender
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
        dabit_batch: &[DabitProver<FE>],
        input_batch: Vec<(F2, Gf40)>,
    ) -> Result<Vec<(FE::PrimeField, FE)>, Error> {
        let n = dabit_batch.len();
        debug_assert!(n == input_batch.len());

        let mut r_plus_x = Vec::with_capacity(n);
        for i in 0..n {
            let r = dabit_batch[i].bit.0;
            let r_mac = dabit_batch[i].bit.1;
            let x = input_batch[i].0;
            let x_mac = input_batch[i].1;
            r_plus_x.push((r + x, r_mac + x_mac));
        }
        self.fcom_f2.f_open_batch(channel, &r_plus_x)?;

        let mut x_m_batch = Vec::with_capacity(n);
        for i in 0..n {
            let r = dabit_batch[i].bit.0;
            let r_m_mac = dabit_batch[i].value.1;
            let x = input_batch[i].0;

            let x_m = bit_to_fe::<FE::PrimeField>(x);
            let c = r + x;
            let x_m_mac = r_m_mac
                + if c == F2::ONE {
                    -(r_m_mac + r_m_mac)
                } else {
                    FE::ZERO
                };
            x_m_batch.push((x_m, x_m_mac));
        }

        Ok(x_m_batch)
    }

    // This function applies the bit_add_carry to a batch of bits,
    // contrary to the one in the paper that applies it on a pair of
    // bits. This allows to the keep the rounds of communication equal
    // to m for any vector of additions
    fn bit_add_carry<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        x_batch: &[EdabitsProver<FE>],
        y_batch: &[EdabitsProver<FE>],
    ) -> Result<Vec<(Vec<(F2, Gf40)>, (F2, Gf40))>, Error> {
        let x_batch_len = x_batch.len();
        let y_batch_len = y_batch.len();
        if x_batch_len != y_batch_len {
            return Err(Error::Other(
                "incompatible input vectors in bit_add_carry".to_string(),
            ));
        }

        let m = x_batch[0].bits.len();

        // input c0
        let mut ci_batch = vec![F2::ZERO; x_batch_len];
        let mut ci_mac_batch = self.fcom_f2.f_input_batch(channel, rng, &ci_batch)?;

        // loop on the m bits over the batch of n addition
        let mut triples = Vec::with_capacity(x_batch_len * m);
        let mut aux_batch = Vec::with_capacity(x_batch_len);
        let mut and_res_batch = Vec::with_capacity(x_batch_len);
        let mut z_batch = vec![Vec::with_capacity(m); x_batch_len];
        for i in 0..m {
            and_res_batch.clear();
            aux_batch.clear();
            for n in 0..x_batch_len {
                let ci = ci_batch[n];
                let ci_mac = ci_mac_batch[n];

                let x = &x_batch[n].bits;
                let y = &y_batch[n].bits;

                if x.len() != m || y.len() != m {
                    panic!("bits vector of different length");
                }

                let (xi, xi_mac) = x[i];
                let (yi, yi_mac) = y[i];

                let and1 = xi + ci;
                let and1_mac = xi_mac + ci_mac;

                let and2 = yi + ci;
                let and2_mac = yi_mac + ci_mac;

                let and_res = and1 * and2;

                and_res_batch.push(and_res);
                aux_batch.push((and1, and1_mac, and2, and2_mac));
            }
            let and_res_mac_batch = self.fcom_f2.f_input_batch(channel, rng, &and_res_batch)?;

            for n in 0..x_batch_len {
                let ci = ci_batch[n];
                let ci_mac = ci_mac_batch[n];
                let x = &x_batch[n].bits;
                let y = &y_batch[n].bits;

                let (xi, xi_mac) = x[i];
                let (yi, yi_mac) = y[i];

                let and1 = aux_batch[n].0;
                let and1_mac = aux_batch[n].1;
                let and2 = aux_batch[n].2;
                let and2_mac = aux_batch[n].3;
                let and_res = and_res_batch[n];
                let and_res_mac = and_res_mac_batch[n];
                triples.push((
                    MacValue(and1, and1_mac),
                    MacValue(and2, and2_mac),
                    MacValue(and_res, and_res_mac),
                ));

                let c = ci + and_res;
                let c_mac = ci_mac + and_res_mac;

                let z = xi + yi + ci;
                let z_mac = xi_mac + yi_mac + ci_mac;

                ci_batch[n] = c;
                ci_mac_batch[n] = c_mac;

                z_batch[n].push((z, z_mac));
            }
        }

        // check all the multiplications in one batch
        self.fcom_f2
            .quicksilver_check_multiply(channel, rng, &triples)?;

        // reconstruct the solution
        let mut res = Vec::with_capacity(x_batch_len);
        for n in 0..x_batch_len {
            res.push((z_batch[n].clone(), (ci_batch[n], ci_mac_batch[n])));
        }

        Ok(res)
    }

    /// generate random edabits
    pub fn random_edabits<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        num: usize, // in the paper: NB + C
    ) -> Result<Vec<EdabitsProver<FE>>, Error> {
        let mut edabits_vec = Vec::with_capacity(num);
        let random_bits = self.fcom_f2.f_random_batch(channel, rng, NB_BITS * num)?;

        let mut aux_bits = Vec::with_capacity(num);
        let mut aux_r_m = Vec::with_capacity(num);
        for i in 0..num {
            let mut bits = Vec::with_capacity(NB_BITS);
            let startidx = NB_BITS * i;
            for j in 0..NB_BITS {
                bits.push(random_bits[startidx + j]);
            }
            let r_m: FE::PrimeField =
                convert_f2_to_field::<FE>(bits.iter().map(|x| x.0).collect::<Vec<F2>>().as_slice());
            aux_bits.push(bits);
            aux_r_m.push(r_m);
        }

        let aux_r_m_mac: Vec<FE> = self.fcom.f_input_batch(channel, rng, &aux_r_m)?;

        for i in 0..num {
            edabits_vec.push(EdabitsProver {
                bits: aux_bits[i].clone(),
                value: (aux_r_m[i], aux_r_m_mac[i]),
            });
        }
        Ok(edabits_vec)
    }

    fn random_dabits<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        num: usize, // in the paper: NB
    ) -> Result<Vec<DabitProver<FE>>, Error> {
        let mut dabit_vec = Vec::with_capacity(num);
        for _ in 0..num {
            let (b, b_mac) = self.fcom_f2.f_random(channel, rng)?;
            let b_m = bit_to_fe(b);
            let b_m_mac = self.fcom.f_input(channel, rng, b_m)?;
            dabit_vec.push(DabitProver {
                bit: (b, b_mac),
                value: (b_m, b_m_mac),
            });
        }
        Ok(dabit_vec)
    }

    fn fdabit<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        dabits: &Vec<DabitProver<FE>>,
    ) -> Result<(), Error> {
        let s = FDABIT_SECURITY_PARAMETER;
        let n = dabits.len();

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
                ((dabits[i].bit.0 == F2::ZERO) & (dabits[i].value.0 == FE::PrimeField::ZERO))
                    | ((dabits[i].bit.0 == F2::ONE) & (dabits[i].value.0 == FE::PrimeField::ONE))
            );
        }

        // step 1)
        let mut c_m: Vec<Vec<FE::PrimeField>> = vec![Vec::with_capacity(gamma); s];
        let mut c_m_mac: Vec<Vec<FE>> = Vec::with_capacity(s);
        for k in 0..s {
            for _ in 0..gamma {
                let b: F2 = F2::random(rng);
                let b_m = bit_to_fe(b);
                c_m[k].push(b_m);
            }
        }

        for k in 0..s {
            let b_m_mac = self.fcom.f_input_batch(channel, rng, c_m[k].as_slice())?;
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
        let c1_mac = self.fcom_f2.f_input_batch(channel, rng, &c1)?;

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
                let (minus_ci, minus_ci_mac) : (FE::PrimeField,FE) = // -ci
                    self.fcom.f_affine_mult_cst(-FE::PrimeField::ONE, andl, andl_mac);
                let (one_minus_ci, one_minus_ci_mac) = // 1 - ci
                    self.fcom.f_affine_add_cst(FE::PrimeField::ONE, minus_ci, minus_ci_mac);
                let and_res = andl * one_minus_ci;
                andl_batch.push(andl);
                andl_mac_batch.push(andl_mac);
                one_minus_ci_batch.push(one_minus_ci);
                one_minus_ci_mac_batch.push(one_minus_ci_mac);
                and_res_batch.push(and_res);
            }
        }
        let and_res_mac_batch = self.fcom.f_input_batch(channel, rng, &and_res_batch)?;

        for j in 0..s * gamma {
            triples.push((
                MacValue(andl_batch[j], andl_mac_batch[j]),
                MacValue(one_minus_ci_batch[j], one_minus_ci_mac_batch[j]),
                MacValue(and_res_batch[j], and_res_mac_batch[j]),
            ));
        }

        // step 3)
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
                let (tmp, tmp_mac) =
                    self.fcom_f2
                        .f_affine_mult_cst(e[k][i], dabits[i].bit.0, dabits[i].bit.1);
                debug_assert!(
                    ((e[k][i] == F2::ONE) & (tmp == dabits[i].bit.0)) | (tmp == F2::ZERO)
                );
                r += tmp;
                r_mac += tmp_mac;
            }
            r_batch.push((r, r_mac));
        }

        // step 5) TODO: move this to the end
        let _ = self.fcom_f2.f_open_batch(channel, &r_batch)?;

        // step 6)
        let mut r_prime_batch = Vec::with_capacity(s);
        for k in 0..s {
            // step 6)
            // NOTE: for performance maybe step 4 and 6 should be combined in one loop
            let (mut r_prime, mut r_prime_mac) = (FE::PrimeField::ZERO, FE::ZERO);
            for i in 0..n {
                // TODO: do not need to do it when e[i] is ZERO
                let b = bit_to_fe(e[k][i]);
                let (tmp, tmp_mac) =
                    self.fcom
                        .f_affine_mult_cst(b, dabits[i].value.0, dabits[i].value.1);
                debug_assert!(
                    ((b == FE::PrimeField::ONE) & (tmp == dabits[i].value.0))
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
                let (tmp, tmp_mac) = self.fcom.f_affine_mult_cst(twos, c_m[k][i], c_m_mac[k][i]);
                if i == 0 {
                    debug_assert!(c_m[k][i] == tmp);
                }
                tau += tmp;
                tau_mac += tmp_mac;
                twos += twos;
            }
            tau_batch.push((tau, tau_mac));
        }

        let _ = self.fcom.f_open_batch(channel, &tau_batch)?;

        // step 8)
        for k in 0..s {
            // step 8)
            // NOTE: This is not needed for the prover,
            let b: bool;
            match (r_batch[k].0 == F2::ONE, tau_batch[k].0.modulus2()) {
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
        self.fcom
            .quicksilver_check_multiply(channel, rng, &triples)?;

        if res {
            Ok(())
        } else {
            Err(Error::Other("fail fdabit prover".to_string()))
        }
    }

    /// conversion checking
    pub fn conv<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        edabits_vector: &[EdabitsProver<FE>],
    ) -> Result<(), Error> {
        let n = edabits_vector.len();

        let nb_random_edabits = n * B + C;
        let nb_random_dabits = n * B;

        // step 1)a): commit random edabit
        let r = self.random_edabits(channel, rng, nb_random_edabits)?;

        // step 1)b)
        let dabits = self.random_dabits(channel, rng, nb_random_dabits)?;

        // step 1)c): TODO: random multiplication triples

        // step 2)
        self.fdabit(channel, rng, &dabits)?;

        // step 3): TODO: generate pi_2 and pi_3
        let seed1 = channel.read_block()?;

        // step 4): TODO: apply permutation to dabits and triples
        let r = generate_permutation(seed1, r);

        // step 5)a):
        let base = n * B;
        for i in 0..C {
            let idx = base + i;
            let a = &r[idx];
            self.fcom_f2.f_open_batch(channel, &a.bits)?;
            self.fcom.f_open(channel, a.value.0, a.value.1)?;
        }
        // step 5) b): TODO: open triples

        // step 6)
        for j in 0..B {
            let idx_base = j * n;

            // step 6)b) batched and moved up
            let e_batch =
                self.bit_add_carry(channel, rng, &edabits_vector, &r[idx_base..idx_base + n])?;

            // step 6)c) batched and moved up
            let mut e_carry_batch = Vec::with_capacity(n);
            for (_, e_carry) in e_batch.iter() {
                e_carry_batch.push(e_carry.clone());
            }
            let e_m_batch = self.convert_bit_2_field(
                channel,
                rng,
                &dabits[idx_base..idx_base + n],
                e_carry_batch,
            )?;

            let mut e1_mac_batch = Vec::with_capacity(n);
            let mut ei_batch = Vec::with_capacity(n * NB_BITS);
            for i in 0..n {
                let edabits = &edabits_vector[i];

                // mapping arguments to variable names similar to ones in the paper
                let (_c_m, c_m_mac) = edabits.value;

                //pick the random edabit
                let idx_r = idx_base + i;

                // 6)a)
                let (_r_m, r_m_mac) = r[idx_r].value;
                let c_plus_r_mac = c_m_mac + r_m_mac;

                // 6)c) done earlier
                let e_m_mac = e_m_batch[i].1;

                // 6)d)
                let e1_mac = c_plus_r_mac
                    - e_m_mac.multiply_by_prime_subfield(power_two::<FE::PrimeField>(NB_BITS));
                e1_mac_batch.push(e1_mac);

                ei_batch.extend(&e_batch[i].0);
            }

            // 6)e)
            let _ei = self.fcom_f2.f_open_batch(channel, &ei_batch)?;

            // Remark this is not necessary for the prover, bc cst addition dont show up in mac
            // let s = convert_f2_to_field(ei);
            self.fcom.f_check_zero_batch(channel, e1_mac_batch)?;
        }

        Ok(())
    }
}

/// Conversion receiver
pub struct ReceiverConv<FE: FiniteField> {
    fcom_f2: FComReceiver<Gf40>,
    fcom: FComReceiver<FE>,
}

impl<FE: FiniteField> ReceiverConv<FE> {
    /// initialize conversion receiver
    pub fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
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
        r_batch: &[DabitVerifier<FE>],
        x_mac_batch: Vec<Gf40>,
    ) -> Result<Vec<FE>, Error> {
        let n = r_batch.len();
        debug_assert!(n == x_mac_batch.len());

        let mut r_mac_plus_x_mac = Vec::with_capacity(n);

        for i in 0..n {
            r_mac_plus_x_mac.push(r_batch[i].bit + x_mac_batch[i]);
        }

        let c_batch = self.fcom_f2.f_open_batch(channel, &r_mac_plus_x_mac)?;

        let mut x_m_mac_batch = Vec::with_capacity(n);

        for i in 0..n {
            let r_m_mac = r_batch[i].value;
            let c = c_batch[i];

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
            x_m_mac_batch.push(x_m_mac);
        }
        Ok(x_m_mac_batch)
    }

    fn bit_add_carry<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        x_batch: &[EdabitsVerifier<FE>],
        y_batch: &[EdabitsVerifier<FE>],
    ) -> Result<Vec<(Vec<Gf40>, Gf40)>, Error> {
        let x_batch_len = x_batch.len();
        let y_batch_len = y_batch.len();
        if x_batch_len != y_batch_len {
            return Err(Error::Other(
                "incompatible input vectors in bit_add_carry".to_string(),
            ));
        }

        let m = x_batch[0].bits.len();

        // input c0
        let mut ci_mac_batch = self.fcom_f2.f_input_batch(channel, rng, x_batch_len)?;

        // loop on the m bits over the batch of n addition
        let mut triples = Vec::with_capacity(x_batch_len * m);
        let mut aux_batch = Vec::with_capacity(x_batch_len);
        let mut z_batch = vec![Vec::with_capacity(m); x_batch_len];
        for i in 0..m {
            aux_batch.clear();
            for n in 0..x_batch_len {
                let ci_mac = ci_mac_batch[n];

                let x = &x_batch[n].bits;
                let y = &y_batch[n].bits;

                if x.len() != m || y.len() != m {
                    panic!("bits vector of different length");
                }
                let xi_mac = x[i];
                let yi_mac = y[i];

                let and1_mac = xi_mac + ci_mac;

                let and2_mac = yi_mac + ci_mac;

                aux_batch.push((and1_mac, and2_mac));
            }
            let and_res_mac_batch = self.fcom_f2.f_input_batch(channel, rng, x_batch_len)?;

            for n in 0..x_batch_len {
                let ci_mac = ci_mac_batch[n];
                let x = &x_batch[n].bits;
                let y = &y_batch[n].bits;

                let xi_mac = x[i];
                let yi_mac = y[i];

                let and1_mac = aux_batch[n].0;
                let and2_mac = aux_batch[n].1;
                let and_res_mac = and_res_mac_batch[n];
                triples.push((and1_mac, and2_mac, and_res_mac));

                let c_mac = ci_mac + and_res_mac;

                let z_mac = xi_mac + yi_mac + ci_mac;

                ci_mac_batch[n] = c_mac;

                z_batch[n].push(z_mac);
            }
        }
        // check all the multiplications in one batch
        self.fcom_f2
            .quicksilver_check_multiply(channel, rng, &triples)?;

        // reconstruct the solution
        let mut res = Vec::with_capacity(x_batch_len);
        for n in 0..x_batch_len {
            res.push((z_batch[n].clone(), ci_mac_batch[n]));
        }

        Ok(res)
    }

    /// generate random edabits
    pub fn random_edabits<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        num: usize, // in the paper: NB + C
    ) -> Result<Vec<EdabitsVerifier<FE>>, Error> {
        let mut edabits_vec_mac = Vec::with_capacity(num);
        let r_mac = self.fcom_f2.f_random_batch(channel, rng, NB_BITS * num)?;

        let mut aux_bits = Vec::with_capacity(num);
        for i in 0..num {
            let mut bits = Vec::with_capacity(NB_BITS);
            let startidx = NB_BITS * i;
            for j in 0..NB_BITS {
                bits.push(r_mac[startidx + j]);
            }
            aux_bits.push(bits);
        }

        let aux_r_m_mac = self.fcom.f_input_batch(channel, rng, num)?;

        for i in 0..num {
            edabits_vec_mac.push(EdabitsVerifier {
                bits: aux_bits[i].clone(),
                value: aux_r_m_mac[i],
            });
        }
        Ok(edabits_vec_mac)
    }

    fn random_dabits<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        num: usize, // in the paper: NB
    ) -> Result<Vec<DabitVerifier<FE>>, Error> {
        let mut dabit_vec_mac = Vec::with_capacity(num);
        for _ in 0..num {
            let b_mac = self.fcom_f2.f_random(channel, rng)?;
            let b_m_mac = self.fcom.f_input(channel, rng)?;
            dabit_vec_mac.push(DabitVerifier {
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
        dabits_mac: &Vec<DabitVerifier<FE>>,
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

        // step 1)
        let mut c_m_mac: Vec<Vec<FE>> = Vec::with_capacity(s);
        for _ in 0..s {
            let b_m_mac = self.fcom.f_input_batch(channel, rng, gamma)?;
            c_m_mac.push(b_m_mac);
        }

        let c1_mac = self.fcom_f2.f_input_batch(channel, rng, s)?;

        // step 2)
        let mut triples = Vec::with_capacity(gamma * s);
        let mut andl_mac_batch = Vec::with_capacity(gamma * s);
        let mut one_minus_ci_mac_batch = Vec::with_capacity(gamma * s);
        for k in 0..s {
            for i in 0..gamma {
                let andl_mac = c_m_mac[k][i];
                let minus_ci_mac : FE = // -ci
                    self.fcom.f_affine_mult_cst(-FE::PrimeField::ONE, andl_mac);
                let one_minus_ci_mac = // 1 - ci
                    self.fcom.f_affine_add_cst(FE::PrimeField::ONE, minus_ci_mac);
                andl_mac_batch.push(andl_mac);
                one_minus_ci_mac_batch.push(one_minus_ci_mac);
            }
        }

        let and_res_mac_batch = self.fcom.f_input_batch(channel, rng, gamma * s)?;
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
            let mut r_mac = c1_mac[k];
            for i in 0..n {
                // TODO: do not need to do it when e[i] is ZERO
                let tmp_mac = self.fcom_f2.f_affine_mult_cst(e[k][i], dabits_mac[i].bit);
                r_mac += tmp_mac;
            }
            r_mac_batch.push(r_mac);
        }

        // step 5)
        let r_batch = self.fcom_f2.f_open_batch(channel, &r_mac_batch)?;

        // step 6)
        let mut r_prime_batch = Vec::with_capacity(s);
        for k in 0..s {
            // NOTE: for performance maybe step 4 and 6 should be combined in one loop
            let mut r_prime_mac = FE::ZERO;
            for i in 0..n {
                // TODO: do not need to do it when e[i] is ZERO
                let b = bit_to_fe(e[k][i]);
                let tmp_mac = self.fcom.f_affine_mult_cst(b, dabits_mac[i].value);
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
                let tmp_mac = self.fcom.f_affine_mult_cst(twos, c_m_mac[k][i]);
                tau_mac += tmp_mac;
                twos += twos;
            }
            tau_mac_batch.push(tau_mac);
        }
        let tau_batch = self.fcom.f_open_batch(channel, &tau_mac_batch)?;

        // step 8)
        for k in 0..s {
            let b: bool;
            match (r_batch[k] == F2::ONE, tau_batch[k].modulus2()) {
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
        self.fcom
            .quicksilver_check_multiply(channel, rng, &triples)?;

        if res {
            Ok(())
        } else {
            Err(Error::Other("fail fdabit verifier".to_string()))
        }
    }

    /// conversion checking
    pub fn conv<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        edabits_vector_mac: &[EdabitsVerifier<FE>],
    ) -> Result<(), Error> {
        let mut b = true;

        let n = edabits_vector_mac.len();
        let nb_random_edabits = n * B + C;
        let nb_random_dabits = n * B;

        // step 1)a)
        let r_mac = self.random_edabits(channel, rng, nb_random_edabits)?;

        // step 1)b)
        let dabits_mac = self.random_dabits(channel, rng, nb_random_dabits)?;

        // step 1)c): TODO: random multiplication triples

        // step 2)
        self.fdabit(channel, rng, &dabits_mac)?;

        // step 3): TODO: generate pi_2 and pi_3
        let seed1 = rng.gen::<Block>();
        channel.write_block(&seed1)?;
        channel.flush()?;

        // step 4): TODO: shuffle dabits and triples
        let r_mac = generate_permutation(seed1, r_mac);

        // step 5)a):
        let base = n * B;
        for i in 0..C {
            let idx = base + i;
            let a_mac = &r_mac[idx];
            let a_vec = self.fcom_f2.f_open_batch(channel, &a_mac.bits)?;
            let a_m = self.fcom.f_open(channel, a_mac.value)?;
            if convert_f2_to_field::<FE>(&a_vec) != a_m {
                return Err(Error::Other("Wrong open random edabit".to_string()));
            }
        }
        // step 5) b): TODO: open triples

        // step 6)
        for j in 0..B {
            let idx_base = j * n;

            // step 6)b) batched and moved up
            let e_batch = self.bit_add_carry(
                channel,
                rng,
                edabits_vector_mac,
                &r_mac[idx_base..idx_base + n],
            )?;

            // step 6)c) batched and moved up
            let mut e_carry_mac_batch = Vec::with_capacity(n);
            for (_, e_carry) in e_batch.iter() {
                e_carry_mac_batch.push(e_carry.clone());
            }
            let e_m_mac_batch = self.convert_bit_2_field(
                channel,
                rng,
                &dabits_mac[idx_base..idx_base + n],
                e_carry_mac_batch,
            )?;

            // 6)a)
            // 6)d)
            let mut e1_mac_batch = Vec::with_capacity(n);
            let mut ei_mac_batch = Vec::with_capacity(n * NB_BITS);
            for i in 0..n {
                let edabits_mac = &edabits_vector_mac[i];
                let c_m_mac = edabits_mac.value;

                //pick the random edabit
                let idx_r = idx_base + i;

                // 6)a)
                let r_m_mac = r_mac[idx_r].value;
                let c_plus_r_mac = c_m_mac + r_m_mac;

                // 6)c) done earlier
                let e_m_mac = e_m_mac_batch[i];

                // 6)d)
                let e1_mac = c_plus_r_mac
                    - e_m_mac.multiply_by_prime_subfield(power_two::<FE::PrimeField>(NB_BITS));
                e1_mac_batch.push(e1_mac);

                // 6)e)
                ei_mac_batch.extend(&e_batch[i].0);
            }
            // 6)e)
            let ei_batch = self.fcom_f2.f_open_batch(channel, &ei_mac_batch)?;

            let mut e_prime_minus_sum_batch = Vec::with_capacity(n);
            for i in 0..n {
                let sum = convert_f2_to_field::<FE>(&ei_batch[i * NB_BITS..(i + 1) * NB_BITS]);
                e_prime_minus_sum_batch
                    .push(e1_mac_batch[i] + self.fcom.get_delta().multiply_by_prime_subfield(sum));
            }
            b = self
                .fcom
                .f_check_zero_batch(channel, e_prime_minus_sum_batch)?;
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
        bit_to_fe, DabitProver, DabitVerifier, EdabitsProver, EdabitsVerifier, ReceiverConv,
        SenderConv,
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
                    .convert_bit_2_field(
                        &mut channel,
                        &mut rng,
                        &vec![DabitProver {
                            bit: (rb, rb_mac),
                            value: (rm, rm_mac),
                        }],
                        vec![(x_f2, x_f2_mac)],
                    )
                    .unwrap()[0];

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
                .convert_bit_2_field(
                    &mut channel,
                    &mut rng,
                    &vec![DabitVerifier {
                        bit: rb_mac,
                        value: r_m_mac,
                    }],
                    vec![x_f2_mac],
                )
                .unwrap()[0];

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

            let mut vx: Vec<(F2, Gf40)> = Vec::new();
            for i in 0..6 {
                vx.push((x[i], x_mac[i]));
            }

            let mut vy = Vec::new();
            for i in 0..6 {
                vy.push((y[i], y_mac[i]));
            }
            let default_fe = (FE::PrimeField::ZERO, FE::ZERO);
            let (res, c) = fconv
                .bit_add_carry(
                    &mut channel,
                    &mut rng,
                    vec![EdabitsProver {
                        bits: vx,
                        value: default_fe,
                    }]
                    .as_slice(),
                    vec![EdabitsProver {
                        bits: vy,
                        value: default_fe,
                    }]
                    .as_slice(),
                )
                .unwrap()[0]
                .clone();

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
        let default_fe = FE::ZERO;
        let (res_mac, c_mac) = fconv
            .bit_add_carry(
                &mut channel,
                &mut rng,
                vec![EdabitsVerifier {
                    bits: x_mac,
                    value: default_fe,
                }]
                .as_slice(),
                vec![EdabitsVerifier {
                    bits: y_mac,
                    value: default_fe,
                }]
                .as_slice(),
            )
            .unwrap()[0]
            .clone();

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

            let dabits = fconv.random_dabits(&mut channel, &mut rng, count).unwrap();
            let _ = fconv.fdabit(&mut channel, &mut rng, &dabits).unwrap();
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

            for n in 1..nb_edabits {
                let edabits = fconv.random_edabits(&mut channel, &mut rng, n).unwrap();

                let _ = fconv.conv(&mut channel, &mut rng, &edabits).unwrap();
            }
            ()
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut fconv = ReceiverConv::<FE>::init(&mut channel, &mut rng).unwrap();

        let mut res = Vec::new();
        for n in 1..nb_edabits {
            let edabits = fconv.random_edabits(&mut channel, &mut rng, n).unwrap();

            let r = fconv.conv(&mut channel, &mut rng, &edabits).unwrap();
            res.push(r);
        }

        let _resprover = handle.join().unwrap();
        ()
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
