// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2021 Galois, Inc.
// See LICENSE for licensing information.

//! This is the implementation of field conversion

use crate::errors::Error;
use rand::{CryptoRng, Rng, SeedableRng};
use scuttlebutt::{
    field::{FiniteField, Gf40, PrimeFiniteField, F2},
    AbstractChannel, AesRng, Block, SyncChannel,
};
use std::io::{BufReader, BufWriter};
use std::net::TcpStream;

use super::homcom::{FComReceiver, FComSender, MacProver, MacVerifier};

/// EdabitsProver struct
#[derive(Clone)]
pub struct EdabitsProver<FE: FiniteField> {
    bits: Vec<MacProver<Gf40>>,
    value: MacProver<FE>,
}

fn copy_edabits_prover<FE: FiniteField>(edabits: &EdabitsProver<FE>) -> EdabitsProver<FE> {
    let num_bits = edabits.bits.len();
    let mut bits_par = Vec::with_capacity(num_bits);
    for j in 0..num_bits {
        bits_par.push(edabits.bits[j].clone());
    }
    return EdabitsProver {
        bits: bits_par,
        value: edabits.value.clone(),
    };
}

/// EdabitsVerifier struct
#[derive(Clone)]
pub struct EdabitsVerifier<FE: FiniteField> {
    bits: Vec<MacVerifier<Gf40>>,
    value: MacVerifier<FE>,
}

fn copy_edabits_verifier<FE: FiniteField>(edabits: &EdabitsVerifier<FE>) -> EdabitsVerifier<FE> {
    let num_bits = edabits.bits.len();
    let mut bits_par = Vec::with_capacity(num_bits);
    for j in 0..num_bits {
        bits_par.push(edabits.bits[j].clone());
    }
    return EdabitsVerifier {
        bits: bits_par,
        value: edabits.value.clone(),
    };
}

/// DabitProver struct
#[derive(Clone)]
struct DabitProver<FE: FiniteField> {
    bit: MacProver<Gf40>,
    value: MacProver<FE>,
}

/// DabitVerifier struct
#[derive(Clone)]
struct DabitVerifier<FE: FiniteField> {
    bit: MacVerifier<Gf40>,
    value: MacVerifier<FE>,
}

const FDABIT_SECURITY_PARAMETER: usize = 38;

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
        res += res;
    }

    res
}

// Permutation pseudorandomly generated following Fisher-Yates method
// `https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle`
fn generate_permutation<T: Clone, RNG: CryptoRng + Rng>(rng: &mut RNG, v: Vec<T>) -> Vec<T> {
    let size = v.len();
    let mut permute = Vec::with_capacity(size);

    for i in 0..size {
        permute.push(v[i].clone());
    }

    let mut i = size - 1;
    while i > 0 {
        let idx = Rng::gen_range(rng, 0, i);
        let tmp: T = permute[idx].clone();
        permute[idx] = permute[i].clone();
        permute[i] = tmp;
        i -= 1;
    }
    permute
}

/// Conversion sender
pub struct SenderConv<FE: FiniteField> {
    fcom_f2: FComSender<Gf40>,
    fcom: FComSender<FE>,
}

impl<FE: FiniteField + PrimeFiniteField> SenderConv<FE> {
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

    fn duplicate<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        Ok(Self {
            fcom_f2: self.fcom_f2.duplicate(channel, rng)?,
            fcom: self.fcom.duplicate(channel, rng)?,
        })
    }

    fn convert_bit_2_field<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        _rng: &mut RNG,
        dabit_batch: &[DabitProver<FE>],
        input_batch: Vec<MacProver<Gf40>>,
    ) -> Result<Vec<MacProver<FE>>, Error> {
        let n = dabit_batch.len();
        debug_assert!(n == input_batch.len());

        let mut r_plus_x = Vec::with_capacity(n);
        for i in 0..n {
            let MacProver(r, r_mac) = dabit_batch[i].bit;
            let MacProver(x, x_mac) = input_batch[i];
            r_plus_x.push(MacProver(r + x, r_mac + x_mac));
        }
        self.fcom_f2.open(channel, &r_plus_x)?;

        let mut x_m_batch = Vec::with_capacity(n);
        for i in 0..n {
            let MacProver(r, _r_mac) = dabit_batch[i].bit;
            let MacProver(_r_m, r_m_mac) = dabit_batch[i].value;
            let MacProver(x, _x_mac) = input_batch[i];

            let x_m = bit_to_fe::<FE::PrimeField>(x);
            let c = r + x;
            let x_m_mac = r_m_mac
                + if c == F2::ONE {
                    -(r_m_mac + r_m_mac)
                } else {
                    FE::ZERO
                };
            x_m_batch.push(MacProver(x_m, x_m_mac));
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
        mult_input_mac: &[MacProver<Gf40>],
    ) -> Result<Vec<(Vec<MacProver<Gf40>>, MacProver<Gf40>)>, Error> {
        let num = x_batch.len();
        if num != y_batch.len() {
            return Err(Error::Other(
                "incompatible input vectors in bit_add_carry".to_string(),
            ));
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
                let ci = ci_batch[n];
                let ci_mac = ci_mac_batch[n];

                let x = &x_batch[n].bits;
                let y = &y_batch[n].bits;

                debug_assert!(x.len() == m && y.len() == m);

                let MacProver(xi, xi_mac) = x[i];
                let MacProver(yi, yi_mac) = y[i];

                let and1 = xi + ci;
                let and1_mac = xi_mac + ci_mac;

                let and2 = yi + ci;
                let and2_mac = yi_mac + ci_mac;

                let and_res = and1 * and2;

                let c = ci + and_res;
                // let c_mac = ci_mac + and_res_mac; // is done in the next step
                ci_batch[n] = c;

                let z = and1 + yi; // xi + yi + ci ;
                let z_mac = and1_mac + yi_mac; // xi_mac + yi_mac + ci_mac;
                z_batch[n].push(MacProver(z, z_mac));

                and_res_batch.push(and_res);
                aux_batch.push((and1, and1_mac, and2, and2_mac));
            }
            and_res_mac_batch.clear();
            self.fcom_f2.input_low_level(
                channel,
                &and_res_batch,
                &mult_input_mac[i * num..(i + 1) * num],
                &mut and_res_mac_batch,
            )?;

            for n in 0..num {
                let (and1, and1_mac, and2, and2_mac) = aux_batch[n];
                let and_res = and_res_batch[n];
                let and_res_mac = and_res_mac_batch[n];
                triples.push((
                    MacProver(and1, and1_mac),
                    MacProver(and2, and2_mac),
                    MacProver(and_res, and_res_mac),
                ));

                let ci_mac = ci_mac_batch[n];
                let c_mac = ci_mac + and_res_mac;

                ci_mac_batch[n] = c_mac;
            }
        }

        // check all the multiplications in one batch
        self.fcom_f2
            .quicksilver_check_multiply(channel, rng, &triples)?;

        // reconstruct the solution
        let mut res = Vec::with_capacity(num);
        for n in 0..num {
            res.push((z_batch[n].clone(), MacProver(ci_batch[n], ci_mac_batch[n])));
        }

        Ok(res)
    }

    /// generate random edabits
    pub fn random_edabits<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        nb_bits: usize,
        num: usize, // in the paper: NB + C
    ) -> Result<Vec<EdabitsProver<FE>>, Error> {
        let mut edabits_vec = Vec::with_capacity(num);

        let mut aux_bits = Vec::with_capacity(num);
        let mut aux_r_m = Vec::with_capacity(num);
        for _ in 0..num {
            let mut bits = Vec::with_capacity(nb_bits);
            for _ in 0..nb_bits {
                bits.push(self.fcom_f2.random(channel, rng)?);
            }
            let r_m: FE::PrimeField =
                convert_f2_to_field::<FE>(bits.iter().map(|x| x.0).collect::<Vec<F2>>().as_slice());
            aux_bits.push(bits);
            aux_r_m.push(r_m);
        }

        let aux_r_m_mac: Vec<FE> = self.fcom.input(channel, rng, &aux_r_m)?;

        for i in 0..num {
            edabits_vec.push(EdabitsProver {
                bits: aux_bits[i].clone(),
                value: MacProver(aux_r_m[i], aux_r_m_mac[i]),
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
        let mut b_batch = Vec::with_capacity(num);
        let mut b_m_batch = Vec::with_capacity(num);

        for _ in 0..num {
            let b = self.fcom_f2.random(channel, rng)?;
            b_batch.push(b);
            let b_m = bit_to_fe(b.0);
            b_m_batch.push(b_m);
        }

        let b_m_mac_batch = self.fcom.input(channel, rng, &b_m_batch)?;

        for i in 0..num {
            dabit_vec.push(DabitProver {
                bit: b_batch[i],
                value: MacProver(b_m_batch[i], b_m_mac_batch[i]),
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
            let b_m_mac = self.fcom.input(channel, rng, c_m[k].as_slice())?;
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
                let MacProver(minus_ci, minus_ci_mac) = // -ci
                    self.fcom.affine_mult_cst(-FE::PrimeField::ONE, MacProver(andl, andl_mac));
                let MacProver(one_minus_ci, one_minus_ci_mac) = // 1 - ci
                    self.fcom.affine_add_cst(FE::PrimeField::ONE, MacProver(minus_ci, minus_ci_mac));
                let and_res = andl * one_minus_ci;
                andl_batch.push(andl);
                andl_mac_batch.push(andl_mac);
                one_minus_ci_batch.push(one_minus_ci);
                one_minus_ci_mac_batch.push(one_minus_ci_mac);
                and_res_batch.push(and_res);
            }
        }
        let and_res_mac_batch = self.fcom.input(channel, rng, &and_res_batch)?;

        for j in 0..s * gamma {
            triples.push((
                MacProver(andl_batch[j], andl_mac_batch[j]),
                MacProver(one_minus_ci_batch[j], one_minus_ci_mac_batch[j]),
                MacProver(and_res_batch[j], and_res_mac_batch[j]),
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
                let MacProver(tmp, tmp_mac) = self.fcom_f2.affine_mult_cst(e[k][i], dabits[i].bit);
                debug_assert!(
                    ((e[k][i] == F2::ONE) & (tmp == dabits[i].bit.0)) | (tmp == F2::ZERO)
                );
                r += tmp;
                r_mac += tmp_mac;
            }
            r_batch.push(MacProver(r, r_mac));
        }

        // step 5) TODO: move this to the end
        let _ = self.fcom_f2.open(channel, &r_batch)?;

        // step 6)
        let mut r_prime_batch = Vec::with_capacity(s);
        for k in 0..s {
            // step 6)
            // NOTE: for performance maybe step 4 and 6 should be combined in one loop
            let (mut r_prime, mut r_prime_mac) = (FE::PrimeField::ZERO, FE::ZERO);
            for i in 0..n {
                // TODO: do not need to do it when e[i] is ZERO
                let b = bit_to_fe(e[k][i]);
                let MacProver(tmp, tmp_mac) = self.fcom.affine_mult_cst(b, dabits[i].value);
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
                let MacProver(tmp, tmp_mac) = self
                    .fcom
                    .affine_mult_cst(twos, MacProver(c_m[k][i], c_m_mac[k][i]));
                if i == 0 {
                    debug_assert!(c_m[k][i] == tmp);
                }
                tau += tmp;
                tau_mac += tmp_mac;
                twos += twos;
            }
            tau_batch.push(MacProver(tau, tau_mac));
        }

        let _ = self.fcom.open(channel, &tau_batch)?;

        // step 8)
        for k in 0..s {
            // step 8)
            // NOTE: This is not needed for the prover,
            let b: bool;
            match (r_batch[k].0 == F2::ONE, tau_batch[k].0.mod2() == FE::ONE) {
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

    fn conv_loop<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        edabits_vector: &[EdabitsProver<FE>],
        r: &[EdabitsProver<FE>],
        mult_input_mac: &[MacProver<Gf40>],
        dabits: &[DabitProver<FE>],
    ) -> Result<(), Error> {
        let n = edabits_vector.len();
        let nb_bits = edabits_vector[0].bits.len();
        let power_two_nb_bits = power_two::<FE::PrimeField>(nb_bits);
        // step 6)b) batched and moved up
        let e_batch = self.bit_add_carry(channel, rng, &edabits_vector, &r, &mult_input_mac)?;

        // step 6)c) batched and moved up
        let mut e_carry_batch = Vec::with_capacity(n);
        for (_, e_carry) in e_batch.iter() {
            e_carry_batch.push(e_carry.clone());
        }
        let e_m_batch = self.convert_bit_2_field(channel, rng, &dabits, e_carry_batch)?;

        // 6)a)
        let mut e_prime_mac_batch = Vec::with_capacity(n);
        // 6)d)
        let mut ei_batch = Vec::with_capacity(n * nb_bits);
        for i in 0..n {
            // 6)a)
            let MacProver(_c_m, c_m_mac) = edabits_vector[i].value;
            let MacProver(_r_m, r_m_mac) = r[i].value;
            let c_plus_r_mac = c_m_mac + r_m_mac;

            // 6)c) done earlier
            let MacProver(_, e_m_mac) = e_m_batch[i];

            // 6)d)
            let e_prime_mac = c_plus_r_mac - e_m_mac.multiply_by_prime_subfield(power_two_nb_bits);
            e_prime_mac_batch.push(e_prime_mac);
            ei_batch.extend(&e_batch[i].0);
        }

        // 6)e)
        let _ei = self.fcom_f2.open(channel, &ei_batch)?;

        // Remark this is not necessary for the prover, bc cst addition dont show up in mac
        // let s = convert_f2_to_field(ei);
        return self.fcom.check_zero(channel, e_prime_mac_batch);
    }

    /// conversion checking
    pub fn conv<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        num_bucket: usize,
        num_cut: usize,
        edabits_vector: &[EdabitsProver<FE>],
        bucket_channels: Option<Vec<SyncChannel<BufReader<TcpStream>, BufWriter<TcpStream>>>>,
    ) -> Result<(), Error> {
        let n = edabits_vector.len();
        let nb_bits = edabits_vector[0].bits.len();

        let nb_random_edabits = n * num_bucket + num_cut;
        let nb_random_dabits = n * num_bucket;

        // step 1)a): commit random edabit
        let r = self.random_edabits(channel, rng, nb_bits, nb_random_edabits)?;

        // step 1)b)
        let dabits = self.random_dabits(channel, rng, nb_random_dabits)?;

        // step 1)c): Precomputing the multiplication triples is
        // replaced by generating svoles to later input the carries
        let mut mult_input_mac = Vec::with_capacity(num_bucket * n * nb_bits);
        for _ in 0..(num_bucket * n * nb_bits) {
            mult_input_mac.push(self.fcom_f2.random(channel, rng)?);
        }

        // step 2)

        self.fdabit(channel, rng, &dabits)?;

        // step 3)
        let seed = channel.read_block()?;
        let mut shuffle_rng = AesRng::from_seed(seed);

        // step 4): shuffle to edabits and dabits
        let r = generate_permutation(&mut shuffle_rng, r);
        let dabits = generate_permutation(&mut shuffle_rng, dabits);

        // step 5)a):
        let base = n * num_bucket;
        for i in 0..num_cut {
            let idx = base + i;
            let a = &r[idx];
            self.fcom_f2.open(channel, &a.bits)?;
            self.fcom.open(channel, &vec![a.value])?;
        }

        // step 5) b): Unnecessary

        // step 6)

        if bucket_channels.is_none() {
            for j in 0..num_bucket {
                // base index for the window of `idx_base..idx_base + n` values
                let idx_base = j * n;

                self.conv_loop(
                    channel,
                    rng,
                    &edabits_vector,
                    &r[idx_base..idx_base + n],
                    &mult_input_mac[idx_base * nb_bits..idx_base * nb_bits + n * nb_bits],
                    &dabits[idx_base..idx_base + n],
                )?;
            }
        } else {
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

                let mut mult_input_mac_par = Vec::with_capacity(n);
                for elm in
                    mult_input_mac[idx_base * nb_bits..idx_base * nb_bits + n * nb_bits].iter()
                {
                    mult_input_mac_par.push(elm.clone());
                }

                let mut dabits_par = Vec::with_capacity(n);
                for elm in dabits[idx_base..idx_base + n].iter() {
                    dabits_par.push(elm.clone());
                }

                let mut new_sender = self.duplicate(channel, rng)?;
                let handle = std::thread::spawn(move || {
                    new_sender.conv_loop(
                        &mut bucket_channel,
                        &mut AesRng::new(),
                        &edabits_vector_par,
                        &r_par,
                        &mult_input_mac_par,
                        &dabits_par,
                    )
                });
                handles.push(handle);

                j += 1;
            }

            for handle in handles {
                handle.join().unwrap();
            }
        }

        Ok(())
    }
}

/// Conversion receiver
pub struct ReceiverConv<FE: FiniteField> {
    fcom_f2: FComReceiver<Gf40>,
    fcom: FComReceiver<FE>,
}

impl<FE: FiniteField + PrimeFiniteField> ReceiverConv<FE> {
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

    fn duplicate<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        Ok(Self {
            fcom_f2: self.fcom_f2.duplicate(channel, rng)?,
            fcom: self.fcom.duplicate(channel, rng)?,
        })
    }

    fn convert_bit_2_field<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        _rng: &mut RNG,
        r_batch: &[DabitVerifier<FE>],
        x_mac_batch: Vec<MacVerifier<Gf40>>,
    ) -> Result<Vec<MacVerifier<FE>>, Error> {
        let n = r_batch.len();
        debug_assert!(n == x_mac_batch.len());

        let mut r_mac_plus_x_mac = Vec::with_capacity(n);

        for i in 0..n {
            r_mac_plus_x_mac.push(MacVerifier(r_batch[i].bit.0 + x_mac_batch[i].0));
        }

        let c_batch = self.fcom_f2.open(channel, &r_mac_plus_x_mac)?;

        let mut x_m_mac_batch = Vec::with_capacity(n);

        for i in 0..n {
            let MacVerifier(r_m_mac) = r_batch[i].value;
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
            x_m_mac_batch.push(MacVerifier(x_m_mac));
        }
        Ok(x_m_mac_batch)
    }

    fn bit_add_carry<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        x_batch: &[EdabitsVerifier<FE>],
        y_batch: &[EdabitsVerifier<FE>],
        mult_input_mac: &[MacVerifier<Gf40>],
    ) -> Result<Vec<(Vec<MacVerifier<Gf40>>, MacVerifier<Gf40>)>, Error> {
        let num = x_batch.len();
        if num != y_batch.len() {
            return Err(Error::Other(
                "incompatible input vectors in bit_add_carry".to_string(),
            ));
        }

        let m = x_batch[0].bits.len();

        // input c0
        let mut ci_mac_batch = self.fcom_f2.input(channel, rng, num)?;

        // loop on the m bits over the batch of n addition
        let mut triples = Vec::with_capacity(num * m);
        let mut aux_batch = Vec::with_capacity(num);
        let mut z_batch = vec![Vec::with_capacity(m); num];
        let mut and_res_mac_batch = Vec::with_capacity(num);
        for i in 0..m {
            aux_batch.clear();
            for n in 0..num {
                let MacVerifier(ci_mac) = ci_mac_batch[n];

                let x = &x_batch[n].bits;
                let y = &y_batch[n].bits;

                debug_assert!(x.len() == m && y.len() == m);

                let MacVerifier(xi_mac) = x[i];
                let MacVerifier(yi_mac) = y[i];

                let and1_mac = xi_mac + ci_mac;
                let and2_mac = yi_mac + ci_mac;

                let z_mac = and1_mac + yi_mac; //xi_mac + yi_mac + ci_mac;
                z_batch[n].push(MacVerifier(z_mac));
                aux_batch.push((and1_mac, and2_mac));
            }
            and_res_mac_batch.clear();
            self.fcom_f2.input_low_level(
                channel,
                num,
                &mult_input_mac[i * num..(i + 1) * num],
                &mut and_res_mac_batch,
            )?;

            for n in 0..num {
                let MacVerifier(ci_mac) = ci_mac_batch[n];
                let (and1_mac, and2_mac) = aux_batch[n];
                let MacVerifier(and_res_mac) = and_res_mac_batch[n];
                triples.push((
                    MacVerifier(and1_mac),
                    MacVerifier(and2_mac),
                    MacVerifier(and_res_mac),
                ));

                let c_mac = ci_mac + and_res_mac;
                ci_mac_batch[n] = MacVerifier(c_mac);
            }
        }
        // check all the multiplications in one batch
        self.fcom_f2
            .quicksilver_check_multiply(channel, rng, &triples)?;

        // reconstruct the solution
        let mut res = Vec::with_capacity(num);
        for n in 0..num {
            res.push((z_batch[n].clone(), ci_mac_batch[n]));
        }

        Ok(res)
    }

    /// generate random edabits
    pub fn random_edabits<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        nb_bits: usize,
        num: usize, // in the paper: NB + C
    ) -> Result<Vec<EdabitsVerifier<FE>>, Error> {
        let mut edabits_vec_mac = Vec::with_capacity(num);
        let mut aux_bits = Vec::with_capacity(num);
        for _ in 0..num {
            let mut bits = Vec::with_capacity(nb_bits);
            for _ in 0..nb_bits {
                bits.push(self.fcom_f2.random(channel, rng)?);
            }
            aux_bits.push(bits);
        }

        let aux_r_m_mac = self.fcom.input(channel, rng, num)?;

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
        let mut b_mac_batch = Vec::with_capacity(num);
        for _ in 0..num {
            b_mac_batch.push(self.fcom_f2.random(channel, rng)?);
        }
        let b_m_mac_batch = self.fcom.input(channel, rng, num)?;
        for i in 0..num {
            dabit_vec_mac.push(DabitVerifier {
                bit: b_mac_batch[i],
                value: b_m_mac_batch[i],
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
        let mut c_m_mac: Vec<Vec<MacVerifier<FE>>> = Vec::with_capacity(s);
        for _ in 0..s {
            let b_m_mac = self.fcom.input(channel, rng, gamma)?;
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
                    self.fcom.affine_mult_cst(-FE::PrimeField::ONE, andl_mac);
                let one_minus_ci_mac = // 1 - ci
                    self.fcom.affine_add_cst(FE::PrimeField::ONE, minus_ci_mac);
                andl_mac_batch.push(andl_mac);
                one_minus_ci_mac_batch.push(one_minus_ci_mac);
            }
        }

        let and_res_mac_batch = self.fcom.input(channel, rng, gamma * s)?;
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
            let mut r_mac = c1_mac[k].0;
            for i in 0..n {
                // TODO: do not need to do it when e[i] is ZERO
                let MacVerifier(tmp_mac) = self.fcom_f2.affine_mult_cst(e[k][i], dabits_mac[i].bit);
                r_mac += tmp_mac;
            }
            r_mac_batch.push(MacVerifier(r_mac));
        }

        // step 5)
        let r_batch = self.fcom_f2.open(channel, &r_mac_batch)?;

        // step 6)
        let mut r_prime_batch = Vec::with_capacity(s);
        for k in 0..s {
            // NOTE: for performance maybe step 4 and 6 should be combined in one loop
            let mut r_prime_mac = FE::ZERO;
            for i in 0..n {
                // TODO: do not need to do it when e[i] is ZERO
                let b = bit_to_fe(e[k][i]);
                let MacVerifier(tmp_mac) = self.fcom.affine_mult_cst(b, dabits_mac[i].value);
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
                let MacVerifier(tmp_mac) = self.fcom.affine_mult_cst(twos, c_m_mac[k][i]);
                tau_mac += tmp_mac;
                twos += twos;
            }
            tau_mac_batch.push(MacVerifier(tau_mac));
        }
        let tau_batch = self.fcom.open(channel, &tau_mac_batch)?;

        // step 8)
        for k in 0..s {
            let b: bool;
            match (r_batch[k] == F2::ONE, tau_batch[k].mod2() == FE::ONE) {
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

    fn conv_loop<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        edabits_vector_mac: &[EdabitsVerifier<FE>],
        r_mac: &[EdabitsVerifier<FE>],
        mult_input_mac: &[MacVerifier<Gf40>],
        dabits_mac: &[DabitVerifier<FE>],
    ) -> Result<bool, Error> {
        let n = edabits_vector_mac.len();
        let nb_bits = edabits_vector_mac[0].bits.len();
        let power_two_nb_bits = power_two::<FE::PrimeField>(nb_bits);
        println!("ADD<");
        // step 6)b) batched and moved up
        let e_batch =
            self.bit_add_carry(channel, rng, edabits_vector_mac, &r_mac, &mult_input_mac)?;
        println!("ADD>");

        println!("A2B<");
        // step 6)c) batched and moved up
        let mut e_carry_mac_batch = Vec::with_capacity(n);
        for (_, e_carry) in e_batch.iter() {
            e_carry_mac_batch.push(e_carry.clone());
        }

        let e_m_mac_batch =
            self.convert_bit_2_field(channel, rng, &dabits_mac, e_carry_mac_batch)?;
        println!("A2B>");

        // 6)a)
        let mut e_prime_mac_batch = Vec::with_capacity(n);
        // 6)d)
        let mut ei_mac_batch = Vec::with_capacity(n * nb_bits);
        for i in 0..n {
            // 6)a)
            let MacVerifier(c_m_mac) = edabits_vector_mac[i].value;
            let MacVerifier(r_m_mac) = r_mac[i].value;
            let c_plus_r_mac = c_m_mac + r_m_mac;

            // 6)c) done earlier
            let MacVerifier(e_m_mac) = e_m_mac_batch[i];

            // 6)d)
            let e_prime_mac = c_plus_r_mac - e_m_mac.multiply_by_prime_subfield(power_two_nb_bits);
            e_prime_mac_batch.push(e_prime_mac);

            // 6)e)
            ei_mac_batch.extend(&e_batch[i].0);
        }
        // 6)e)
        println!("OPEN<");
        let ei_batch = self.fcom_f2.open(channel, &ei_mac_batch)?;
        println!("OPEN>");

        let mut e_prime_minus_sum_batch = Vec::with_capacity(n);
        for i in 0..n {
            let sum = convert_f2_to_field::<FE>(&ei_batch[i * nb_bits..(i + 1) * nb_bits]);
            e_prime_minus_sum_batch.push(MacVerifier(
                e_prime_mac_batch[i] + self.fcom.get_delta().multiply_by_prime_subfield(sum),
            ));
        }
        println!("CHECK_Z<");
        let b = self
            .fcom
            .check_zero(channel, rng, e_prime_minus_sum_batch)?;
        println!("CHECK_Z>");

        return Ok(b);
    }

    /// conversion checking
    pub fn conv<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        num_bucket: usize,
        num_cut: usize,
        edabits_vector_mac: &[EdabitsVerifier<FE>],
        bucket_channels: Option<Vec<SyncChannel<BufReader<TcpStream>, BufWriter<TcpStream>>>>,
    ) -> Result<(), Error> {
        let n = edabits_vector_mac.len();
        let nb_bits = edabits_vector_mac[0].bits.len();
        let nb_random_edabits = n * num_bucket + num_cut;
        let nb_random_dabits = n * num_bucket;

        // step 1)a)
        println!("RANDOM EDA-DA-BITS<");
        let r_mac = self.random_edabits(channel, rng, nb_bits, nb_random_edabits)?;

        // step 1)b)
        let dabits_mac = self.random_dabits(channel, rng, nb_random_dabits)?;
        println!("RANDOM EDA-DABITS>");

        // step 1)c): Precomputing the multiplication triples is
        // replaced by generating svoles to later input the carries
        let mut mult_input_mac = Vec::with_capacity(num_bucket * n * nb_bits);
        for _ in 0..(num_bucket * n * nb_bits) {
            mult_input_mac.push(self.fcom_f2.random(channel, rng)?);
        }

        // step 2)
        println!("CHECK DA<");
        self.fdabit(channel, rng, &dabits_mac)?;
        println!("CHECK DA>");

        // step 3): TODO: generate pi_2 and pi_3
        let seed = rng.gen::<Block>();
        channel.write_block(&seed)?;
        channel.flush()?;
        let mut shuffle_rng = AesRng::from_seed(seed);

        // step 4): shuffle the edabits and dabits
        let r_mac = generate_permutation(&mut shuffle_rng, r_mac);
        let dabits_mac = generate_permutation(&mut shuffle_rng, dabits_mac);

        // step 5)a):
        println!("Open<");
        let base = n * num_bucket;
        for i in 0..num_cut {
            let idx = base + i;
            let a_mac = &r_mac[idx];
            let a_vec = self.fcom_f2.open(channel, &a_mac.bits)?;
            let a_m = self.fcom.open(channel, &vec![a_mac.value])?[0];
            if convert_f2_to_field::<FE>(&a_vec) != a_m {
                return Err(Error::Other("Wrong open random edabit".to_string()));
            }
        }
        println!("Open>");
        // step 5) b): unnecessary

        // step 6)
        let mut b = true;

        if bucket_channels.is_none() {
            for j in 0..num_bucket {
                // base index for the window of `idx_base..idx_base + n` values
                let idx_base = j * n;

                b = b
                    && self.conv_loop(
                        channel,
                        rng,
                        &edabits_vector_mac,
                        &r_mac[idx_base..idx_base + n],
                        &mult_input_mac[idx_base * nb_bits..idx_base * nb_bits + n * nb_bits],
                        &dabits_mac[idx_base..idx_base + n],
                    )?;
            }
        } else {
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

                let mut mult_input_mac_par = Vec::with_capacity(n);
                for elm in
                    mult_input_mac[idx_base * nb_bits..idx_base * nb_bits + n * nb_bits].iter()
                {
                    mult_input_mac_par.push(elm.clone());
                }

                let mut dabits_mac_par = Vec::with_capacity(n);
                for elm in dabits_mac[idx_base..idx_base + n].iter() {
                    dabits_mac_par.push(elm.clone());
                }

                let mut new_receiver = self.duplicate(channel, rng)?;
                let handle = std::thread::spawn(move || {
                    new_receiver.conv_loop(
                        &mut bucket_channel,
                        &mut AesRng::new(),
                        &edabits_vector_mac_par,
                        &r_mac_par,
                        &mult_input_mac_par,
                        &dabits_mac_par,
                    )
                });
                handles.push(handle);

                j += 1;
            }

            for handle in handles {
                b = b && handle.join().unwrap().unwrap();
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

    use super::super::homcom::{MacProver, MacVerifier};
    use super::{
        bit_to_fe, DabitProver, DabitVerifier, EdabitsProver, EdabitsVerifier, ReceiverConv,
        SenderConv,
    };
    use scuttlebutt::{
        field::{F61p, FiniteField, PrimeFiniteField, F2},
        AesRng, Channel,
    };
    use std::{
        io::{BufReader, BufWriter},
        os::unix::net::UnixStream,
    };

    const DEFAULT_NUM_BUCKET: usize = 5;
    const DEFAULT_NUM_CUT: usize = 5;
    const NB_BITS: usize = 38;

    fn test_convert_bit_2_field<FE: FiniteField + PrimeFiniteField>() -> () {
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
                let MacProver(rb, rb_mac) = fconv.fcom_f2.random(&mut channel, &mut rng).unwrap();
                let rm = bit_to_fe(rb);
                let rm_mac = fconv.fcom.input(&mut channel, &mut rng, &vec![rm]).unwrap()[0];
                let MacProver(x_f2, x_f2_mac) =
                    fconv.fcom_f2.random(&mut channel, &mut rng).unwrap();

                let MacProver(x_m, x_m_mac) = fconv
                    .convert_bit_2_field(
                        &mut channel,
                        &mut rng,
                        &vec![DabitProver {
                            bit: MacProver(rb, rb_mac),
                            value: MacProver(rm, rm_mac),
                        }],
                        vec![MacProver(x_f2, x_f2_mac)],
                    )
                    .unwrap()[0];

                let _ = fconv
                    .fcom
                    .open(&mut channel, &vec![MacProver(x_m, x_m_mac)])
                    .unwrap();
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
            let rb_mac = fconv.fcom_f2.random(&mut channel, &mut rng).unwrap();
            let r_m_mac = fconv.fcom.input(&mut channel, &mut rng, 1).unwrap()[0];
            let x_f2_mac = fconv.fcom_f2.random(&mut channel, &mut rng).unwrap();

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

            let x_m = fconv.fcom.open(&mut channel, &vec![x_m_mac]).unwrap()[0];
            res.push(x_m);
        }

        let resprover = handle.join().unwrap();

        for i in 0..count {
            assert_eq!(resprover[i].1, res[i]);
        }
    }

    fn test_bit_add_carry<FE: FiniteField + PrimeFiniteField>() -> () {
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

            let x_mac = fconv.fcom_f2.input(&mut channel, &mut rng, &x).unwrap();
            let y_mac = fconv.fcom_f2.input(&mut channel, &mut rng, &y).unwrap();

            let mut vx = Vec::new();
            for i in 0..power {
                vx.push(MacProver(x[i], x_mac[i]));
            }

            let mut vy = Vec::new();
            for i in 0..power {
                vy.push(MacProver(y[i], y_mac[i]));
            }
            let default_fe = MacProver(FE::PrimeField::ZERO, FE::ZERO);
            let mut mult_input_mac = Vec::with_capacity(power);
            for _ in 0..power {
                mult_input_mac.push(fconv.fcom_f2.random(&mut channel, &mut rng).unwrap());
            }
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
                    mult_input_mac.as_slice(),
                )
                .unwrap()[0]
                .clone();

            fconv.fcom_f2.open(&mut channel, &res).unwrap();

            fconv.fcom_f2.open(&mut channel, &vec![c]).unwrap();
            (res, c)
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut fconv = ReceiverConv::<FE>::init(&mut channel, &mut rng).unwrap();

        let x_mac = fconv.fcom_f2.input(&mut channel, &mut rng, power).unwrap();
        let y_mac = fconv.fcom_f2.input(&mut channel, &mut rng, power).unwrap();

        let default_fe = MacVerifier(FE::ZERO);
        let mut mult_input_mac = Vec::with_capacity(power);
        for _ in 0..power {
            mult_input_mac.push(fconv.fcom_f2.random(&mut channel, &mut rng).unwrap());
        }
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
                mult_input_mac.as_slice(),
            )
            .unwrap()[0]
            .clone();

        let res = fconv.fcom_f2.open(&mut channel, &res_mac).unwrap();

        let c = fconv.fcom_f2.open(&mut channel, &vec![c_mac]).unwrap()[0];

        let _resprover = handle.join().unwrap();

        for i in 0..power {
            assert_eq!(expected[i], res[i]);
        }
        assert_eq!(carry, c);
    }

    fn test_fdabit<FE: FiniteField + PrimeFiniteField>() -> () {
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

    fn test_conv<FE: FiniteField + PrimeFiniteField>() -> () {
        let nb_edabits = 50;
        let (sender, receiver) = UnixStream::pair().unwrap();

        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut fconv = SenderConv::<FE>::init(&mut channel, &mut rng).unwrap();

            for n in 1..nb_edabits {
                let edabits = fconv
                    .random_edabits(&mut channel, &mut rng, NB_BITS, n)
                    .unwrap();

                let _ = fconv
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
            ()
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut fconv = ReceiverConv::<FE>::init(&mut channel, &mut rng).unwrap();

        let mut res = Vec::new();
        for n in 1..nb_edabits {
            let edabits = fconv
                .random_edabits(&mut channel, &mut rng, NB_BITS, n)
                .unwrap();

            let r = fconv
                .conv(
                    &mut channel,
                    &mut rng,
                    DEFAULT_NUM_BUCKET,
                    DEFAULT_NUM_CUT,
                    &edabits,
                    None,
                )
                .unwrap();
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
