//! Field switching functionality based on protocol with Edabits.

use crate::homcom::{FCom, MultCheckState, ZeroCheckState};
use crate::mac::Mac;
use crate::svole_trait::{field_name, SvoleT};
use eyre::{bail, ensure, eyre, Result};
use generic_array::typenum::Unsigned;
use log::info;
use rand::{Rng, SeedableRng};
use scuttlebutt::{AbstractChannel, AesRng, Block, SyncChannel};
use std::io::{BufReader, BufWriter};
use std::net::TcpStream;
use subtle::{ConditionallySelectable, ConstantTimeEq};
use swanky_field::{FiniteField, FiniteRing};
use swanky_field_binary::{F40b, F2};
use swanky_party::either::{PartyEither, PartyEitherCopy};
use swanky_party::private::{ProverPrivate, ProverPrivateCopy, VerifierPrivate};
use swanky_party::{IsParty, Party, Prover, WhichParty};

/// Edabits struct
#[derive(Clone)]
pub struct Edabits<P: Party, FE: FiniteField> {
    pub bits: Vec<Mac<P, F2, F40b>>,
    pub value: Mac<P, FE::PrimeField, FE>,
}

/// Dabit struct
#[derive(Clone)]
struct Dabit<P: Party, FE: FiniteField> {
    bit: Mac<P, F2, F40b>,
    value: Mac<P, FE::PrimeField, FE>,
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

fn convert_bits_to_field_mac<P: Party, FE: FiniteField>(
    ev: IsParty<P, Prover>,
    v: &[Mac<P, F2, F40b>],
) -> FE {
    let mut res = FE::ZERO;

    for b in v.iter().rev() {
        res += res; // double
        res += f2_to_fe(b.value().into_inner(ev));
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
fn generate_permutation<T: Clone>(rng: &mut AesRng, v: &mut [T]) {
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

/// The edabits conversion protocol
pub struct Conv<P: Party, FE: Copy, SvoleF2: SvoleT<P, F2, F40b>, SvoleFE: SvoleT<P, FE, FE>> {
    pub fcom_f2: FCom<P, F2, F40b, SvoleF2>,
    fcom_fe: FCom<P, FE, FE, SvoleFE>,
}

/// The Finite field is required to be a prime field because of the fdabit
/// protocol working only for prime finite fields.
impl<
        P: Party,
        FE: FiniteField<PrimeField = FE>,
        SvoleF2: SvoleT<P, F2, F40b>,
        SvoleFE: SvoleT<P, FE, FE>,
    > Conv<P, FE, SvoleF2, SvoleFE>
{
    /// Initialize provided the commitment functionalities.
    pub fn init_with_fcoms(
        fcom_f2: &FCom<P, F2, F40b, SvoleF2>,
        fcom_fe: &FCom<P, FE, FE, SvoleFE>,
    ) -> Result<Self> {
        Ok(Self {
            fcom_f2: fcom_f2.duplicate()?,
            fcom_fe: fcom_fe.duplicate()?,
        })
    }

    fn convert_bit_2_field<C: AbstractChannel + Clone>(
        &mut self,
        channel: &mut C,
        r_batch: &[Dabit<P, FE>],
        x_batch: &[Mac<P, F2, F40b>],
        r_mac_plus_x_mac: &mut VerifierPrivate<P, &mut Vec<Mac<P, F2, F40b>>>,
        c_batch: &mut PartyEither<P, &mut Vec<Mac<P, F2, F40b>>, &mut Vec<F2>>,
        x_m_batch: &mut Vec<Mac<P, FE::PrimeField, FE>>,
    ) -> Result<()> {
        let n = r_batch.len();
        debug_assert_eq!(n, x_batch.len());

        match P::WHICH {
            WhichParty::Prover(ev) => {
                c_batch.as_mut().prover_into(ev).clear();
            }
            WhichParty::Verifier(ev) => {
                r_mac_plus_x_mac.as_mut().into_inner(ev).clear();
            }
        }

        x_m_batch.clear();

        match P::WHICH {
            WhichParty::Prover(ev) => {
                for i in 0..n {
                    c_batch
                        .as_mut()
                        .prover_into(ev)
                        .push(self.fcom_f2.add(r_batch[i].bit, x_batch[i]));
                }
                self.fcom_f2.open(
                    channel,
                    c_batch.as_ref().prover_into(ev),
                    &mut VerifierPrivate::empty(ev),
                )?;
            }
            WhichParty::Verifier(ev) => {
                for i in 0..n {
                    r_mac_plus_x_mac
                        .as_mut()
                        .into_inner(ev)
                        .push(self.fcom_f2.add(r_batch[i].bit, x_batch[i]));
                }
                self.fcom_f2.open(
                    channel,
                    r_mac_plus_x_mac.as_ref().into_inner(ev),
                    &mut VerifierPrivate::new(c_batch.as_mut().verifier_into(ev)),
                )?;
            }
        }

        for (i, r) in r_batch.iter().enumerate() {
            let c = match P::WHICH {
                WhichParty::Prover(ev) => {
                    c_batch.as_ref().prover_into(ev)[i].value().into_inner(ev)
                }
                WhichParty::Verifier(ev) => c_batch.as_ref().verifier_into(ev)[i],
            };

            let c_m = f2_to_fe::<FE::PrimeField>(c);

            let choice = c.ct_eq(&F2::ONE);
            let x = self.fcom_fe.neg(r.value);
            let beq = self.fcom_fe.affine_add_cst(c_m, x);
            let bneq = self.fcom_fe.affine_add_cst(c_m, r.value);
            let x_m = Mac::conditional_select(&bneq, &beq, choice);

            x_m_batch.push(x_m);
        }

        debug_assert_eq!(n, x_m_batch.len());
        Ok(())
    }

    // This function applies the bit_add_carry to a batch of bits,
    // contrary to the one in the paper that applies it on a pair of
    // bits. This allows to the keep the rounds of communication equal
    // to m for any vector of additions.
    fn bit_add_carry<C: AbstractChannel + Clone>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
        x_batch: &[Edabits<P, FE>],
        y_batch: &[Edabits<P, FE>],
    ) -> Result<Vec<(Vec<Mac<P, F2, F40b>>, Mac<P, F2, F40b>)>> {
        let num = x_batch.len();
        ensure!(
            num == y_batch.len(),
            "incompatible input vectors in bit_add_carry"
        );

        let m = x_batch[0].bits.len();

        // input c0
        let mut ci_batch = match P::WHICH {
            WhichParty::Prover(ev) => PartyEither::prover_new(ev, vec![F2::ZERO; num]),
            WhichParty::Verifier(ev) => {
                PartyEither::verifier_new(ev, self.fcom_f2.input_verifier(ev, channel, rng, num)?)
            }
        };
        let mut ci_mac_batch = match P::WHICH {
            WhichParty::Prover(ev) => ProverPrivate::new(self.fcom_f2.input_prover(
                ev,
                channel,
                rng,
                ci_batch.as_ref().prover_into(ev),
            )?),
            WhichParty::Verifier(ev) => ProverPrivate::empty(ev),
        };

        // loop on the m bits over the batch of n addition
        let mut mult_check_state = MultCheckState::<P, F40b>::init(channel, rng)?;
        let mut aux_batch = Vec::with_capacity(num);
        let mut and_res_batch = ProverPrivate::new(Vec::with_capacity(num));
        let mut z_batch = vec![Vec::with_capacity(m); num];
        let mut and_res_mac_batch = match P::WHICH {
            WhichParty::Prover(ev) => PartyEither::prover_new(ev, Vec::with_capacity(num)),
            WhichParty::Verifier(ev) => PartyEither::verifier_new(ev, Vec::with_capacity(num)),
        };
        for i in 0..m {
            if let WhichParty::Prover(ev) = P::WHICH {
                and_res_batch.as_mut().into_inner(ev).clear();
            }
            aux_batch.clear();
            for n in 0..num {
                let ci_clr = match P::WHICH {
                    WhichParty::Prover(ev) => {
                        ProverPrivateCopy::new(ci_batch.as_ref().prover_into(ev)[n])
                    }
                    WhichParty::Verifier(ev) => ProverPrivateCopy::empty(ev),
                };
                let ci_mac: ProverPrivateCopy<_, _> = ci_mac_batch
                    .as_ref()
                    .map(|ci_mac_batch| ci_mac_batch[n])
                    .into();

                let ci = match P::WHICH {
                    WhichParty::Prover(ev) => Mac::new(
                        ProverPrivateCopy::new(ci_clr.into_inner(ev)),
                        ci_mac.into_inner(ev),
                    ),
                    WhichParty::Verifier(ev) => ci_batch.as_ref().verifier_into(ev)[n],
                };

                let x = &x_batch[n].bits;
                let y = &y_batch[n].bits;

                debug_assert_eq!(x.len(), m);
                debug_assert_eq!(y.len(), m);

                let xi = x[i];
                let yi = y[i];

                let and1 = xi + ci;
                let and2 = yi + ci;

                if let WhichParty::Prover(ev) = P::WHICH {
                    let and1_clr = and1.value().into_inner(ev);
                    let and_res = and1_clr * and2.value().into_inner(ev);

                    let c = ci_clr.into_inner(ev) + and_res;
                    // let c_mac = ci_mac + and_res_mac; // is done in the next step
                    ci_batch.as_mut().prover_into(ev)[n] = c;
                    and_res_batch.as_mut().into_inner(ev).push(and_res);
                }

                let z = and1 + yi; // xi + yi + ci ;
                z_batch[n].push(z);
                aux_batch.push((and1, and2));
            }
            and_res_mac_batch.as_mut().map(|v| v.clear(), |v| v.clear());
            match P::WHICH {
                WhichParty::Prover(ev) => self.fcom_f2.input_prover_low_level(
                    ev,
                    channel,
                    rng,
                    and_res_batch.as_ref().into_inner(ev),
                    and_res_mac_batch.as_mut().prover_into(ev),
                )?,
                WhichParty::Verifier(ev) => self.fcom_f2.input_verifier_low_level(
                    ev,
                    channel,
                    rng,
                    num,
                    and_res_mac_batch.as_mut().verifier_into(ev),
                )?,
            }

            for (n, &aux) in aux_batch.iter().enumerate() {
                match P::WHICH {
                    WhichParty::Prover(ev) => {
                        let (and1, and2) = aux;
                        let and_res = and_res_batch.as_ref().into_inner(ev)[n];
                        let and_res_mac = and_res_mac_batch.as_ref().prover_into(ev)[n];
                        mult_check_state.accumulate(
                            &(
                                and1,
                                and2,
                                Mac::new(ProverPrivateCopy::new(and_res), and_res_mac),
                            ),
                            self.fcom_f2.get_delta(),
                        );

                        let ci_mac = ci_mac_batch.as_ref().into_inner(ev)[n];
                        let c_mac = ci_mac + and_res_mac;

                        ci_mac_batch.as_mut().into_inner(ev)[n] = c_mac;
                    }
                    WhichParty::Verifier(ev) => {
                        let (and1_mac, and2_mac) = aux;
                        let and_res_mac = and_res_mac_batch.as_ref().verifier_into(ev)[n];
                        mult_check_state.accumulate(
                            &(and1_mac, and2_mac, and_res_mac),
                            self.fcom_f2.get_delta(),
                        );

                        let ci = ci_batch.as_ref().verifier_into(ev)[n];
                        let c_mac = self.fcom_f2.add(ci, and_res_mac);
                        ci_batch.as_mut().verifier_into(ev)[n] = c_mac;
                    }
                }
            }
        }
        // check all the multiplication in one batch
        if let WhichParty::Prover(_) = P::WHICH {
            channel.flush()?;
        }
        self.fcom_f2
            .quicksilver_finalize(channel, rng, &mut mult_check_state)?;

        // reconstruct the solution
        let mut res = Vec::with_capacity(num);

        for (i, zs) in z_batch.into_iter().enumerate() {
            res.push((
                zs,
                match P::WHICH {
                    WhichParty::Prover(ev) => Mac::new(
                        ProverPrivateCopy::new(ci_batch.as_ref().prover_into(ev)[i]),
                        ci_mac_batch.as_ref().into_inner(ev)[i],
                    ),
                    WhichParty::Verifier(ev) => ci_batch.as_ref().verifier_into(ev)[i],
                },
            ));
        }

        Ok(res)
    }

    /// generate random edabits
    pub fn random_edabits<C: AbstractChannel + Clone>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
        nb_bits: usize,
        num: usize, // in the paper: NB + C
    ) -> Result<Vec<Edabits<P, FE>>> {
        let mut edabits_vec = Vec::with_capacity(num);
        let mut aux_bits = Vec::with_capacity(num);
        let mut aux_r_m = ProverPrivate::new(Vec::with_capacity(num));
        for _ in 0..num {
            let mut bits = Vec::with_capacity(nb_bits);
            for _ in 0..nb_bits {
                bits.push(self.fcom_f2.random(channel, rng)?);
            }
            if let WhichParty::Prover(ev) = P::WHICH {
                let r_m: FE::PrimeField = convert_bits_to_field::<FE::PrimeField>(
                    bits.iter()
                        .map(|x| x.value().into_inner(ev))
                        .collect::<Vec<F2>>()
                        .as_slice(),
                );
                aux_r_m.as_mut().into_inner(ev).push(r_m);
            }
            aux_bits.push(bits);
        }

        let aux_r_m_mac = match P::WHICH {
            WhichParty::Prover(ev) => PartyEither::prover_new(
                ev,
                self.fcom_fe
                    .input_prover(ev, channel, rng, aux_r_m.as_ref().into_inner(ev))?,
            ),
            WhichParty::Verifier(ev) => {
                PartyEither::verifier_new(ev, self.fcom_fe.input_verifier(ev, channel, rng, num)?)
            }
        };

        for (i, aux_bits) in aux_bits.into_iter().enumerate() {
            let value = match P::WHICH {
                WhichParty::Prover(ev) => Mac::new(
                    aux_r_m.as_ref().map(|aux_r_m| aux_r_m[i]).into(),
                    aux_r_m_mac.as_ref().prover_into(ev)[i],
                ),
                WhichParty::Verifier(ev) => aux_r_m_mac.as_ref().verifier_into(ev)[i],
            };
            edabits_vec.push(Edabits {
                bits: aux_bits,
                value,
            })
        }

        Ok(edabits_vec)
    }

    fn random_dabits<C: AbstractChannel + Clone>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
        num: usize,
    ) -> Result<Vec<Dabit<P, FE>>> {
        let mut dabit_vec = Vec::with_capacity(num);
        let mut b_batch = Vec::with_capacity(num);
        let mut b_m_batch = ProverPrivate::new(Vec::with_capacity(num));

        for _ in 0..num {
            let b = self.fcom_f2.random(channel, rng)?;
            b_batch.push(b);
            b_m_batch
                .as_mut()
                .zip(b.value().into())
                .map(|(b_m_batch, b)| b_m_batch.push(f2_to_fe(b)));
        }

        let b_m_mac_batch = match P::WHICH {
            WhichParty::Prover(ev) => PartyEither::prover_new(
                ev,
                self.fcom_fe
                    .input_prover(ev, channel, rng, b_m_batch.as_ref().into_inner(ev))?,
            ),
            WhichParty::Verifier(ev) => {
                PartyEither::verifier_new(ev, self.fcom_fe.input_verifier(ev, channel, rng, num)?)
            }
        };
        for (i, &b) in b_batch.iter().enumerate() {
            let value = match P::WHICH {
                WhichParty::Prover(ev) => Mac::new(
                    ProverPrivateCopy::new(b_m_batch.as_ref().into_inner(ev)[i]),
                    b_m_mac_batch.as_ref().prover_into(ev)[i],
                ),
                WhichParty::Verifier(ev) => b_m_mac_batch.as_ref().verifier_into(ev)[i],
            };
            dabit_vec.push(Dabit { bit: b, value })
        }

        Ok(dabit_vec)
    }

    fn fdabit<C: AbstractChannel + Clone>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
        dabits: &[Dabit<P, FE>],
    ) -> Result<()> {
        let s = FDABIT_SECURITY_PARAMETER;
        let n = dabits.len();

        let num_bits = std::mem::size_of::<usize>() * 8;
        let gamma = num_bits - ((n + 1).leading_zeros() as usize) - 1 + 1;

        check_parameters::<FE>(n, gamma)?;

        let mut res = true;

        if let WhichParty::Prover(ev) = P::WHICH {
            for dabit in dabits.iter() {
                // making sure the faulty dabits are not faulty
                debug_assert!(
                    ((dabit.bit.value().into_inner(ev) == F2::ZERO)
                        & (dabit.value.value().into_inner(ev) == FE::PrimeField::ZERO))
                        | ((dabit.bit.value().into_inner(ev) == F2::ONE)
                            & (dabit.value.value().into_inner(ev) == FE::PrimeField::ONE))
                );
            }
        }

        // step 1)
        let mut c_m = ProverPrivate::new(
            (0..s)
                .map(|_| Vec::with_capacity(gamma))
                .collect::<Vec<_>>(),
        );
        let mut c_m_mac = match P::WHICH {
            WhichParty::Prover(ev) => PartyEither::prover_new(ev, Vec::with_capacity(s)),
            WhichParty::Verifier(ev) => PartyEither::verifier_new(ev, Vec::with_capacity(s)),
        };

        if let WhichParty::Prover(ev) = P::WHICH {
            for k in 0..s {
                for _ in 0..gamma {
                    let b = F2::random(rng);
                    let b_m = f2_to_fe(b);
                    c_m.as_mut().into_inner(ev)[k].push(b_m);
                }
            }
        }

        for k in 0..s {
            match P::WHICH {
                WhichParty::Prover(ev) => {
                    let b_m_mac = self.fcom_fe.input_prover(
                        ev,
                        channel,
                        rng,
                        c_m.as_ref().into_inner(ev)[k].as_slice(),
                    )?;
                    c_m_mac.as_mut().prover_into(ev).push(b_m_mac);
                }
                WhichParty::Verifier(ev) => {
                    let b_m_mac = self.fcom_fe.input_verifier(ev, channel, rng, gamma)?;
                    c_m_mac.as_mut().verifier_into(ev).push(b_m_mac);
                }
            }
        }

        let mut c1 = ProverPrivate::new(Vec::with_capacity(s));
        if let WhichParty::Prover(ev) = P::WHICH {
            for k in 0..s {
                if c_m.as_ref().into_inner(ev)[k][0] == FE::PrimeField::ZERO {
                    c1.as_mut().into_inner(ev).push(F2::ZERO);
                } else {
                    c1.as_mut().into_inner(ev).push(F2::ONE);
                }
            }
        }
        let c1_mac = match P::WHICH {
            WhichParty::Prover(ev) => PartyEither::prover_new(
                ev,
                self.fcom_f2
                    .input_prover(ev, channel, rng, c1.as_ref().into_inner(ev))?,
            ),
            WhichParty::Verifier(ev) => {
                PartyEither::verifier_new(ev, self.fcom_f2.input_verifier(ev, channel, rng, s)?)
            }
        };

        // step 2)
        let mut triples = Vec::with_capacity(gamma * s);
        let mut andl_batch = ProverPrivate::new(Vec::with_capacity(gamma * s));
        let mut andl_mac_batch = match P::WHICH {
            WhichParty::Prover(ev) => PartyEither::prover_new(ev, Vec::with_capacity(gamma * s)),
            WhichParty::Verifier(ev) => {
                PartyEither::verifier_new(ev, Vec::with_capacity(gamma * s))
            }
        };
        let mut one_minus_ci_batch = ProverPrivate::new(Vec::with_capacity(gamma * s));
        let mut one_minus_ci_mac_batch = match P::WHICH {
            WhichParty::Prover(ev) => PartyEither::prover_new(ev, Vec::with_capacity(gamma * s)),
            WhichParty::Verifier(ev) => {
                PartyEither::verifier_new(ev, Vec::with_capacity(gamma * s))
            }
        };
        let mut and_res_batch = ProverPrivate::new(Vec::with_capacity(gamma * s));
        for k in 0..s {
            for i in 0..gamma {
                match P::WHICH {
                    WhichParty::Prover(ev) => {
                        let andl = c_m.as_ref().into_inner(ev)[k][i];
                        let andl_mac = c_m_mac.as_ref().prover_into(ev)[k][i];
                        let minus_ci = // -ci
                            Mac::new(ProverPrivateCopy::new(andl), andl_mac) * -FE::PrimeField::ONE;
                        let one_minus_ci = // 1 - ci
                            self.fcom_fe.affine_add_cst(FE::PrimeField::ONE, minus_ci);
                        let and_res = andl * one_minus_ci.value().into_inner(ev);
                        andl_batch.as_mut().into_inner(ev).push(andl);
                        andl_mac_batch.as_mut().prover_into(ev).push(andl_mac);
                        one_minus_ci_batch
                            .as_mut()
                            .into_inner(ev)
                            .push(one_minus_ci.value().into_inner(ev));
                        one_minus_ci_mac_batch
                            .as_mut()
                            .prover_into(ev)
                            .push(one_minus_ci.mac());
                        and_res_batch.as_mut().into_inner(ev).push(and_res);
                    }
                    WhichParty::Verifier(ev) => {
                        let andl_mac = c_m_mac.as_ref().verifier_into(ev)[k][i];
                        let minus_ci_mac = // -ci
                            andl_mac * -FE::PrimeField::ONE;
                        let one_minus_ci_mac = // 1 - ci
                            self.fcom_fe.affine_add_cst(FE::PrimeField::ONE, minus_ci_mac);
                        andl_mac_batch.as_mut().verifier_into(ev).push(andl_mac);
                        one_minus_ci_mac_batch
                            .as_mut()
                            .verifier_into(ev)
                            .push(one_minus_ci_mac);
                    }
                }
            }
        }

        let and_res_mac_batch = match P::WHICH {
            WhichParty::Prover(ev) => PartyEither::prover_new(
                ev,
                self.fcom_fe.input_prover(
                    ev,
                    channel,
                    rng,
                    and_res_batch.as_ref().into_inner(ev),
                )?,
            ),
            WhichParty::Verifier(ev) => PartyEither::verifier_new(
                ev,
                self.fcom_fe.input_verifier(ev, channel, rng, gamma * s)?,
            ),
        };
        for j in 0..s * gamma {
            triples.push(match P::WHICH {
                WhichParty::Prover(ev) => (
                    Mac::new(
                        ProverPrivateCopy::new(andl_batch.as_ref().into_inner(ev)[j]),
                        andl_mac_batch.as_ref().prover_into(ev)[j],
                    ),
                    Mac::new(
                        ProverPrivateCopy::new(one_minus_ci_batch.as_ref().into_inner(ev)[j]),
                        one_minus_ci_mac_batch.as_ref().prover_into(ev)[j],
                    ),
                    Mac::new(
                        ProverPrivateCopy::new(and_res_batch.as_ref().into_inner(ev)[j]),
                        and_res_mac_batch.as_ref().prover_into(ev)[j],
                    ),
                ),
                WhichParty::Verifier(ev) => (
                    andl_mac_batch.as_ref().verifier_into(ev)[j],
                    one_minus_ci_mac_batch.as_ref().verifier_into(ev)[j],
                    and_res_mac_batch.as_ref().verifier_into(ev)[j],
                ),
            });
        }

        // step 3)
        let seed = match P::WHICH {
            WhichParty::Prover(_) => {
                channel.flush()?;
                channel.read_block()?
            }
            WhichParty::Verifier(_) => {
                let seed = rng.gen::<Block>();
                channel.write_block(&seed)?;
                channel.flush()?;
                seed
            }
        };
        let mut e_rng = AesRng::from_seed(seed);
        let mut e = (0..s).map(|_| Vec::with_capacity(n)).collect::<Vec<_>>();
        for ek in e.iter_mut() {
            for _ in 0..n {
                let b = F2::random(&mut e_rng);
                ek.push(b);
            }
        }

        // step 4)
        let mut r_mac_batch = Vec::with_capacity(s);
        for k in 0..s {
            let mut r: ProverPrivateCopy<_, _> = c1.as_ref().map(|c1| c1[k]).into();
            let mut r_mac = match P::WHICH {
                WhichParty::Prover(ev) => c1_mac.as_ref().prover_into(ev)[k],
                WhichParty::Verifier(ev) => c1_mac.as_ref().verifier_into(ev)[k].mac(),
            };
            for (dabit, &eki) in dabits.iter().zip(e[k].iter()) {
                // TODO: do not need to do it when e[i] is ZERO
                let tmp = dabit.bit * eki;
                if let WhichParty::Prover(ev) = P::WHICH {
                    debug_assert!(
                        ((eki == F2::ONE)
                            & (tmp.value().into_inner(ev) == dabit.bit.value().into_inner(ev)))
                            | (tmp.value().into_inner(ev) == F2::ZERO)
                    );

                    *r.as_mut().into_inner(ev) += tmp.value().into_inner(ev);
                }
                r_mac += tmp.mac();
            }
            r_mac_batch.push(Mac::new(r, r_mac));
        }

        // step 5)
        let mut r_batch = VerifierPrivate::new(Vec::with_capacity(s));
        match P::WHICH {
            WhichParty::Prover(ev) => {
                self.fcom_f2
                    .open(channel, &r_mac_batch, &mut VerifierPrivate::empty(ev))?
            }
            WhichParty::Verifier(_) => {
                self.fcom_f2
                    .open(channel, &r_mac_batch, &mut r_batch.as_mut())?
            }
        }

        // step 6)
        let mut r_prime_batch = match P::WHICH {
            WhichParty::Prover(ev) => PartyEither::prover_new(ev, Vec::with_capacity(s)),
            WhichParty::Verifier(ev) => PartyEither::verifier_new(ev, Vec::with_capacity(s)),
        };
        for ek in e.iter() {
            // NOTE: for performance maybe step 4 and 6 should be combined in one loop
            let mut r_prime = ProverPrivateCopy::new(FE::PrimeField::ZERO);
            let mut r_prime_mac = FE::ZERO;
            for (dabit, &eki) in dabits.iter().zip(ek.iter()) {
                // TODO: do not need to do it when e[i] is ZERO
                let b = f2_to_fe(eki);
                let tmp = dabit.value * b;
                if let WhichParty::Prover(ev) = P::WHICH {
                    debug_assert!(
                        ((b == FE::PrimeField::ONE)
                            & (tmp.value().into_inner(ev) == dabit.value.value().into_inner(ev)))
                            | (tmp.value().into_inner(ev) == FE::PrimeField::ZERO)
                    );
                    *r_prime.as_mut().into_inner(ev) += tmp.value().into_inner(ev);
                }
                r_prime_mac += tmp.mac();
            }
            match P::WHICH {
                WhichParty::Prover(ev) => r_prime_batch
                    .as_mut()
                    .prover_into(ev)
                    .push((r_prime.into_inner(ev), r_prime_mac)),
                WhichParty::Verifier(ev) => {
                    r_prime_batch.as_mut().verifier_into(ev).push(r_prime_mac)
                }
            }
        }

        // step 7)
        let mut tau_mac_batch = Vec::with_capacity(s);
        for k in 0..s {
            let mut tau: PartyEitherCopy<_, _, _> = r_prime_batch
                .as_ref()
                .map(
                    |r_prime_batch| r_prime_batch[k],
                    |r_prime_batch| r_prime_batch[k],
                )
                .into();
            let mut twos = FE::PrimeField::ONE;
            for i in 0..gamma {
                let tmp = match P::WHICH {
                    WhichParty::Prover(ev) => {
                        Mac::new(
                            ProverPrivateCopy::new(c_m.as_ref().into_inner(ev)[k][i]),
                            c_m_mac.as_ref().prover_into(ev)[k][i],
                        ) * twos
                    }
                    WhichParty::Verifier(ev) => c_m_mac.as_ref().verifier_into(ev)[k][i] * twos,
                };
                match P::WHICH {
                    WhichParty::Prover(ev) => {
                        if i == 0 {
                            debug_assert_eq!(
                                c_m.as_ref().into_inner(ev)[k][i],
                                tmp.value().into_inner(ev)
                            );
                        }
                        tau.as_mut().prover_into(ev).0 += tmp.value().into_inner(ev);
                        tau.as_mut().prover_into(ev).1 += tmp.mac();
                    }
                    WhichParty::Verifier(ev) => {
                        *tau.as_mut().verifier_into(ev) += tmp.mac();
                    }
                }
                twos += twos;
            }
            tau_mac_batch.push(match P::WHICH {
                WhichParty::Prover(ev) => Mac::new(
                    ProverPrivateCopy::new(tau.prover_into(ev).0),
                    tau.prover_into(ev).1,
                ),
                WhichParty::Verifier(ev) => {
                    Mac::new(ProverPrivateCopy::empty(ev), tau.verifier_into(ev))
                }
            });
        }

        let mut tau_batch = VerifierPrivate::new(Vec::with_capacity(s));
        match P::WHICH {
            WhichParty::Prover(ev) => {
                self.fcom_fe
                    .open(channel, &tau_mac_batch, &mut VerifierPrivate::empty(ev))?
            }
            WhichParty::Verifier(ev) => self.fcom_fe.open(
                channel,
                &tau_mac_batch,
                &mut VerifierPrivate::new(tau_batch.as_mut().into_inner(ev)),
            )?,
        }

        // step 8)
        for k in 0..s {
            // NOTE: This is not needed for the prover
            let b =
                // mod2 is computed using the first bit of the bit decomposition.
                // NOTE: This scales linearly with the size of the bit decomposition and could lead to potential inefficiencies
                match P::WHICH {
                    WhichParty::Prover(ev) => (r_mac_batch[k].value().into_inner(ev) == F2::ONE) == tau_mac_batch[k].value().into_inner(ev).bit_decomposition()[0],
                    WhichParty::Verifier(ev) => (r_batch.as_ref().into_inner(ev)[k] == F2::ONE) == tau_batch.as_ref().into_inner(ev)[k].bit_decomposition()[0],
                };
            res &= b;
        }
        self.fcom_fe
            .quicksilver_check_multiply(channel, rng, &triples)?;

        if res {
            Ok(())
        } else {
            bail!("fail fdabit")
        }
    }

    // The conversion loop requires all of these parameters to function
    #[allow(clippy::too_many_arguments)]
    fn conv_loop<C: AbstractChannel + Clone>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
        edabits_vector: &[Edabits<P, FE>],
        r: &[Edabits<P, FE>],
        dabits: &[Dabit<P, FE>],
        convert_bit_2_field_aux1: &mut VerifierPrivate<P, &mut Vec<Mac<P, F2, F40b>>>,
        convert_bit_2_field_aux2: &mut PartyEither<P, &mut Vec<Mac<P, F2, F40b>>, &mut Vec<F2>>,
        e_m_batch: &mut Vec<Mac<P, FE, FE>>,
        ei_batch: &mut VerifierPrivate<P, &mut Vec<F2>>,
    ) -> Result<()> {
        let n = edabits_vector.len();
        let nb_bits = edabits_vector[0].bits.len();
        let power_two_nb_bits = power_two::<FE>(nb_bits);

        // step 6)b) batched and moved up
        let e_batch = self.bit_add_carry(channel, rng, edabits_vector, r)?;

        // step 6)c) batched and moved up
        let mut e_carry_batch = Vec::with_capacity(n);
        for &(_, e_carry) in e_batch.iter() {
            e_carry_batch.push(e_carry);
        }

        self.convert_bit_2_field(
            channel,
            dabits,
            &e_carry_batch,
            convert_bit_2_field_aux1,
            convert_bit_2_field_aux2,
            e_m_batch,
        )?;

        // 6)a)
        let mut e_prime_mac_batch = Vec::with_capacity(n);
        // 6)d)
        let mut ei_mac_batch = Vec::with_capacity(n * nb_bits);
        for i in 0..n {
            // 6)a)
            let c_m = edabits_vector[i].value;
            let r_m = r[i].value;
            let c_plus_r = c_m + r_m;

            // 6)c) done earlier
            let e_m = e_m_batch[i];

            // 6)d)
            let tmp = e_m * -power_two_nb_bits;
            let e_prime = c_plus_r + tmp;
            e_prime_mac_batch.push(e_prime);
            ei_mac_batch.extend(&e_batch[i].0);
        }

        // 6)e)
        match P::WHICH {
            WhichParty::Prover(ev) => {
                self.fcom_f2
                    .open(channel, &ei_mac_batch, &mut VerifierPrivate::empty(ev))?
            }
            WhichParty::Verifier(_) => self.fcom_f2.open(channel, &ei_mac_batch, ei_batch)?,
        }

        let mut check_zero_state = ZeroCheckState::init(channel, rng)?;
        for i in 0..n {
            let sum = match P::WHICH {
                WhichParty::Prover(ev) => convert_bits_to_field_mac::<_, FE>(
                    ev,
                    &ei_mac_batch[i * nb_bits..(i + 1) * nb_bits],
                ),
                WhichParty::Verifier(ev) => convert_bits_to_field::<FE>(
                    &ei_batch.as_ref().into_inner(ev)[i * nb_bits..(i + 1) * nb_bits],
                ),
            };
            check_zero_state
                .accumulate(&self.fcom_fe.affine_add_cst(-sum, e_prime_mac_batch[i]))?;
        }

        check_zero_state.finalize(channel)?;
        Ok(())
    }

    /// conversion checking
    pub fn conv<C: AbstractChannel + Clone>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
        num_bucket: usize,
        num_cut: usize,
        edabits_vector: &[Edabits<P, FE>],
        bucket_channels: Option<Vec<SyncChannel<BufReader<TcpStream>, BufWriter<TcpStream>>>>,
    ) -> Result<()> {
        let n = edabits_vector.len();
        if n == 0 {
            info!("conversion check on no conversions");
            return Ok(());
        }

        let nb_bits = edabits_vector[0].bits.len();
        info!(
            "conversion check, field:{}, nb_bits:{:?} vector_size:{:?}",
            field_name::<FE>(),
            nb_bits,
            edabits_vector.len(),
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

        // step 3): get seed for permutation
        let seed = match P::WHICH {
            WhichParty::Prover(_) => channel.read_block()?,
            WhichParty::Verifier(_) => {
                let seed = rng.gen::<Block>();
                channel.write_block(&seed)?;
                channel.flush()?;
                seed
            }
        };
        let mut shuffle_rng = AesRng::from_seed(seed);

        // step 4): shuffle edabits, dabits, and triples
        generate_permutation(&mut shuffle_rng, &mut r);
        generate_permutation(&mut shuffle_rng, &mut dabits);

        // step 5)a)
        let base = n * num_bucket;
        let mut a_vec = VerifierPrivate::new(Vec::with_capacity(nb_bits));
        let mut a_m = VerifierPrivate::new(Vec::with_capacity(1));
        for i in 0..num_cut {
            let idx = base + i;
            let a = &r[idx];
            self.fcom_f2.open(channel, &a.bits, &mut a_vec.as_mut())?;
            self.fcom_fe.open(channel, &[a.value], &mut a_m.as_mut())?;
            if let WhichParty::Verifier(ev) = P::WHICH {
                if convert_bits_to_field::<FE>(a_vec.as_ref().into_inner(ev))
                    != a_m.as_ref().into_inner(ev)[0]
                {
                    bail!("Wrong open random edabit");
                }
            }
        }

        // step 5)b)
        // unnecessary step with quicksilver mult check

        // step 6)
        if bucket_channels.is_none() {
            let mut convert_bit_2_field_aux1 = VerifierPrivate::new(Vec::with_capacity(n));
            let mut convert_bit_2_field_aux2 = match P::WHICH {
                WhichParty::Prover(ev) => PartyEither::prover_new(ev, Vec::with_capacity(n)),
                WhichParty::Verifier(ev) => PartyEither::verifier_new(ev, Vec::with_capacity(n)),
            };
            let mut e_m_batch = Vec::with_capacity(n);
            let mut ei_batch = VerifierPrivate::new(Vec::with_capacity(n));
            for j in 0..num_bucket {
                // base index for the window of `idx_base..idx_base + n` values
                let idx_base = j * n;

                self.conv_loop(
                    channel,
                    rng,
                    edabits_vector,
                    &r[idx_base..idx_base + n],
                    &dabits[idx_base..idx_base + n],
                    &mut convert_bit_2_field_aux1.as_mut(),
                    &mut convert_bit_2_field_aux2.as_mut(),
                    &mut e_m_batch,
                    &mut ei_batch.as_mut(),
                )?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::mac::Mac;
    use super::{f2_to_fe, Conv, Dabit, Edabits};
    use crate::homcom::FCom;
    use crate::svole_trait::Svole;
    use ocelot::svole::{LPN_EXTEND_SMALL, LPN_SETUP_SMALL};
    use scuttlebutt::ring::FiniteRing;
    use scuttlebutt::{
        field::{F61p, FiniteField, F2},
        AesRng, Channel,
    };
    use std::{
        io::{BufReader, BufWriter},
        os::unix::net::UnixStream,
    };
    use swanky_party::either::PartyEither;
    use swanky_party::private::{ProverPrivateCopy, VerifierPrivate};
    use swanky_party::{Prover, Verifier, IS_PROVER, IS_VERIFIER};

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
            let mut fconv = Conv::<Prover, FE, Svole<_, _, _>, Svole<_, _, _>>::init_with_fcoms(
                &FCom::init(&mut channel, &mut rng, LPN_SETUP_SMALL, LPN_EXTEND_SMALL).unwrap(),
                &FCom::init(&mut channel, &mut rng, LPN_SETUP_SMALL, LPN_EXTEND_SMALL).unwrap(),
            )
            .unwrap();

            let mut res = Vec::new();
            for _ in 0..count {
                let (rb, rb_mac) = fconv
                    .fcom_f2
                    .random(&mut channel, &mut rng)
                    .unwrap()
                    .decompose(IS_PROVER);
                let rm = f2_to_fe(rb);
                let rm_mac = fconv
                    .fcom_fe
                    .input_prover(IS_PROVER, &mut channel, &mut rng, &[rm])
                    .unwrap()[0];
                let (x_f2, x_f2_mac) = fconv
                    .fcom_f2
                    .random(&mut channel, &mut rng)
                    .unwrap()
                    .decompose(IS_PROVER);

                let mut convert_bit_2_field_aux = PartyEither::prover_new(IS_PROVER, Vec::new());
                let mut x_m_batch = Vec::new();
                fconv
                    .convert_bit_2_field(
                        &mut channel,
                        &[Dabit {
                            bit: Mac::new(ProverPrivateCopy::new(rb), rb_mac),
                            value: Mac::new(ProverPrivateCopy::new(rm), rm_mac),
                        }],
                        &[Mac::new(ProverPrivateCopy::new(x_f2), x_f2_mac)],
                        &mut VerifierPrivate::empty(IS_PROVER),
                        &mut convert_bit_2_field_aux.as_mut(),
                        &mut x_m_batch,
                    )
                    .unwrap();

                fconv
                    .fcom_fe
                    .open(
                        &mut channel,
                        &x_m_batch,
                        &mut VerifierPrivate::empty(IS_PROVER),
                    )
                    .unwrap();

                assert_eq!(
                    f2_to_fe::<FE::PrimeField>(x_f2),
                    x_m_batch[0].value().into_inner(IS_PROVER)
                );
                res.push((x_f2, x_m_batch[0].value().into_inner(IS_PROVER)));
            }
            res
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut fconv = Conv::<Verifier, FE, Svole<_, _, _>, Svole<_, _, _>>::init_with_fcoms(
            &FCom::init(&mut channel, &mut rng, LPN_SETUP_SMALL, LPN_EXTEND_SMALL).unwrap(),
            &FCom::init(&mut channel, &mut rng, LPN_SETUP_SMALL, LPN_EXTEND_SMALL).unwrap(),
        )
        .unwrap();

        let mut res = Vec::new();
        for _ in 0..count {
            let rb_mac = fconv.fcom_f2.random(&mut channel, &mut rng).unwrap();
            let r_m_mac = fconv
                .fcom_fe
                .input_verifier(IS_VERIFIER, &mut channel, &mut rng, 1)
                .unwrap()[0];
            let x_f2_mac = fconv.fcom_f2.random(&mut channel, &mut rng).unwrap();

            let mut convert_bit_2_field_aux1 = VerifierPrivate::new(Vec::new());
            let mut convert_bit_2_field_aux2 = PartyEither::verifier_new(IS_VERIFIER, Vec::new());
            let mut x_m_batch = Vec::new();
            fconv
                .convert_bit_2_field(
                    &mut channel,
                    &[Dabit {
                        bit: rb_mac,
                        value: r_m_mac,
                    }],
                    &[x_f2_mac],
                    &mut convert_bit_2_field_aux1.as_mut(),
                    &mut convert_bit_2_field_aux2.as_mut(),
                    &mut x_m_batch,
                )
                .unwrap();

            let mut x_m = Vec::new();
            fconv
                .fcom_fe
                .open(
                    &mut channel,
                    &[x_m_batch[0]],
                    &mut VerifierPrivate::new(&mut x_m),
                )
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
        let x = [F2::ONE, F2::ZERO, F2::ONE, F2::ZERO, F2::ONE, F2::ONE];
        let y = [F2::ZERO, F2::ONE, F2::ONE, F2::ONE, F2::ZERO, F2::ONE];
        let expected = [F2::ONE, F2::ONE, F2::ZERO, F2::ZERO, F2::ZERO, F2::ONE];
        let carry = F2::ONE;

        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut fconv = Conv::<Prover, FE, Svole<_, _, _>, Svole<_, _, _>>::init_with_fcoms(
                &FCom::init(&mut channel, &mut rng, LPN_SETUP_SMALL, LPN_EXTEND_SMALL).unwrap(),
                &FCom::init(&mut channel, &mut rng, LPN_SETUP_SMALL, LPN_EXTEND_SMALL).unwrap(),
            )
            .unwrap();

            let x_mac = fconv
                .fcom_f2
                .input_prover(IS_PROVER, &mut channel, &mut rng, &x)
                .unwrap();
            let y_mac = fconv
                .fcom_f2
                .input_prover(IS_PROVER, &mut channel, &mut rng, &y)
                .unwrap();

            let mut vx = Vec::new();
            for i in 0..power {
                vx.push(Mac::new(ProverPrivateCopy::new(x[i]), x_mac[i]));
            }

            let mut vy = Vec::new();
            for i in 0..power {
                vy.push(Mac::new(ProverPrivateCopy::new(y[i]), y_mac[i]));
            }
            let default_fe = Mac::new(ProverPrivateCopy::new(FE::PrimeField::ZERO), FE::ZERO);
            let (res, c) = fconv
                .bit_add_carry(
                    &mut channel,
                    &mut rng,
                    &[Edabits {
                        bits: vx,
                        value: default_fe,
                    }],
                    &[Edabits {
                        bits: vy,
                        value: default_fe,
                    }],
                )
                .unwrap()[0]
                .clone();

            fconv
                .fcom_f2
                .open(&mut channel, &res, &mut VerifierPrivate::empty(IS_PROVER))
                .unwrap();

            fconv
                .fcom_f2
                .open(&mut channel, &[c], &mut VerifierPrivate::empty(IS_PROVER))
                .unwrap();
            (res, c)
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut fconv = Conv::<Verifier, FE, Svole<_, _, _>, Svole<_, _, _>>::init_with_fcoms(
            &FCom::init(&mut channel, &mut rng, LPN_SETUP_SMALL, LPN_EXTEND_SMALL).unwrap(),
            &FCom::init(&mut channel, &mut rng, LPN_SETUP_SMALL, LPN_EXTEND_SMALL).unwrap(),
        )
        .unwrap();

        let x_mac = fconv
            .fcom_f2
            .input_verifier(IS_VERIFIER, &mut channel, &mut rng, power)
            .unwrap();
        let y_mac = fconv
            .fcom_f2
            .input_verifier(IS_VERIFIER, &mut channel, &mut rng, power)
            .unwrap();

        let default_fe = Mac::new(ProverPrivateCopy::empty(IS_VERIFIER), FE::ZERO);
        let (res_mac, c_mac) = fconv
            .bit_add_carry(
                &mut channel,
                &mut rng,
                &[Edabits {
                    bits: x_mac,
                    value: default_fe,
                }],
                &[Edabits {
                    bits: y_mac,
                    value: default_fe,
                }],
            )
            .unwrap()[0]
            .clone();

        let mut res = Vec::new();
        fconv
            .fcom_f2
            .open(&mut channel, &res_mac, &mut VerifierPrivate::new(&mut res))
            .unwrap();

        let mut c = Vec::new();
        fconv
            .fcom_f2
            .open(&mut channel, &[c_mac], &mut VerifierPrivate::new(&mut c))
            .unwrap();

        let _resprover = handle.join().unwrap();

        for i in 0..power {
            assert_eq!(expected[i], res[i]);
        }
        assert_eq!(carry, c[0]);
    }

    fn test_fdabit<FE: FiniteField<PrimeField = FE>>() {
        let count = 5;
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut fconv = Conv::<Prover, FE, Svole<_, _, _>, Svole<_, _, _>>::init_with_fcoms(
                &FCom::init(&mut channel, &mut rng, LPN_SETUP_SMALL, LPN_EXTEND_SMALL).unwrap(),
                &FCom::init(&mut channel, &mut rng, LPN_SETUP_SMALL, LPN_EXTEND_SMALL).unwrap(),
            )
            .unwrap();

            let dabits = fconv.random_dabits(&mut channel, &mut rng, count).unwrap();
            fconv.fdabit(&mut channel, &mut rng, &dabits).unwrap();
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut fconv = Conv::<Verifier, FE, Svole<_, _, _>, Svole<_, _, _>>::init_with_fcoms(
            &FCom::init(&mut channel, &mut rng, LPN_SETUP_SMALL, LPN_EXTEND_SMALL).unwrap(),
            &FCom::init(&mut channel, &mut rng, LPN_SETUP_SMALL, LPN_EXTEND_SMALL).unwrap(),
        )
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
            let mut fconv = Conv::<Prover, FE, Svole<_, _, _>, Svole<_, _, _>>::init_with_fcoms(
                &FCom::init(&mut channel, &mut rng, LPN_SETUP_SMALL, LPN_EXTEND_SMALL).unwrap(),
                &FCom::init(&mut channel, &mut rng, LPN_SETUP_SMALL, LPN_EXTEND_SMALL).unwrap(),
            )
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
        let mut fconv = Conv::<Verifier, FE, Svole<_, _, _>, Svole<_, _, _>>::init_with_fcoms(
            &FCom::init(&mut channel, &mut rng, LPN_SETUP_SMALL, LPN_EXTEND_SMALL).unwrap(),
            &FCom::init(&mut channel, &mut rng, LPN_SETUP_SMALL, LPN_EXTEND_SMALL).unwrap(),
        )
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
