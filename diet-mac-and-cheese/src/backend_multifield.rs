#![allow(clippy::too_many_arguments)]

//! Diet Mac'n'Cheese backends supporting SIEVE IR0+ with multiple fields.

use crate::circuit_ir::{CircInputs, FunStore, GateM, TypeSpecification, TypeStore, WireId};
use crate::edabits::RcRefCell;
use crate::edabits::{EdabitsProver, EdabitsVerifier, ProverConv, VerifierConv};
use crate::homcom::{FComProver, FComVerifier};
use crate::homcom::{MacProver, MacVerifier};
use crate::memory::Memory;
use crate::read_sieveir_phase2::BufRelation;
use crate::text_reader::TextRelation;
use crate::{backend_trait::BackendT, circuit_ir::GatesOrPluginBody};
use crate::{DietMacAndCheeseProver, DietMacAndCheeseVerifier};
use eyre::{ensure, eyre, Result};
use generic_array::typenum::Unsigned;
use log::{debug, info};
use mac_n_cheese_sieve_parser::text_parser::RelationReader;
use mac_n_cheese_sieve_parser::RelationReader as RR;
use ocelot::svole::wykw::LpnParams;
#[cfg(feature = "ff")]
use ocelot::svole::wykw::{LPN_EXTEND_EXTRASMALL, LPN_SETUP_EXTRASMALL};
use ocelot::svole::wykw::{LPN_EXTEND_MEDIUM, LPN_EXTEND_SMALL, LPN_SETUP_MEDIUM, LPN_SETUP_SMALL};
use rand::{CryptoRng, Rng};
#[cfg(feature = "ff")]
use scuttlebutt::field::{F384p, F384q, Secp256k1, Secp256k1order};
use scuttlebutt::field::{F40b, F61p, FiniteField, F2};
use scuttlebutt::ring::FiniteRing;
use scuttlebutt::AbstractChannel;
use scuttlebutt::AesRng;
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::path::PathBuf;

// This file implements IR0+ support for diet-mac-n-cheese and is broken up into the following components:
//
// 0)   Assuming `DietMacAndCheeseProver/Verifier` and `BackendT` which provides the interface and implementation of
//         primitive arithmetic gates for a single field
// I)   Field Conversion. Extend BackendT with interface for field-switching conversions
// II)  Circuit. Instance/Witness/Relation/FunStore
// III) Memory. Structure for Wires and stack to support function calls
// IV)  EvaluatorSingle. An evaluator for a single field
// V)   EvaluatorMulti. An evaluator holding multiple single-field evaluators.

// NOTES: optimizations to consider
//
// * use `*mut X` instead of AbsoluteAddr
// * retry the StreamGate but without the Arc, that might be the reason of the slow down.
//   Profiler was showing a lot of time on `drop Gate`, which implies not building the intermediate gate
// * Reduce to one round the `mult_check` and `check_zero`.

/// Conversions between fields are batched, and this constant defines the batch size.
const SIZE_CONVERSION_BATCH: usize = 100_000;

#[derive(Clone, Debug)]
pub enum MacBitGeneric {
    BitProver(MacProver<F40b>),
    BitVerifier(MacVerifier<F40b>),
    BitPublic(F2),
}

/// This trait extends the `BackendT` trait with `assert_conv_*` functions to go to bits.
pub trait BackendConvT: BackendT {
    // Convert a wire to bits in lower-endian
    fn assert_conv_to_bits(&mut self, w: &Self::Wire) -> Result<Vec<MacBitGeneric>>;
    // convert bits in lower-endian to a wire
    fn assert_conv_from_bits(&mut self, x: &[MacBitGeneric]) -> Result<Self::Wire>;

    // Finalize the field switching conversions, by running edabits conversion checks
    fn finalize_conv(&mut self) -> Result<()>;
}

impl<C: AbstractChannel, RNG: CryptoRng + Rng> BackendConvT
    for DietMacAndCheeseProver<F40b, C, RNG>
{
    fn assert_conv_to_bits(&mut self, w: &Self::Wire) -> Result<Vec<MacBitGeneric>> {
        debug!("CONV_TO_BITS {:?}", w);
        Ok(vec![MacBitGeneric::BitProver(*w)])
    }

    fn assert_conv_from_bits(&mut self, x: &[MacBitGeneric]) -> Result<Self::Wire> {
        match x[0] {
            MacBitGeneric::BitProver(m) => Ok(m),
            MacBitGeneric::BitVerifier(_) => {
                panic!("Should be a prover bit");
            }
            MacBitGeneric::BitPublic(m) => self.input_public(m),
        }
    }

    fn finalize_conv(&mut self) -> Result<()> {
        // We dont need to finalize the conversion
        // for the binary functionality because they are for free.
        Ok(())
    }
}

impl<C: AbstractChannel, RNG: CryptoRng + Rng> BackendConvT
    for DietMacAndCheeseVerifier<F40b, C, RNG>
{
    fn assert_conv_to_bits(&mut self, w: &Self::Wire) -> Result<Vec<MacBitGeneric>> {
        Ok(vec![MacBitGeneric::BitVerifier(*w)])
    }

    fn assert_conv_from_bits(&mut self, x: &[MacBitGeneric]) -> Result<Self::Wire> {
        match x[0] {
            MacBitGeneric::BitVerifier(m) => Ok(m),
            MacBitGeneric::BitProver(_) => {
                panic!("Should be a verifier bit");
            }
            MacBitGeneric::BitPublic(m) => self.input_public(m),
        }
    }

    fn finalize_conv(&mut self) -> Result<()> {
        // We dont need to finalize the conversion
        // for the binary functionality because they are for free.
        Ok(())
    }
}

// this structure is for grouping the edabits with the same number of bits.
// This is necessary for example when F1 -> F2 and F3 -> F2, with F1 and F3
// requiring a different number of bits.
// NOTE: We use a BTreeMap instead of a HashMap so that the iterator is sorted over the keys, which proved
// to be useful during `finalize`
struct EdabitsMap<E>(BTreeMap<usize, Vec<E>>);

impl<E> EdabitsMap<E> {
    pub(crate) fn new() -> Self {
        EdabitsMap(BTreeMap::new())
    }

    pub(crate) fn push_elm(&mut self, k: usize, e: E) -> usize {
        self.0.entry(k).or_insert_with(std::vec::Vec::new);
        self.0.get_mut(&k).as_mut().unwrap().push(e);
        self.0.len()
    }
}

struct DietMacAndCheeseConvProver<FE: FiniteField, C: AbstractChannel, RNG: CryptoRng + Rng> {
    dmc: DietMacAndCheeseProver<FE, C, RNG>,
    conv: ProverConv<FE>,
    edabits_map: EdabitsMap<EdabitsProver<FE>>,
    dmc_f2: DietMacAndCheeseProver<F40b, C, RNG>,
    no_batching: bool,
}

impl<FE: FiniteField<PrimeField = FE>, C: AbstractChannel, RNG: CryptoRng + Rng>
    DietMacAndCheeseConvProver<FE, C, RNG>
{
    pub fn init(
        channel: &mut C,
        rng: RNG,
        rng2: RNG,
        fcom_f2: &RcRefCell<FComProver<F40b>>,
        lpn_setup: LpnParams,
        lpn_extend: LpnParams,
        no_batching: bool,
    ) -> Result<Self> {
        let mut dmc = DietMacAndCheeseProver::<FE, C, RNG>::init(
            channel,
            rng,
            lpn_setup,
            lpn_extend,
            no_batching,
        )?;
        let conv = ProverConv::init_zero(fcom_f2, dmc.get_party())?;
        Ok(DietMacAndCheeseConvProver {
            dmc,
            conv,
            edabits_map: EdabitsMap::new(),
            dmc_f2: DietMacAndCheeseProver::<F40b, C, RNG>::init_with_fcom(
                channel,
                rng2,
                fcom_f2,
                no_batching,
            )?,
            no_batching,
        })
    }
}

impl<FE: FiniteField<PrimeField = FE>, C: AbstractChannel, RNG: CryptoRng + Rng> BackendT
    for DietMacAndCheeseConvProver<FE, C, RNG>
{
    type Wire = <DietMacAndCheeseProver<FE, C, RNG> as BackendT>::Wire;
    type FieldElement = <DietMacAndCheeseProver<FE, C, RNG> as BackendT>::FieldElement;

    fn from_bytes_le(val: &[u8]) -> Result<Self::FieldElement> {
        <DietMacAndCheeseProver<FE, C, RNG> as BackendT>::from_bytes_le(val)
    }
    fn one(&self) -> Result<Self::FieldElement> {
        self.dmc.one()
    }
    fn zero(&self) -> Result<Self::FieldElement> {
        self.dmc.zero()
    }
    fn challenge(&mut self) -> Result<Self::Wire> {
        self.dmc.challenge()
    }
    fn copy(&mut self, wire: &Self::Wire) -> Result<Self::Wire> {
        self.dmc.copy(wire)
    }
    fn constant(&mut self, val: Self::FieldElement) -> Result<Self::Wire> {
        self.dmc.constant(val)
    }
    fn assert_zero(&mut self, wire: &Self::Wire) -> Result<()> {
        self.dmc.assert_zero(wire)
    }
    fn add(&mut self, a: &Self::Wire, b: &Self::Wire) -> Result<Self::Wire> {
        self.dmc.add(a, b)
    }
    fn sub(&mut self, a: &Self::Wire, b: &Self::Wire) -> Result<Self::Wire> {
        self.dmc.sub(a, b)
    }
    fn mul(&mut self, a: &Self::Wire, b: &Self::Wire) -> Result<Self::Wire> {
        self.dmc.mul(a, b)
    }
    fn add_constant(&mut self, a: &Self::Wire, b: Self::FieldElement) -> Result<Self::Wire> {
        self.dmc.add_constant(a, b)
    }
    fn mul_constant(&mut self, a: &Self::Wire, b: Self::FieldElement) -> Result<Self::Wire> {
        self.dmc.mul_constant(a, b)
    }

    fn input_public(&mut self, val: Self::FieldElement) -> Result<Self::Wire> {
        <DietMacAndCheeseProver<FE, C, RNG> as BackendT>::input_public(&mut self.dmc, val)
    }
    fn input_private(&mut self, val: Option<Self::FieldElement>) -> Result<Self::Wire> {
        <DietMacAndCheeseProver<FE, C, RNG> as BackendT>::input_private(&mut self.dmc, val)
    }
    fn finalize(&mut self) -> Result<()> {
        self.dmc.finalize()?;
        self.dmc_f2.finalize()?;
        Ok(())
    }
    fn reset(&mut self) {
        self.dmc.reset();
    }
}

impl<FE: FiniteField<PrimeField = FE>, C: AbstractChannel, RNG: CryptoRng + Rng>
    DietMacAndCheeseConvProver<FE, C, RNG>
{
    pub(crate) fn less_eq_than_with_public2(
        &mut self,
        a: &[MacProver<F40b>],
        b: &[F2],
    ) -> Result<()> {
        // act = 1;
        // r   = 0;
        // for i in 0..(n+1):
        //     act' = act(1+a+b)
        //     r'   = r + ((r+1) * act * a * (b+1))
        // assert_zero(r)
        assert_eq!(a.len(), b.len());

        let mut act = self.dmc_f2.input_public(F2::ONE)?;
        let mut r = self.dmc_f2.input_public(F2::ZERO)?;

        // data assumed provided in little-endian
        let l = a.len();
        for i in 0..a.len() {
            let a_i = a[l - i - 1];
            let b_i = b[l - i - 1];
            // (1+a+b)
            let a_plus_b = self.dmc_f2.add_constant(&a_i, b_i)?;
            let one_plus_a_plus_b = self.dmc_f2.add_constant(&a_plus_b, F2::ONE)?;

            // act' = act(1+a+b)
            let act_prime = self.dmc_f2.mul(&act, &one_plus_a_plus_b)?;

            // r + 1
            let r_plus_one = self.dmc_f2.add_constant(&r, F2::ONE)?;

            // p1 = a * (b+1)
            let b_1 = b_i + F2::ONE;
            let p1 = self.dmc_f2.mul_constant(&a_i, b_1)?;

            // act * (a * (b+1))
            let act_times_p1 = self.dmc_f2.mul(&act, &p1)?;

            // (r+1) * (act * (a * (b+1)))
            let p2 = self.dmc_f2.mul(&r_plus_one, &act_times_p1)?;

            // r' = r + ((r+1) * act * a * (b+1))
            let r_prime = self.dmc_f2.add(&r, &p2)?;

            act = act_prime;
            r = r_prime;
        }

        self.dmc_f2.assert_zero(&r)?;
        Ok(())
    }

    fn maybe_do_conversion_check(&mut self, id: usize, num: usize) -> Result<()> {
        if num > SIZE_CONVERSION_BATCH || self.no_batching {
            let edabits = self.edabits_map.0.get_mut(&id).unwrap();
            self.conv.conv(
                &mut self.dmc.channel,
                &mut self.dmc.rng,
                5,
                5,
                edabits,
                None,
            )?;
            self.edabits_map.0.insert(id, vec![]);
        }

        Ok(())
    }
}
impl<FE: FiniteField<PrimeField = FE>, C: AbstractChannel, RNG: CryptoRng + Rng> BackendConvT
    for DietMacAndCheeseConvProver<FE, C, RNG>
{
    fn assert_conv_to_bits(&mut self, a: &Self::Wire) -> Result<Vec<MacBitGeneric>> {
        debug!("CONV_TO_BITS {:?}", a);
        let bits = a.value().bit_decomposition();

        let mut v = Vec::with_capacity(bits.len());
        for b in bits {
            let b2 = F2::from(b);
            let mac = self.conv.fcom_f2.get_refmut().input1(
                &mut self.dmc.channel,
                &mut self.dmc.rng,
                b2,
            )?;
            v.push(MacProver::new(b2, mac));
        }

        self.less_eq_than_with_public2(
            &v,
            (-FE::ONE)
                .bit_decomposition()
                .into_iter()
                .map(F2::from)
                .collect::<Vec<_>>()
                .as_slice(),
        )?;

        let r = v.iter().map(|m| MacBitGeneric::BitProver(*m)).collect();

        let id = v.len();
        let num = self
            .edabits_map
            .push_elm(id, EdabitsProver { bits: v, value: *a });
        self.maybe_do_conversion_check(id, num)?;

        Ok(r)
    }

    fn assert_conv_from_bits(&mut self, x: &[MacBitGeneric]) -> Result<Self::Wire> {
        let mut power_twos = FE::ONE;
        let mut recomposed_value = FE::ZERO;
        let mut bits = Vec::with_capacity(x.len());

        for xx in x {
            match xx {
                MacBitGeneric::BitProver(m) => {
                    recomposed_value += (if m.value() == F2::ONE {
                        FE::ONE
                    } else {
                        FE::ZERO
                    }) * power_twos;
                    power_twos += power_twos;

                    bits.push(*m);
                }
                MacBitGeneric::BitVerifier(_) => {
                    panic!("Should not be a Verifier value");
                }
                MacBitGeneric::BitPublic(b) => {
                    // input the public bit as a private value and assert they are equal
                    let m = self.dmc_f2.input_private(Some(*b))?;
                    let hope_zero = self.dmc_f2.add_constant(&m, *b)?;
                    self.dmc_f2.assert_zero(&hope_zero)?;

                    recomposed_value +=
                        (if *b == F2::ONE { FE::ONE } else { FE::ZERO }) * power_twos;
                    power_twos += power_twos;
                    bits.push(m);
                }
            }
        }

        debug!("CONV_FROM_BITS {:?}", recomposed_value);
        let mac = <DietMacAndCheeseProver<FE, C, RNG> as BackendT>::input_private(
            &mut self.dmc,
            Some(recomposed_value),
        )?;

        let id = bits.len();
        let num = self
            .edabits_map
            .push_elm(id, EdabitsProver { bits, value: mac });
        self.maybe_do_conversion_check(id, num)?;
        Ok(mac)
    }

    fn finalize_conv(&mut self) -> Result<()> {
        for (_key, edabits) in self.edabits_map.0.iter() {
            self.conv.conv(
                &mut self.dmc.channel,
                &mut self.dmc.rng,
                5,
                5,
                edabits,
                None,
            )?;
        }
        Ok(())
    }
}

struct DietMacAndCheeseConvVerifier<FE: FiniteField, C: AbstractChannel, RNG: CryptoRng + Rng> {
    dmc: DietMacAndCheeseVerifier<FE, C, RNG>,
    conv: VerifierConv<FE>,
    edabits_map: EdabitsMap<EdabitsVerifier<FE>>,
    dmc_f2: DietMacAndCheeseVerifier<F40b, C, RNG>,
    no_batching: bool,
}

impl<FE: FiniteField<PrimeField = FE>, C: AbstractChannel, RNG: CryptoRng + Rng>
    DietMacAndCheeseConvVerifier<FE, C, RNG>
{
    pub fn init(
        channel: &mut C,
        rng: RNG,
        rng2: RNG,
        fcom_f2: &RcRefCell<FComVerifier<F40b>>,
        lpn_setup: LpnParams,
        lpn_extend: LpnParams,
        no_batching: bool,
    ) -> Result<Self> {
        let mut dmc = DietMacAndCheeseVerifier::<FE, C, RNG>::init(
            channel,
            rng,
            lpn_setup,
            lpn_extend,
            no_batching,
        )?;
        let conv = VerifierConv::init_zero(fcom_f2, dmc.get_party())?;
        Ok(DietMacAndCheeseConvVerifier {
            dmc,
            conv,
            edabits_map: EdabitsMap::new(),
            dmc_f2: DietMacAndCheeseVerifier::<F40b, C, RNG>::init_with_fcom(
                channel,
                rng2,
                fcom_f2,
                no_batching,
            )?,
            no_batching,
        })
    }
}

impl<FE: FiniteField<PrimeField = FE>, C: AbstractChannel, RNG: CryptoRng + Rng> BackendT
    for DietMacAndCheeseConvVerifier<FE, C, RNG>
{
    type Wire = <DietMacAndCheeseVerifier<FE, C, RNG> as BackendT>::Wire;
    type FieldElement = <DietMacAndCheeseVerifier<FE, C, RNG> as BackendT>::FieldElement;

    fn from_bytes_le(val: &[u8]) -> Result<Self::FieldElement> {
        <DietMacAndCheeseVerifier<FE, C, RNG> as BackendT>::from_bytes_le(val)
    }
    fn one(&self) -> Result<Self::FieldElement> {
        self.dmc.one()
    }
    fn zero(&self) -> Result<Self::FieldElement> {
        self.dmc.zero()
    }
    fn copy(&mut self, wire: &Self::Wire) -> Result<Self::Wire> {
        self.dmc.copy(wire)
    }
    fn challenge(&mut self) -> Result<Self::Wire> {
        self.dmc.challenge()
    }
    fn constant(&mut self, val: Self::FieldElement) -> Result<Self::Wire> {
        self.dmc.constant(val)
    }
    fn assert_zero(&mut self, wire: &Self::Wire) -> Result<()> {
        self.dmc.assert_zero(wire)
    }
    fn add(&mut self, a: &Self::Wire, b: &Self::Wire) -> Result<Self::Wire> {
        self.dmc.add(a, b)
    }
    fn sub(&mut self, a: &Self::Wire, b: &Self::Wire) -> Result<Self::Wire> {
        self.dmc.sub(a, b)
    }
    fn mul(&mut self, a: &Self::Wire, b: &Self::Wire) -> Result<Self::Wire> {
        self.dmc.mul(a, b)
    }
    fn add_constant(&mut self, a: &Self::Wire, b: Self::FieldElement) -> Result<Self::Wire> {
        self.dmc.add_constant(a, b)
    }
    fn mul_constant(&mut self, a: &Self::Wire, b: Self::FieldElement) -> Result<Self::Wire> {
        self.dmc.mul_constant(a, b)
    }

    fn input_public(&mut self, val: Self::FieldElement) -> Result<Self::Wire> {
        <DietMacAndCheeseVerifier<FE, C, RNG> as BackendT>::input_public(&mut self.dmc, val)
    }
    fn input_private(&mut self, _val: Option<Self::FieldElement>) -> Result<Self::Wire> {
        <DietMacAndCheeseVerifier<FE, C, RNG> as BackendT>::input_private(&mut self.dmc, None)
    }
    fn finalize(&mut self) -> Result<()> {
        self.dmc.finalize()?;
        self.dmc_f2.finalize()?;
        Ok(())
    }
    fn reset(&mut self) {
        self.dmc.reset();
    }
}

impl<FE: FiniteField<PrimeField = FE>, C: AbstractChannel, RNG: CryptoRng + Rng>
    DietMacAndCheeseConvVerifier<FE, C, RNG>
{
    fn less_eq_than_with_public2(&mut self, a: &[MacVerifier<F40b>], b: &[F2]) -> Result<()> {
        // act = 1;
        // r   = 0;
        // for i in 0..(n+1):
        //     act' = act(1+a+b)
        //     r'   = r + ((r+1) * act * a * (b+1))
        // assert_zero(r)
        assert_eq!(a.len(), b.len());

        let mut act = self.dmc_f2.input_public(F2::ONE)?;
        let mut r = self.dmc_f2.input_public(F2::ZERO)?;

        // data assumed provided in little-endian
        let l = a.len();
        for i in 0..a.len() {
            let a_i = a[l - i - 1];
            let b_i = b[l - i - 1];

            // (1+a+b)
            let a_plus_b = self.dmc_f2.add_constant(&a_i, b_i)?;
            let one_plus_a_plus_b = self.dmc_f2.add_constant(&a_plus_b, F2::ONE)?;

            // act' = act(1+a+b)
            let act_prime = self.dmc_f2.mul(&act, &one_plus_a_plus_b)?;

            // r + 1
            let r_plus_one = self.dmc_f2.add_constant(&r, F2::ONE)?;

            // p1 = a * (b+1)
            let b_1 = b_i + F2::ONE;
            let p1 = self.dmc_f2.mul_constant(&a_i, b_1)?;

            // act * (a * (b+1))
            let act_times_p1 = self.dmc_f2.mul(&act, &p1)?;

            // (r+1) * (act * (a * (b+1)))
            let p2 = self.dmc_f2.mul(&r_plus_one, &act_times_p1)?;

            // r' = r + ((r+1) * act * a * (b+1))
            let r_prime = self.dmc_f2.add(&r, &p2)?;

            act = act_prime;
            r = r_prime;
        }

        self.dmc_f2.assert_zero(&r)?;
        Ok(())
    }

    fn maybe_do_conversion_check(&mut self, id: usize, num: usize) -> Result<()> {
        if num > SIZE_CONVERSION_BATCH || self.no_batching {
            let edabits = self.edabits_map.0.get_mut(&id).unwrap();
            self.conv.conv(
                &mut self.dmc.channel,
                &mut self.dmc.rng,
                5,
                5,
                edabits,
                None,
            )?;
            self.edabits_map.0.insert(id, vec![]);
        }

        Ok(())
    }
}

impl<FE: FiniteField<PrimeField = FE>, C: AbstractChannel, RNG: CryptoRng + Rng> BackendConvT
    for DietMacAndCheeseConvVerifier<FE, C, RNG>
{
    fn assert_conv_to_bits(&mut self, a: &Self::Wire) -> Result<Vec<MacBitGeneric>> {
        let mut v = Vec::with_capacity(FE::NumberOfBitsInBitDecomposition::to_usize());
        for _ in 0..FE::NumberOfBitsInBitDecomposition::to_usize() {
            let mac = self
                .conv
                .fcom_f2
                .get_refmut()
                .input1(&mut self.dmc.channel, &mut self.dmc.rng)?;
            v.push(mac);
        }

        self.less_eq_than_with_public2(
            &v,
            (-FE::ONE)
                .bit_decomposition()
                .iter()
                .copied()
                .map(F2::from)
                .collect::<Vec<_>>()
                .as_slice(),
        )?;

        let r = v.iter().map(|m| MacBitGeneric::BitVerifier(*m)).collect();

        let id = v.len();
        let num = self
            .edabits_map
            .push_elm(id, EdabitsVerifier { bits: v, value: *a });
        self.maybe_do_conversion_check(id, num)?;

        Ok(r)
    }
    fn assert_conv_from_bits(&mut self, x: &[MacBitGeneric]) -> Result<Self::Wire> {
        let mut bits = Vec::with_capacity(x.len());

        for xx in x {
            match xx {
                MacBitGeneric::BitVerifier(m) => {
                    bits.push(*m);
                }
                MacBitGeneric::BitProver(_) => {
                    panic!("Should not be a Prover value");
                }
                MacBitGeneric::BitPublic(b) => {
                    // input the public bit as a private value and assert they are equal
                    let m = self.dmc_f2.input_private(None)?;
                    let hope_zero = self.dmc_f2.add_constant(&m, *b)?;
                    self.dmc_f2.assert_zero(&hope_zero)?;
                    bits.push(m);
                }
            }
        }

        let mac =
            <DietMacAndCheeseVerifier<FE, C, RNG> as BackendT>::input_private(&mut self.dmc, None)?;

        let id = bits.len();
        let num = self
            .edabits_map
            .push_elm(id, EdabitsVerifier { bits, value: mac });
        self.maybe_do_conversion_check(id, num)?;

        Ok(mac)
    }
    fn finalize_conv(&mut self) -> Result<()> {
        for (_key, edabits) in self.edabits_map.0.iter() {
            self.conv.conv(
                &mut self.dmc.channel,
                &mut self.dmc.rng,
                5,
                5,
                edabits,
                None,
            )?;
        }
        Ok(())
    }
}

// II) Instance/Witness/Relation/Gates/FunStore
// See circuit_ir.rs

// III Memory layout
// See memory.rs

// IV Evaluator for single field

trait EvaluatorT {
    fn evaluate_gate(
        &mut self,
        gate: &GateM,
        instance: Option<Vec<u8>>,
        witness: Option<Vec<u8>>,
    ) -> Result<()>;

    fn conv_gate_get(&mut self, gate: &GateM) -> Result<Vec<MacBitGeneric>>;
    fn conv_gate_set(&mut self, gate: &GateM, bits: &[MacBitGeneric]) -> Result<()>;

    fn push_frame(&mut self, args_count: &Option<WireId>, vector_size: &Option<WireId>);
    fn pop_frame(&mut self);
    fn allocate_new(&mut self, first_id: WireId, last_id: WireId);
    // TODO: Make allocate_slice return a result in case the operation violate some memory management
    fn allocate_slice(
        &mut self,
        src_first: WireId,
        src_last: WireId,
        start: WireId,
        count: WireId,
        allow_allocation: bool,
    );

    fn finalize(&mut self) -> Result<()>;
}

pub struct EvaluatorSingle<B: BackendConvT> {
    memory: Memory<<B as BackendT>::Wire>,
    backend: B,
    is_boolean: bool,
}

impl<B: BackendConvT> EvaluatorSingle<B>
where
    B::Wire: Default + Clone + Copy + Debug,
{
    fn new(backend: B, is_boolean: bool) -> Self {
        let memory = Memory::new();
        EvaluatorSingle {
            memory,
            backend,
            is_boolean,
        }
    }
}

impl<B: BackendConvT> EvaluatorT for EvaluatorSingle<B>
where
    B::Wire: Default + Clone + Copy + Debug,
{
    #[inline]
    fn evaluate_gate(
        &mut self,
        gate: &GateM,
        instance: Option<Vec<u8>>,
        witness: Option<Vec<u8>>,
    ) -> Result<()> {
        use GateM::*;

        match gate {
            Constant(_, out, value) => {
                let v = self.backend.constant(B::from_bytes_le(value)?)?;
                self.memory.set(*out, &v);
            }

            AssertZero(_, inp) => {
                let wire = self.memory.get(*inp);
                debug!("AssertZero wire: {wire:?}");
                if self.backend.assert_zero(wire).is_err() {
                    return Err(eyre!("Assert zero fails on wire {}", *inp));
                }
            }

            Copy(_, out, inp) => {
                let in_wire = self.memory.get(*inp);
                let out_wire = self.backend.copy(in_wire)?;
                self.memory.set(*out, &out_wire);
            }

            Add(_, out, left, right) => {
                let l = self.memory.get(*left);
                let r = self.memory.get(*right);
                let v = self.backend.add(l, r)?;
                self.memory.set(*out, &v);
            }

            Sub(_, out, left, right) => {
                let l = self.memory.get(*left);
                let r = self.memory.get(*right);
                let v = self.backend.sub(l, r)?;
                self.memory.set(*out, &v);
            }

            Mul(_, out, left, right) => {
                let l = self.memory.get(*left);
                let r = self.memory.get(*right);
                let v = self.backend.mul(l, r)?;
                self.memory.set(*out, &v);
            }

            AddConstant(_, out, inp, constant) => {
                let l = self.memory.get(*inp);
                let r = constant;
                let v = self.backend.add_constant(l, B::from_bytes_le(r)?)?;
                self.memory.set(*out, &v);
            }

            MulConstant(_, out, inp, constant) => {
                let l = self.memory.get(*inp);
                let r = constant;
                let v = self.backend.mul_constant(l, B::from_bytes_le(r)?)?;
                self.memory.set(*out, &v);
            }

            Instance(_ty, out) => {
                let v = self
                    .backend
                    .input_public(B::from_bytes_le(&instance.unwrap()).unwrap())?;
                self.memory.set(*out, &v);
            }

            Witness(_, out) => {
                let w = witness.map(|v| B::from_bytes_le(&v).unwrap());
                let v = self.backend.input_private(w)?;
                // debug!("WITNESS: {:?}", v);
                self.memory.set(*out, &v);
            }
            New(_ty, first, last) => {
                self.memory.allocation_new(*first, *last);
            }
            Delete(_ty, first, last) => {
                self.memory.allocation_delete(*first, *last);
            }
            Call(_) => {
                panic!("Call should be intercepted earlier")
            }
            Conv(_) => {
                panic!("Conv should be intercepted earlier")
            }
            Challenge(_, out) => {
                let v = self.backend.challenge()?;
                debug!("Challenge value: {v:?}");
                self.memory.set(*out, &v);
            }
            Comment(_) => {
                panic!("Comment should be intercepted earlier")
            }
        }
        Ok(())
    }

    // The cases covered for field switching are:
    // 1) b <- x
    // 2) x <- b
    // 3) b0..b_n <- x   with n = log2(X)
    // 4) x <- b0..b_n   with n = log2(X)
    // 5) b0..b_n <- x   with n < log2(X)
    // 6) x <- b0..b_n   with n < log2(X)
    // 7) y <- x         with Y > X
    // 8) x <- y         with Y > X
    fn conv_gate_get(&mut self, gate: &GateM) -> Result<Vec<MacBitGeneric>> {
        use GateM::*;
        match gate {
            Conv(conv_members) => {
                let (_ty_out, _out, _ty_in, (inp1, inp2)) = conv_members.as_ref();
                if *inp1 != *inp2 {
                    if self.is_boolean {
                        let mut v = Vec::with_capacity((inp2 + 1 - inp1).try_into().unwrap());
                        for inp in *inp1..(*inp2 + 1) {
                            let in_wire = self.memory.get(inp);
                            debug!("CONV GET {:?}", in_wire);
                            let bits = self.backend.assert_conv_to_bits(in_wire)?;
                            assert_eq!(bits.len(), 1);
                            v.push(bits[0].clone());
                        }
                        return Ok(v.into_iter().rev().collect());
                        // NOTE: Without reverse in case conversation gates are little-endian instead of big-endian
                        //return Ok(v);
                    }

                    return Err(eyre!(
                        "field switching from multiple wires on non-boolean field is not supported"
                    ));
                }
                let in_wire = self.memory.get(*inp1);
                debug!("CONV GET {:?}", in_wire);
                let bits = self.backend.assert_conv_to_bits(in_wire)?;
                debug!("CONV GET bits {:?}", bits);
                Ok(bits)
            }
            _ => {
                panic!("Conv gate expected");
            }
        }
    }

    fn conv_gate_set(&mut self, gate: &GateM, bits: &[MacBitGeneric]) -> Result<()> {
        use GateM::*;
        match gate {
            Conv(conv_members) => {
                let (_ty_out, (out1, out2), _ty_in, _inp) = conv_members.as_ref();
                if *out1 != *out2 {
                    if self.is_boolean {
                        assert!((*out2 - *out1 + 1) as usize <= bits.len());

                        for (i, _out) in (*out1..(*out2 + 1)).enumerate() {
                            let v = self.backend.assert_conv_from_bits(&[bits[i].clone()])?;
                            debug!("CONV SET {:?}", v);
                            let out_wire = out2 - (i as WireId);
                            // NOTE: Without reverse in case conversation gates are little-endian instead of big-endian
                            // let out_wire = out1 + i as WireId;
                            self.memory.set(out_wire, &v);
                        }
                        return Ok(());
                    }

                    return Err(eyre!(
                        "field switching to multiple wires on non-boolean field is not supported"
                    ));
                }
                let v = self.backend.assert_conv_from_bits(bits)?;
                debug!("CONV SET {:?}", v);
                self.memory.set(*out1, &v);
                Ok(())
            }
            _ => {
                panic!("Conv gate expected");
            }
        }
    }

    fn push_frame(&mut self, args_count: &Option<WireId>, vector_size: &Option<WireId>) {
        self.memory.push_frame(args_count, vector_size);
    }

    fn pop_frame(&mut self) {
        self.memory.pop_frame();
    }

    fn allocate_new(&mut self, first_id: WireId, last_id: WireId) {
        self.memory.allocation_new(first_id, last_id);
    }

    fn allocate_slice(
        &mut self,
        src_first: WireId,
        src_last: WireId,
        start: WireId,
        count: WireId,
        allow_allocation: bool,
    ) {
        self.memory
            .allocate_slice(src_first, src_last, start, count, allow_allocation);
    }

    fn finalize(&mut self) -> Result<()> {
        debug!("Finalize in EvaluatorSingle");
        self.backend.finalize_conv()?;
        self.backend.finalize()?;
        Ok(())
    }
}

// V) Evaluator for multiple fields

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum Party {
    Prover,
    Verifier,
}

pub struct EvaluatorCirc<C: AbstractChannel + 'static> {
    inputs: CircInputs,
    fcom_f2_prover: Option<RcRefCell<FComProver<F40b>>>, // RcRefCell because of a unique Homcom functionality F2 shared by all other fields
    fcom_f2_verifier: Option<RcRefCell<FComVerifier<F40b>>>,
    type_store: TypeStore,
    eval: Vec<Box<dyn EvaluatorT>>,
    f2_idx: usize,
    party: Party,
    rng: AesRng,
    no_batching: bool,
    phantom: PhantomData<C>,
}

impl<C: AbstractChannel + 'static> EvaluatorCirc<C> {
    // TODO: Factorize interface for `new_with_prover` and `new_with_verifier`
    pub fn new(
        party: Party,
        channel: &mut C,
        mut rng: AesRng,
        inputs: CircInputs,
        type_store: TypeStore,
        lpn_small: bool,
        no_batching: bool,
    ) -> Result<Self> {
        let lpn_setup;
        let lpn_extend;
        if lpn_small {
            lpn_setup = LPN_SETUP_SMALL;
            lpn_extend = LPN_EXTEND_SMALL;
        } else {
            lpn_setup = LPN_SETUP_MEDIUM;
            lpn_extend = LPN_EXTEND_MEDIUM;
        }
        let fcom_f2_prover = if party == Party::Prover {
            Some(RcRefCell::new(FComProver::<F40b>::init(
                channel, &mut rng, lpn_setup, lpn_extend,
            )?))
        } else {
            None
        };

        let fcom_f2_verifier = if party == Party::Verifier {
            Some(RcRefCell::new(FComVerifier::<F40b>::init(
                channel, &mut rng, lpn_setup, lpn_extend,
            )?))
        } else {
            None
        };

        Ok(EvaluatorCirc {
            party,
            inputs,
            fcom_f2_prover,
            fcom_f2_verifier,
            type_store,
            eval: Vec::new(),
            f2_idx: 42,
            rng,
            no_batching,
            phantom: PhantomData,
        })
    }

    pub fn load_backends(&mut self, channel: &mut C, lpn_small: bool) -> Result<()> {
        let type_store = self.type_store.clone();
        for (idx, spec) in type_store.iter() {
            match spec {
                TypeSpecification::Field(field) => {
                    let rng = self.rng.fork();
                    let rng2 = self.rng.fork();
                    self.load_backend(channel, rng, rng2, *field, *idx as usize, lpn_small)?;
                }
                _ => {
                    todo!("Type not supported yet: {:?}", spec);
                }
            }
        }
        Ok(())
    }

    fn load_backend(
        &mut self,
        channel: &mut C,
        rng: AesRng,
        rng2: AesRng,
        field: std::any::TypeId,
        idx: usize,
        lpn_small: bool,
    ) -> Result<()> {
        // Loading the backends in order
        assert_eq!(idx, self.eval.len());

        let back: Box<dyn EvaluatorT>;
        let lpn_setup;
        let lpn_extend;
        if lpn_small {
            lpn_setup = LPN_SETUP_SMALL;
            lpn_extend = LPN_EXTEND_SMALL;
        } else {
            lpn_setup = LPN_SETUP_MEDIUM;
            lpn_extend = LPN_EXTEND_MEDIUM;
        }
        if field == std::any::TypeId::of::<F2>() {
            info!("loading field F2");

            // Note for F2 we do not use the backend with Conv, simply dietMC
            if self.party == Party::Prover {
                let fcom_f2 = self.fcom_f2_prover.as_ref().unwrap();
                let dmc = DietMacAndCheeseProver::<F40b, _, _>::init_with_fcom(
                    channel,
                    rng,
                    fcom_f2,
                    self.no_batching,
                )?;
                back = Box::new(EvaluatorSingle::new(dmc, true));
            } else {
                let fcom_f2 = self.fcom_f2_verifier.as_ref().unwrap();
                let dmc = DietMacAndCheeseVerifier::<F40b, _, _>::init_with_fcom(
                    channel,
                    rng,
                    fcom_f2,
                    self.no_batching,
                )?;
                back = Box::new(EvaluatorSingle::new(dmc, true));
            }
            self.f2_idx = self.eval.len();
        } else if field == std::any::TypeId::of::<F61p>() {
            info!("loading field F61p");
            if self.party == Party::Prover {
                let fcom_f2 = self.fcom_f2_prover.as_ref().unwrap();
                let dmc = DietMacAndCheeseConvProver::<F61p, _, _>::init(
                    channel,
                    rng,
                    rng2,
                    fcom_f2,
                    lpn_setup,
                    lpn_extend,
                    self.no_batching,
                )?;
                back = Box::new(EvaluatorSingle::new(dmc, false));
            } else {
                let fcom_f2 = self.fcom_f2_verifier.as_ref().unwrap();
                let dmc = DietMacAndCheeseConvVerifier::<F61p, _, _>::init(
                    channel,
                    rng,
                    rng2,
                    fcom_f2,
                    lpn_setup,
                    lpn_extend,
                    self.no_batching,
                )?;
                back = Box::new(EvaluatorSingle::new(dmc, false));
            }
        } else {
            #[cfg(all(feature = "ff"))]
            {
                if field == std::any::TypeId::of::<Secp256k1>() {
                    info!("loading field Secp256k1");
                    if self.party == Party::Prover {
                        let fcom_f2 = self.fcom_f2_prover.as_ref().unwrap();
                        let dmc = DietMacAndCheeseConvProver::<Secp256k1, _, _>::init(
                            channel,
                            rng,
                            rng2,
                            fcom_f2,
                            LPN_SETUP_EXTRASMALL,
                            LPN_EXTEND_EXTRASMALL,
                            self.no_batching,
                        )?;
                        back = Box::new(EvaluatorSingle::new(dmc, false));
                    } else {
                        let fcom_f2 = self.fcom_f2_verifier.as_ref().unwrap();
                        let dmc = DietMacAndCheeseConvVerifier::<Secp256k1, _, _>::init(
                            channel,
                            rng,
                            rng2,
                            fcom_f2,
                            LPN_SETUP_EXTRASMALL,
                            LPN_EXTEND_EXTRASMALL,
                            self.no_batching,
                        )?;
                        back = Box::new(EvaluatorSingle::new(dmc, false));
                    }
                } else if field == std::any::TypeId::of::<Secp256k1order>() {
                    info!("loading field Secp256k1order");
                    if self.party == Party::Prover {
                        let fcom_f2 = self.fcom_f2_prover.as_ref().unwrap();
                        let dmc = DietMacAndCheeseConvProver::<Secp256k1order, _, _>::init(
                            channel,
                            rng,
                            rng2,
                            fcom_f2,
                            LPN_SETUP_EXTRASMALL,
                            LPN_EXTEND_EXTRASMALL,
                            self.no_batching,
                        )?;
                        back = Box::new(EvaluatorSingle::new(dmc, false));
                    } else {
                        let fcom_f2 = self.fcom_f2_verifier.as_ref().unwrap();
                        let dmc = DietMacAndCheeseConvVerifier::<Secp256k1order, _, _>::init(
                            channel,
                            rng,
                            rng2,
                            fcom_f2,
                            LPN_SETUP_EXTRASMALL,
                            LPN_EXTEND_EXTRASMALL,
                            self.no_batching,
                        )?;
                        back = Box::new(EvaluatorSingle::new(dmc, false));
                    }
                } else if field == std::any::TypeId::of::<F384p>() {
                    info!("loading field F384p");
                    if self.party == Party::Prover {
                        let fcom_f2 = self.fcom_f2_prover.as_ref().unwrap();
                        let dmc = DietMacAndCheeseConvProver::<F384p, _, _>::init(
                            channel,
                            rng,
                            rng2,
                            fcom_f2,
                            LPN_SETUP_EXTRASMALL,
                            LPN_EXTEND_EXTRASMALL,
                            self.no_batching,
                        )?;
                        back = Box::new(EvaluatorSingle::new(dmc, false));
                    } else {
                        let fcom_f2 = self.fcom_f2_verifier.as_ref().unwrap();
                        let dmc = DietMacAndCheeseConvVerifier::<F384p, _, _>::init(
                            channel,
                            rng,
                            rng2,
                            fcom_f2,
                            LPN_SETUP_EXTRASMALL,
                            LPN_EXTEND_EXTRASMALL,
                            self.no_batching,
                        )?;
                        back = Box::new(EvaluatorSingle::new(dmc, false));
                    }
                } else if field == std::any::TypeId::of::<F384q>() {
                    info!("loading field F384q");
                    if self.party == Party::Prover {
                        let fcom_f2 = self.fcom_f2_prover.as_ref().unwrap();
                        let dmc = DietMacAndCheeseConvProver::<F384q, _, _>::init(
                            channel,
                            rng,
                            rng2,
                            fcom_f2,
                            LPN_SETUP_EXTRASMALL,
                            LPN_EXTEND_EXTRASMALL,
                            self.no_batching,
                        )?;
                        back = Box::new(EvaluatorSingle::new(dmc, false));
                    } else {
                        let fcom_f2 = self.fcom_f2_verifier.as_ref().unwrap();
                        let dmc = DietMacAndCheeseConvVerifier::<F384q, _, _>::init(
                            channel,
                            rng,
                            rng2,
                            fcom_f2,
                            LPN_SETUP_EXTRASMALL,
                            LPN_EXTEND_EXTRASMALL,
                            self.no_batching,
                        )?;
                        back = Box::new(EvaluatorSingle::new(dmc, false));
                    }
                } else {
                    return Err(eyre!("Unknown or unsupported field {:?}", field));
                }
            }
            #[cfg(not(all(feature = "ff")))]
            {
                return Err(eyre!(
                    "Unknown or unsupported field {:?} without feature ff",
                    field
                ));
            }
        }
        self.eval.push(back);
        Ok(())
    }

    pub fn finish(&mut self) -> Result<()> {
        info!("Finish EvaluatorCirc...");
        for i in 0..self.eval.len() {
            self.eval[i].finalize()?;
        }
        info!("...done");
        Ok(())
    }

    pub fn evaluate_gates(&mut self, gates: &[GateM], fun_store: &FunStore) -> Result<()> {
        for gate in gates.iter() {
            self.eval_gate(gate, fun_store)?;
        }

        for i in 0..self.eval.len() {
            self.eval[i].finalize()?;
        }
        Ok(())
    }

    fn evaluate_gates_passed(&mut self, gates: &[GateM], fun_store: &FunStore) -> Result<()> {
        for gate in gates.iter() {
            self.eval_gate(gate, fun_store)?;
        }
        Ok(())
    }

    // This is an almost copy of `eval_gate`for Cybernetica
    pub fn evaluate_gates_with_inputs(
        &mut self,
        gates: &[GateM],
        fun_store: &FunStore,
        inputs: &mut CircInputs,
    ) -> Result<()> {
        for gate in gates.iter() {
            self.eval_gate_with_inputs(gate, fun_store, inputs)?;
        }
        Ok(())
    }

    pub fn evaluate_relation(&mut self, path: &PathBuf) -> Result<()> {
        let mut buf_rel = BufRelation::new(path, &self.type_store)?;

        loop {
            let r = buf_rel.next();
            match r {
                None => {
                    break;
                }
                Some(()) => {
                    self.evaluate_gates_passed(&buf_rel.gates, &buf_rel.fun_store)?;
                }
            }
        }
        for i in 0..self.eval.len() {
            self.eval[i].finalize()?;
        }
        Ok(())
    }

    pub fn evaluate_relation_text(&mut self, path: &PathBuf) -> Result<()> {
        let rel = RelationReader::open(path.as_path()).unwrap();

        let mut buf_rel = TextRelation::new_with_type_store(&self.type_store);

        rel.read(&mut buf_rel)?;
        self.evaluate_gates_passed(&buf_rel.gates, &buf_rel.fun_store)?;

        for i in 0..self.eval.len() {
            self.eval[i].finalize()?;
        }
        Ok(())
    }

    #[inline]
    fn evaluate_call_gate(
        &mut self,
        name: &String,
        out_ranges: &[(WireId, WireId)],
        in_ranges: &[(WireId, WireId)],
        fun_store: &FunStore,
    ) -> Result<()> {
        // 1) get the function information and body
        // 2) push new function frame, with references to output and inputs
        // 3) call eval_gates on body of function
        // 4) pop frame

        // 1)
        let func = fun_store.get(name)?;

        let gates_body = match &func.body() {
            GatesOrPluginBody::Gates(body) => body,
            GatesOrPluginBody::Plugin(_) => func
                .compiled_info
                .plugin_gates
                .as_ref()
                .ok_or(eyre!("No gates associated with plugin"))?,
        };

        // 2)
        // We use the analysis on function body to find the types used in the body and only push a frame to those field backends.
        // TODO: currently push the size of args or vec without differentiating based on type.
        for ty in func.compiled_info.type_ids.iter() {
            self.eval[*ty as usize]
                .push_frame(&func.compiled_info.args_count, &func.compiled_info.body_max);
        }

        let mut prev = 0;
        let output_counts = func.output_counts();
        ensure!(
            out_ranges.len() == output_counts.len(),
            "Output range does not match output counts: {} != {}",
            out_ranges.len(),
            output_counts.len()
        );
        #[allow(clippy::needless_range_loop)]
        for i in 0..output_counts.len() {
            let (field_idx, count) = output_counts[i];
            let (src_first, src_last) = out_ranges[i];
            self.eval[field_idx as usize].allocate_slice(src_first, src_last, prev, count, true);
            prev += count;
        }

        let input_counts = func.input_counts();
        ensure!(
            in_ranges.len() == input_counts.len(),
            "Input range does not match input counts: {} != {}",
            in_ranges.len(),
            input_counts.len()
        );
        #[allow(clippy::needless_range_loop)]
        for i in 0..input_counts.len() {
            let (field_idx, count) = input_counts[i];
            let (src_first, src_last) = in_ranges[i];
            self.eval[field_idx as usize].allocate_slice(src_first, src_last, prev, count, false);
            prev += count;
        }

        // 3)
        self.evaluate_gates_passed(gates_body.gates(), fun_store)?;

        // 4)
        // TODO: dont do the push blindly on all backends
        for ty in func.compiled_info.type_ids.iter() {
            self.eval[*ty as usize].pop_frame();
        }
        Ok(())
    }

    fn eval_gate(&mut self, gate: &GateM, fun_store: &FunStore) -> Result<()> {
        debug!("GATE: {:?}", gate);
        match gate {
            GateM::Conv(conv_members) => {
                debug!("CONV IN");
                let (ty1, _out, ty2, _inp) = conv_members.as_ref();
                // First we get the bits from the input and then we convert to the output.
                let bits = self.eval[*ty2 as usize].conv_gate_get(gate)?;
                // then we convert the bits to the out field.
                self.eval[*ty1 as usize].conv_gate_set(gate, &bits)?;
                debug!("CONV OUT");
            }
            GateM::Instance(ty, _out) => {
                let i = *ty as usize;
                self.eval[i].evaluate_gate(gate, self.inputs.pop_instance(i), None)?;
            }
            GateM::Witness(ty, _out) => {
                let i = *ty as usize;
                self.eval[i].evaluate_gate(gate, None, self.inputs.pop_witness(i))?;
            }
            GateM::Call(arg) => {
                let (name, out_ranges, in_ranges) = arg.as_ref();
                self.evaluate_call_gate(name, out_ranges, in_ranges, fun_store)?;
            }
            GateM::Comment(str) => {
                debug!("Comment: {:?}", str);
            }
            _ => {
                let ty = gate.type_id();
                self.eval[ty as usize].evaluate_gate(gate, None, None)?;
            }
        }
        Ok(())
    }

    // This function is a copy of `eval_gate` (added for Cybernetica/ZKSC) where the inputs
    // are passed because they could be dynamically updated.
    fn eval_gate_with_inputs(
        &mut self,
        gate: &GateM,
        fun_store: &FunStore,
        inputs: &mut CircInputs,
    ) -> Result<()> {
        debug!("GATE: {:?}", gate);
        match gate {
            GateM::Conv(conv_members) => {
                debug!("CONV IN");
                let (ty1, _out, ty2, _inp) = conv_members.as_ref();
                // First we get the bits from the input and then we convert to the output.
                let bits = self.eval[*ty2 as usize].conv_gate_get(gate)?;
                // then we convert the bits to the out field.
                self.eval[*ty1 as usize].conv_gate_set(gate, &bits)?;
                debug!("CONV OUT");
            }
            GateM::Instance(ty, _out) => {
                let i = *ty as usize;
                self.eval[i].evaluate_gate(gate, inputs.pop_instance(i), None)?;
            }
            GateM::Witness(ty, _out) => {
                let i = *ty as usize;
                self.eval[i].evaluate_gate(gate, None, inputs.pop_witness(i))?;
            }
            GateM::Call(arg) => {
                let (name, out_ranges, in_ranges) = arg.as_ref();
                self.evaluate_call_gate(name, out_ranges, in_ranges, fun_store)?;
            }
            GateM::Comment(str) => {
                debug!("Comment: {:?}", str);
            }
            _ => {
                let ty = gate.type_id();
                self.eval[ty as usize].evaluate_gate(gate, None, None)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{RcRefCell, TypeStore};
    use crate::backend_multifield::{EvaluatorCirc, Party};
    use crate::circuit_ir::{CircInputs, FunStore, FuncDecl, GateM, WireId, WireRange};
    use crate::{
        backend_trait::BackendT,
        homcom::{FComProver, FComVerifier},
    };
    use ocelot::svole::wykw::{LPN_EXTEND_SMALL, LPN_SETUP_SMALL};
    use pretty_env_logger;
    use rand::SeedableRng;
    #[cfg(feature = "ff")]
    use scuttlebutt::field::{F384p, F384q};
    #[allow(unused_imports)]
    use scuttlebutt::field::{F40b, F2};
    #[cfg(all(feature = "ff"))]
    use scuttlebutt::field::{Secp256k1, Secp256k1order};
    use scuttlebutt::ring::FiniteRing;
    use scuttlebutt::{field::F61p, field::FiniteField, AesRng, Channel};
    use std::env;
    use std::{collections::VecDeque, thread::JoinHandle};
    use std::{
        io::{BufReader, BufWriter},
        os::unix::net::UnixStream,
    };

    use super::{DietMacAndCheeseConvProver, DietMacAndCheeseConvVerifier};

    // TODO: make test work without requiring feature `ff` for F384p, F384q

    pub(crate) const F2_VEC: [u8; 1] = [2];
    pub(crate) const F61P_VEC: [u8; 8] = [255, 255, 255, 255, 255, 255, 255, 31];
    #[allow(dead_code)]
    const F384P_VEC: [u8; 48] = [
        255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 254, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255,
    ];
    #[allow(dead_code)]
    const F384Q_VEC: [u8; 48] = [
        115, 41, 197, 204, 106, 25, 236, 236, 122, 167, 176, 72, 178, 13, 26, 88, 223, 45, 55, 244,
        129, 77, 99, 199, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    ];

    #[allow(dead_code)]
    const SECP256K1_VEC: [u8; 32] = [
        47, 252, 255, 255, 254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    ];

    #[allow(dead_code)]
    const SECP256K1ORDER_VEC: [u8; 32] = [
        65, 65, 54, 208, 140, 94, 210, 191, 59, 160, 72, 175, 230, 220, 174, 186, 254, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    ];

    pub(crate) const FF0: u8 = 0;
    const FF1: u8 = 1;
    #[allow(dead_code)]
    const FF2: u8 = 2;
    #[allow(dead_code)]
    const FF3: u8 = 3;

    pub(crate) fn into_vec<FE: FiniteField>(e: FE) -> Vec<u8> {
        e.to_bytes().to_vec()
    }

    pub(crate) fn zero<FE: FiniteField>() -> Vec<u8> {
        into_vec(FE::ZERO)
    }
    pub(crate) fn one<FE: FiniteField>() -> Vec<u8> {
        into_vec(FE::ONE)
    }
    fn two<FE: FiniteField>() -> Vec<u8> {
        into_vec(FE::ONE + FE::ONE)
    }
    pub(crate) fn minus_one<FE: FiniteField>() -> Vec<u8> {
        into_vec(-FE::ONE)
    }
    pub(crate) fn minus_two<FE: FiniteField>() -> Vec<u8> {
        into_vec(-(FE::ONE + FE::ONE))
    }
    fn three<FE: FiniteField>() -> Vec<u8> {
        into_vec(FE::ONE + FE::ONE + FE::ONE)
    }
    pub(crate) fn minus_three<FE: FiniteField>() -> Vec<u8> {
        into_vec(-(FE::ONE + FE::ONE + FE::ONE))
    }
    pub(crate) fn minus_four<FE: FiniteField>() -> Vec<u8> {
        into_vec(-(FE::ONE + FE::ONE + FE::ONE + FE::ONE))
    }
    fn minus_five<FE: FiniteField>() -> Vec<u8> {
        into_vec(-(FE::ONE + FE::ONE + FE::ONE + FE::ONE + FE::ONE))
    }
    fn minus_nine<FE: FiniteField>() -> Vec<u8> {
        into_vec(
            -(FE::ONE
                + FE::ONE
                + FE::ONE
                + FE::ONE
                + FE::ONE
                + FE::ONE
                + FE::ONE
                + FE::ONE
                + FE::ONE),
        )
    }

    fn wr(w: WireId) -> WireRange {
        (w, w)
    }

    #[allow(dead_code)]
    fn setup_logger() {
        // if log-level `RUST_LOG` not already set, then set to info
        match env::var("RUST_LOG") {
            Ok(val) => println!("loglvl: {}", val),
            Err(_) => env::set_var("RUST_LOG", "info"),
        };

        pretty_env_logger::init_timed();
    }

    pub(crate) fn test_circuit(
        fields: Vec<Vec<u8>>,
        func_store: FunStore,
        gates: Vec<GateM>,
        ins: Vec<Vec<Vec<u8>>>,
        wit: Vec<Vec<Vec<u8>>>,
    ) -> eyre::Result<()> {
        let func_store_prover = func_store.clone();
        let gates_prover = gates.clone();
        let ins_prover = ins.clone();
        let wit_prover = wit;
        let type_store = TypeStore::try_from(fields.clone())?;
        let type_store_prover = type_store.clone();
        let (sender, receiver) = UnixStream::pair()?;
        let handle: JoinHandle<eyre::Result<()>> = std::thread::spawn(move || {
            let rng = AesRng::from_seed(Default::default());
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);

            let mut inputs = CircInputs::default();

            for (id, inst) in ins_prover.iter().enumerate() {
                inputs.ingest_instances(id, VecDeque::from(inst.clone()));
            }

            for (id, w) in wit_prover.iter().enumerate() {
                inputs.ingest_witnesses(id, VecDeque::from(w.clone()));
            }

            let mut eval = EvaluatorCirc::new(
                Party::Prover,
                &mut channel,
                rng,
                inputs,
                type_store_prover,
                true,
                false,
            )?;
            eval.load_backends(&mut channel, true)?;
            eval.evaluate_gates(&gates_prover, &func_store_prover)?;
            eyre::Result::Ok(())
        });

        let rng = AesRng::from_seed(Default::default());
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);

        let mut inputs = CircInputs::default();

        for (id, inst) in ins.iter().enumerate() {
            inputs.ingest_instances(id, VecDeque::from(inst.clone()));
        }

        let mut eval = EvaluatorCirc::new(
            Party::Verifier,
            &mut channel,
            rng,
            inputs,
            type_store,
            true,
            false,
        )
        .unwrap();
        eval.load_backends(&mut channel, true)?;
        eval.evaluate_gates(&gates, &func_store)?;

        handle.join().unwrap()
    }

    fn test_conv_00() {
        // Test simple conversion from F61p to F2
        let fields = vec![F61P_VEC.to_vec(), F2_VEC.to_vec()];
        let func_store = FunStore::default();

        let gates = vec![
            GateM::Witness(FF0, 0),
            GateM::Witness(FF0, 1),
            GateM::Mul(FF0, 2, 0, 1),
            GateM::Conv(Box::new((FF1, wr(3), FF0, wr(2)))),
            GateM::AssertZero(FF1, 3),
        ];

        let instances = vec![vec![], vec![]];
        let witnesses = vec![vec![zero::<F61p>(), one::<F61p>()]];

        test_circuit(fields, func_store, gates, instances, witnesses).unwrap();
    }

    fn test_conv_01() {
        // Test simple conversion from F2 to F61p
        let fields = vec![F61P_VEC.to_vec(), F2_VEC.to_vec()];
        let func_store = FunStore::default();

        let gates = vec![
            GateM::Witness(FF1, 0),
            GateM::Witness(FF1, 1),
            GateM::Add(FF1, 2, 0, 1),
            GateM::Conv(Box::new((FF0, wr(3), FF1, wr(2)))),
            GateM::AddConstant(FF0, 4, 3, Box::from(minus_one::<F61p>())),
            GateM::AssertZero(FF0, 4),
        ];

        let instances = vec![vec![], vec![]];
        let witnesses = vec![vec![], vec![zero::<F2>(), one::<F2>()]];

        test_circuit(fields, func_store, gates, instances, witnesses).unwrap();
    }

    fn test_conv_02_twoway() {
        // Test that convert from F61p to F2 and from F2 to F61p works
        let fields = vec![F61P_VEC.to_vec(), F2_VEC.to_vec()];
        let func_store = FunStore::default();

        let gates = vec![
            GateM::Witness(FF0, 0),
            GateM::Witness(FF0, 1),
            GateM::Mul(FF0, 2, 0, 1),
            GateM::Conv(Box::new((FF1, wr(3), FF0, wr(2)))),
            GateM::AssertZero(FF1, 3),
            GateM::Witness(FF1, 4),
            GateM::Witness(FF1, 5),
            GateM::Add(FF1, 6, 5, 4),
            GateM::Conv(Box::new((FF0, wr(7), FF1, wr(6)))),
            GateM::AddConstant(FF0, 8, 7, Box::from(minus_one::<F61p>())),
            GateM::AssertZero(FF0, 8),
        ];

        let instances = vec![vec![], vec![]];
        let witnesses = vec![
            vec![zero::<F61p>(), one::<F61p>()],
            vec![zero::<F2>(), one::<F2>()],
        ];

        test_circuit(fields, func_store, gates, instances, witnesses).unwrap();
    }

    fn test_conv_binary_to_field() {
        // Test conversion from 2 bits to F61p
        let fields = vec![F61P_VEC.to_vec(), F2_VEC.to_vec()];
        let func_store = FunStore::default();

        let gates = vec![
            GateM::Witness(FF1, 0),
            GateM::Witness(FF1, 1),
            GateM::Conv(Box::new((FF0, wr(3), FF1, (0, 1)))),
            GateM::AddConstant(FF0, 4, 3, Box::from(minus_three::<F61p>())),
            GateM::AssertZero(FF0, 4),
        ];

        let instances = vec![vec![], vec![]];
        let witnesses = vec![vec![], vec![one::<F2>(), one::<F2>()]];

        test_circuit(fields, func_store, gates, instances, witnesses).unwrap();
    }

    fn test_conv_field_to_binary() {
        // Test conversion from F61p to a vec of F2
        // 3 bit decomposition is 11000 on 5 bits, 00011
        let fields = vec![F61P_VEC.to_vec(), F2_VEC.to_vec()];
        let func_store = FunStore::default();

        let gates = vec![
            GateM::Witness(FF0, 0),
            GateM::Conv(Box::new((FF1, (1, 5), FF0, wr(0)))),
            GateM::AssertZero(FF1, 1),
            GateM::AssertZero(FF1, 2),
            GateM::AssertZero(FF1, 3),
            GateM::AddConstant(FF1, 6, 4, Box::from(one::<F2>())),
            GateM::AddConstant(FF1, 7, 5, Box::from(one::<F2>())),
            GateM::AssertZero(FF1, 6),
            GateM::AssertZero(FF1, 7),
        ];

        let instances = vec![vec![], vec![]];
        let witnesses = vec![vec![three::<F61p>()], vec![]];

        test_circuit(fields, func_store, gates, instances, witnesses).unwrap();
    }

    fn test_conv_publics() {
        // Test conversion from F61p to a vec of F2 on public values
        let fields = vec![F61P_VEC.to_vec(), F2_VEC.to_vec()];
        let func_store = FunStore::default();

        let gates = vec![
            GateM::Instance(FF1, 0),
            GateM::Instance(FF1, 1),
            GateM::Instance(FF1, 2),
            GateM::Instance(FF1, 3),
            GateM::Conv(Box::new((FF0, wr(4), FF1, (0, 3)))),
            GateM::AddConstant(FF0, 5, 4, Box::from(minus_five::<F61p>())),
            GateM::AssertZero(FF0, 5),
        ];

        let instances = vec![
            vec![],
            vec![
                into_vec(F2::ZERO),
                into_vec(F2::ONE),
                into_vec(F2::ZERO),
                into_vec(F2::ONE),
            ],
        ];
        let witnesses = vec![vec![], vec![]];

        test_circuit(fields, func_store, gates, instances, witnesses).unwrap();
    }

    fn test_conv_shift() {
        // Test conversion and shift
        // 2 = 010000..., shifted as 10+010000...]= 10010000...] = 9, with truncation
        let fields = vec![F61P_VEC.to_vec(), F2_VEC.to_vec()];
        let func_store = FunStore::default();

        let mut gates = vec![
            GateM::New(FF0, 0, 0),
            GateM::Witness(FF0, 0),
            GateM::New(FF1, 1, 61),
            GateM::Conv(Box::new((FF1, (1, 61), FF0, wr(0)))),
            GateM::New(FF1, 62, 122),
        ];
        for i in 0..59 {
            gates.push(GateM::Copy(FF1, 62 + i, 1 + 2 + i));
        }
        gates.push(GateM::Constant(FF1, 121, Box::new(zero::<F2>())));
        gates.push(GateM::Constant(FF1, 122, Box::new(one::<F2>())));
        gates.push(GateM::New(FF0, 123, 124));
        gates.push(GateM::Conv(Box::new((FF0, wr(123), FF1, (100, 122))))); // Beware!! truncate here, but that's only the zero upper bits
        gates.push(GateM::AddConstant(
            FF0,
            124,
            123,
            Box::from(minus_nine::<F61p>()),
        ));
        gates.push(GateM::AssertZero(FF0, 124));

        let instances = vec![vec![], vec![]];
        let witnesses = vec![vec![two::<F61p>()], vec![]];

        test_circuit(fields, func_store, gates, instances, witnesses).unwrap();
    }

    #[cfg(feature = "ff")]
    fn test_conv_ff_1() {
        let fields = vec![
            F61P_VEC.to_vec(),
            F384P_VEC.to_vec(),
            F384Q_VEC.to_vec(),
            F2_VEC.to_vec(),
        ];
        let func_store = FunStore::default();

        let gates = vec![
            GateM::Witness(FF0, 0),
            GateM::Witness(FF0, 1),
            GateM::Mul(FF0, 2, 0, 1),
            GateM::Conv(Box::new((FF1, wr(3), FF0, wr(2)))),
            GateM::AssertZero(FF1, 3),
        ];

        let instances = vec![vec![], vec![], vec![], vec![]];
        let witnesses = vec![vec![zero::<F61p>(), one::<F61p>()], vec![], vec![], vec![]];

        test_circuit(fields, func_store, gates, instances, witnesses).unwrap();
    }

    #[cfg(feature = "ff")]
    fn test_conv_ff_2() {
        let fields = vec![
            F61P_VEC.to_vec(),
            F384P_VEC.to_vec(),
            F384Q_VEC.to_vec(),
            F2_VEC.to_vec(),
        ];
        let func_store = FunStore::default();

        let gates = vec![
            //GateM::New(FF3, 4, 4),
            //GateM::New(FF2, 5, 7),
            GateM::Witness(FF3, 4),
            GateM::Conv(Box::new((FF2, wr(5), FF3, wr(4)))),
            GateM::Constant(FF2, 6, Box::from(minus_one::<F384q>())),
            GateM::Add(FF2, 7, 5, 6),
            GateM::AssertZero(FF2, 7),
        ];

        let instances = vec![vec![], vec![], vec![], vec![]];
        let witnesses = vec![vec![], vec![], vec![], vec![one::<F2>()]];

        test_circuit(fields, func_store, gates, instances, witnesses).unwrap();
    }

    #[cfg(feature = "ff")]
    fn test_conv_ff_3() {
        // tests that conversions from big fields to bools
        let fields = vec![
            F61P_VEC.to_vec(),
            F384P_VEC.to_vec(),
            F384Q_VEC.to_vec(),
            F2_VEC.to_vec(),
        ];
        let func_store = FunStore::default();

        let gates = vec![
            GateM::Witness(FF2, 4),
            GateM::Conv(Box::new((FF3, wr(5), FF2, wr(4)))),
            GateM::Witness(FF1, 1),
            GateM::Conv(Box::new((FF3, wr(2), FF1, wr(1)))),
            GateM::Constant(FF3, 6, Box::from(minus_one::<F2>())),
            GateM::Add(FF3, 7, 5, 6),
            GateM::AssertZero(FF3, 7),
            GateM::AssertZero(FF3, 2),
        ];

        let instances = vec![vec![], vec![], vec![], vec![]];
        let witnesses = vec![
            vec![],
            vec![into_vec(F384p::ZERO)],
            vec![into_vec(F384q::ONE)],
            vec![],
        ];

        test_circuit(fields, func_store, gates, instances, witnesses).unwrap();
    }

    #[cfg(feature = "ff")]
    fn test_conv_ff_4() {
        // test conversion from large field to smaller field
        let fields = vec![F61P_VEC.to_vec(), F384P_VEC.to_vec()];
        let func_store = FunStore::default();

        let gates = vec![
            GateM::Witness(FF1, 0),
            GateM::Witness(FF1, 1),
            GateM::Mul(FF1, 2, 0, 1),
            GateM::Conv(Box::new((FF0, wr(3), FF1, wr(2)))),
            GateM::AssertZero(FF0, 3),
            GateM::Add(FF1, 3, 1, 1),
            GateM::Add(FF1, 4, 3, 1),
            GateM::Conv(Box::new((FF0, wr(5), FF1, wr(4)))),
            GateM::AddConstant(FF0, 6, 5, Box::from(minus_three::<F61p>())),
            GateM::AssertZero(FF0, 6),
        ];

        let instances = vec![vec![], vec![]];
        let witnesses = vec![vec![], vec![zero::<F61p>(), one::<F61p>()]];

        test_circuit(fields, func_store, gates, instances, witnesses).unwrap();
    }

    #[cfg(all(feature = "ff"))]
    fn test_conv_ff_5() {
        // tests that conversions from big fields secp
        let fields = vec![SECP256K1_VEC.to_vec(), SECP256K1ORDER_VEC.to_vec()];
        let func_store = FunStore::default();

        let gates = vec![
            GateM::Witness(FF0, 0),
            GateM::Conv(Box::new((FF1, wr(1), FF0, wr(0)))),
            GateM::Witness(FF1, 2),
            GateM::Conv(Box::new((FF0, wr(3), FF1, wr(2)))),
            GateM::Constant(FF1, 4, Box::from(zero::<Secp256k1order>())),
            GateM::Add(FF1, 5, 1, 4),
            GateM::AssertZero(FF1, 5),
            GateM::Constant(FF0, 6, Box::from(minus_one::<Secp256k1>())),
            GateM::Add(FF0, 7, 3, 6),
            GateM::AssertZero(FF0, 7),
        ];

        let instances = vec![vec![], vec![]];
        let witnesses = vec![
            vec![into_vec(Secp256k1::ZERO)],
            vec![into_vec(Secp256k1order::ONE)],
            vec![],
        ];

        test_circuit(fields, func_store, gates, instances, witnesses).unwrap();
    }

    fn test4_simple_fun() {
        // tests the simplest function

        let fields = vec![F61P_VEC.to_vec()];
        let mut func_store = FunStore::default();

        let gates_func = vec![GateM::Add(FF0, 0, 2, 4), GateM::Add(FF0, 1, 3, 5)];

        let mut func = FuncDecl::new_function(
            "myadd".into(),
            0,
            gates_func,
            vec![(FF0, 1), (FF0, 1)],
            vec![(FF0, 2), (FF0, 2)],
        );

        // The following instruction disable the vector optimization
        func.compiled_info.body_max = None;

        func_store.insert("myadd".into(), func);

        let gates = vec![
            GateM::New(FF0, 0, 7), // TODO: Test when not all the New is done
            GateM::Witness(FF0, 0),
            GateM::Witness(FF0, 1),
            GateM::Witness(FF0, 2),
            GateM::Witness(FF0, 3),
            GateM::Call(Box::new((
                "myadd".into(),
                vec![(4, 4), (5, 5)],
                vec![(0, 1), (2, 3)],
            ))),
            GateM::Add(FF0, 6, 4, 5),
            GateM::AddConstant(
                FF0,
                7,
                6,
                Box::from(into_vec(-(F61p::ONE + F61p::ONE + F61p::ONE + F61p::ONE))),
            ),
            GateM::AssertZero(FF0, 7),
        ];

        let one = one::<F61p>();
        let instances = vec![vec![], vec![], vec![], vec![]];
        let witnesses = vec![
            vec![one.clone(), one.clone(), one.clone(), one],
            vec![],
            vec![],
            vec![],
        ];

        test_circuit(fields, func_store, gates, instances, witnesses).unwrap();
    }

    fn test5_simple_fun_with_vec() {
        // tests the simplest function with vec

        let fields = vec![F61P_VEC.to_vec()];
        let mut func_store = FunStore::default();

        let gates_fun = vec![
            GateM::Add(FF0, 6, 2, 4),
            GateM::AddConstant(FF0, 0, 6, Box::from(zero::<F61p>())),
            GateM::Add(FF0, 1, 3, 5),
        ];

        let func = FuncDecl::new_function(
            "myadd".into(),
            0,
            gates_fun,
            vec![(FF0, 1), (FF0, 1)],
            vec![(FF0, 2), (FF0, 2)],
        );
        func_store.insert("myadd".into(), func);

        let gates = vec![
            GateM::New(FF0, 0, 7), // TODO: Test when not all the New is done
            GateM::Witness(FF0, 0),
            GateM::Witness(FF0, 1),
            GateM::Witness(FF0, 2),
            GateM::Witness(FF0, 3),
            GateM::Call(Box::new((
                "myadd".into(),
                vec![(4, 4), (5, 5)],
                vec![(0, 1), (2, 3)],
            ))),
            GateM::Add(FF0, 6, 4, 5),
            GateM::AddConstant(
                FF0,
                7,
                6,
                Box::from(into_vec(-(F61p::ONE + F61p::ONE + F61p::ONE + F61p::ONE))),
            ),
            GateM::AssertZero(FF0, 7),
        ];

        let one = one::<F61p>();
        let instances = vec![vec![], vec![], vec![], vec![]];
        let witnesses = vec![
            vec![one.clone(), one.clone(), one.clone(), one],
            vec![],
            vec![],
            vec![],
        ];

        test_circuit(fields, func_store, gates, instances, witnesses).unwrap();
    }

    fn test6_fun_slice_and_unallocated() {
        // tests a simple function passing instances in allocated slice and unallocated wire

        let fields = vec![F61P_VEC.to_vec()];
        let mut func_store = FunStore::default();

        let gates_func = vec![
            GateM::Copy(FF0, 0, 3),
            GateM::Add(FF0, 1, 4, 6),
            GateM::Copy(FF0, 2, 5),
        ];

        let mut func = FuncDecl::new_function(
            "myfun".into(),
            0,
            gates_func,
            vec![(FF0, 2), (FF0, 1)],
            vec![(FF0, 3), (FF0, 1)],
        );

        // The following instruction disable the vector optimization
        func.compiled_info.body_max = None;
        func_store.insert("myfun".into(), func);

        let two = into_vec(F61p::ONE + F61p::ONE);
        let minus_four = into_vec(-(F61p::ONE + F61p::ONE + F61p::ONE + F61p::ONE));
        let gates = vec![
            // New(0,2)
            // New(3,3)
            // Witness(0)  2
            // Witness(1)  2
            // Instance(2) 2
            // Witness(3)  2
            // 4..5, 6 <- Call(f, 0..2, 3)
            // AddConstant(7, 4, -2)
            // AddConstant(8, 5, -4)
            // AddConstant(9, 6, -2)
            // AssertZero(7)
            // AssertZero(8)
            // AssertZero(9)
            GateM::New(FF0, 0, 2),
            GateM::New(FF0, 3, 3),
            GateM::Witness(FF0, 0),
            GateM::Witness(FF0, 1),
            GateM::Instance(FF0, 2),
            GateM::Witness(FF0, 3),
            GateM::Call(Box::new((
                "myfun".into(),
                vec![(4, 5), (6, 6)],
                vec![(0, 2), (3, 3)],
            ))),
            GateM::AddConstant(FF0, 7, 4, Box::from(minus_two::<F61p>())),
            GateM::AddConstant(FF0, 8, 5, Box::from(minus_four)),
            GateM::AddConstant(FF0, 9, 6, Box::from(minus_two::<F61p>())),
            GateM::AssertZero(FF0, 7),
            GateM::AssertZero(FF0, 8),
            GateM::AssertZero(FF0, 9),
        ];

        let instances = vec![vec![two.clone()]];
        let witnesses = vec![vec![two.clone(), two.clone(), two]];

        test_circuit(fields, func_store, gates, instances, witnesses).unwrap();
    }

    fn test_less_eq_than_1() {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::from_seed(Default::default());
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);

            let fcom =
                FComProver::<F40b>::init(&mut channel, &mut rng, LPN_SETUP_SMALL, LPN_EXTEND_SMALL)
                    .unwrap();
            let rfcom = RcRefCell::new(fcom);

            let rng2 = AesRng::from_seed(Default::default());
            let mut party = DietMacAndCheeseConvProver::<F61p, _, _>::init(
                &mut channel,
                rng,
                rng2,
                &rfcom,
                LPN_SETUP_SMALL,
                LPN_EXTEND_SMALL,
                false,
            )
            .unwrap();
            let zero = party.dmc_f2.input_private(Some(F2::ZERO)).unwrap();
            let one = party.dmc_f2.input_private(Some(F2::ONE)).unwrap();

            party
                .less_eq_than_with_public2(vec![zero].as_slice(), vec![F2::ZERO].as_slice())
                .unwrap();
            party.dmc_f2.finalize().unwrap();
            party
                .less_eq_than_with_public2(vec![zero].as_slice(), vec![F2::ONE].as_slice())
                .unwrap();
            party.dmc_f2.finalize().unwrap();
            party
                .less_eq_than_with_public2(vec![one].as_slice(), vec![F2::ONE].as_slice())
                .unwrap();
            party.dmc_f2.finalize().unwrap();
            party
                .less_eq_than_with_public2(vec![one].as_slice(), vec![F2::ZERO].as_slice())
                .unwrap();
            let _ = party.dmc_f2.finalize().unwrap_err();
            party.dmc_f2.reset();

            party
                .less_eq_than_with_public2(vec![zero].as_slice(), vec![F2::ZERO].as_slice())
                .unwrap();
            party.dmc_f2.finalize().unwrap();

            party
                .less_eq_than_with_public2(
                    vec![one, one, zero].as_slice(),
                    vec![F2::ONE, F2::ONE, F2::ZERO].as_slice(),
                )
                .unwrap();
            party.dmc_f2.finalize().unwrap();

            party
                .less_eq_than_with_public2(
                    vec![one, one, one].as_slice(),
                    vec![F2::ONE, F2::ONE, F2::ZERO].as_slice(),
                )
                .unwrap();
            let _ = party.dmc_f2.finalize().unwrap_err();
            party.dmc_f2.reset();

            party
                .less_eq_than_with_public2(
                    vec![one, zero, zero].as_slice(),
                    vec![F2::ONE, F2::ZERO, F2::ONE].as_slice(),
                )
                .unwrap();
            party.dmc_f2.finalize().unwrap();

            party
                .less_eq_than_with_public2(
                    vec![one, one, one].as_slice(),
                    vec![F2::ONE, F2::ONE, F2::ONE].as_slice(),
                )
                .unwrap();
            party.dmc_f2.finalize().unwrap();

            party
                .less_eq_than_with_public2(
                    vec![one, zero, one, one].as_slice(),
                    vec![F2::ONE, F2::ZERO, F2::ZERO, F2::ONE].as_slice(),
                )
                .unwrap();
            let _ = party.dmc_f2.finalize().unwrap_err();
            party.dmc_f2.reset();

            // that's testing the little-endianness of the function
            party
                .less_eq_than_with_public2(
                    vec![one, one].as_slice(),
                    vec![F2::ZERO, F2::ONE].as_slice(),
                )
                .unwrap();
            let _ = party.dmc_f2.finalize().unwrap_err();
            party.dmc_f2.reset();
        });

        let mut rng = AesRng::from_seed(Default::default());
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);

        let fcom =
            FComVerifier::<F40b>::init(&mut channel, &mut rng, LPN_SETUP_SMALL, LPN_EXTEND_SMALL)
                .unwrap();
        let rfcom = RcRefCell::new(fcom);

        let rng2 = AesRng::from_seed(Default::default());
        let mut party = DietMacAndCheeseConvVerifier::<F61p, _, _>::init(
            &mut channel,
            rng,
            rng2,
            &rfcom,
            LPN_SETUP_SMALL,
            LPN_EXTEND_SMALL,
            false,
        )
        .unwrap();
        let zero = party.dmc_f2.input_private(None).unwrap();
        let one = party.dmc_f2.input_private(None).unwrap();

        party
            .less_eq_than_with_public2(vec![zero].as_slice(), vec![F2::ZERO].as_slice())
            .unwrap();
        party.dmc_f2.finalize().unwrap();
        party
            .less_eq_than_with_public2(vec![zero].as_slice(), vec![F2::ONE].as_slice())
            .unwrap();
        party.dmc_f2.finalize().unwrap();
        party
            .less_eq_than_with_public2(vec![one].as_slice(), vec![F2::ONE].as_slice())
            .unwrap();
        party.dmc_f2.finalize().unwrap();
        party
            .less_eq_than_with_public2(vec![one].as_slice(), vec![F2::ZERO].as_slice())
            .unwrap();
        let _ = party.dmc_f2.finalize().unwrap_err();
        party.dmc_f2.reset();

        party
            .less_eq_than_with_public2(vec![zero].as_slice(), vec![F2::ZERO].as_slice())
            .unwrap();
        party.dmc_f2.finalize().unwrap();

        party
            .less_eq_than_with_public2(
                vec![one, one, zero].as_slice(),
                vec![F2::ONE, F2::ONE, F2::ZERO].as_slice(),
            )
            .unwrap();
        party.dmc_f2.finalize().unwrap();

        party
            .less_eq_than_with_public2(
                vec![one, one, one].as_slice(),
                vec![F2::ONE, F2::ONE, F2::ZERO].as_slice(),
            )
            .unwrap();
        let _ = party.dmc_f2.finalize().unwrap_err();
        party.dmc_f2.reset();

        party
            .less_eq_than_with_public2(
                vec![one, zero, zero].as_slice(),
                vec![F2::ONE, F2::ZERO, F2::ONE].as_slice(),
            )
            .unwrap();
        party.dmc_f2.finalize().unwrap();

        party
            .less_eq_than_with_public2(
                vec![one, one, one].as_slice(),
                vec![F2::ONE, F2::ONE, F2::ONE].as_slice(),
            )
            .unwrap();
        party.dmc_f2.finalize().unwrap();

        party
            .less_eq_than_with_public2(
                vec![one, zero, one, one].as_slice(),
                vec![F2::ONE, F2::ZERO, F2::ZERO, F2::ONE].as_slice(),
            )
            .unwrap();
        let _ = party.dmc_f2.finalize().unwrap_err();
        party.dmc_f2.reset();

        // that's testing the little-endianness of the function
        party
            .less_eq_than_with_public2(
                vec![one, one].as_slice(),
                vec![F2::ZERO, F2::ONE].as_slice(),
            )
            .unwrap();
        let _ = party.dmc_f2.finalize().unwrap_err();
        party.dmc_f2.reset();

        handle.join().unwrap();
    }

    #[test]
    fn test_multifield_conv() {
        test_conv_00();
        test_conv_01();
        test_conv_02_twoway();
        test_conv_binary_to_field();
        test_conv_field_to_binary();
        test_conv_publics();
        test_conv_shift();
    }

    #[test]
    #[cfg(feature = "ff")]
    fn test_multifield_ff() {
        test_conv_ff_1();
        test_conv_ff_2();
        test_conv_ff_3();
        test_conv_ff_4();
    }

    #[test]
    #[cfg(all(feature = "ff"))]
    fn test_multifield_ff_secp256() {
        test_conv_ff_5();
    }

    #[test]
    fn test_func() {
        test4_simple_fun();
        test5_simple_fun_with_vec();
        test6_fun_slice_and_unallocated()
    }

    #[test]
    fn test_less_eq_than_circuit() {
        test_less_eq_than_1();
    }
}
