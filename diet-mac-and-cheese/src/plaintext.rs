//! Plaintext backend.

use crate::{
    backend::Monitor,
    backend_multifield::{BackendConvT, BackendDisjunctionT, BackendLiftT},
    backend_trait::BackendT,
    mac::{make_x_i, Mac, MacT},
    plugins::DisjunctionBody,
};
use eyre::{bail, Result};
use generic_array::GenericArray;
use scuttlebutt::AesRng;
use std::marker::PhantomData;
use swanky_field::{DegreeModulo, FiniteField, FiniteRing, IsSubFieldOf, PrimeFiniteField};
use swanky_field_binary::{F40b, F2};
use swanky_party::{private::ProverPrivateCopy, Party, WhichParty};

// This file provides an implementation of the Plaintext backend.
// `DietMacAndCheePlaintext<V,T>` is the main struct for this backend.
// It may be instantiated for any supported field <V> with its associated tag field <T>.
// Note that for the plaintext evaluator the tag field is usually ignored but a necessity to satisfy the
// current architecture focusing on the ZK backend based on VOLE.
// The struct `DietMacAndCheePlaintext<V,T>` implements the following traits (necessary for toplevel multifield evaluator `EvaluatorCirc`):
//   * `BackendT` for the basic gates functions add/mul/check_zero etc.
//   * `BackendConvT` for converting functions from the field to binary
//   * `BackendLiftT` for lifting values to the tag field
//   * `BackendDisjT`, not supported
//
// Another key structure is `WirePlaintext<V, T>` that holds a `V` value and phatom second value for `T`.

pub(crate) struct DietMacAndCheesePlaintext<V: IsSubFieldOf<T>, T: FiniteField> {
    // The random generator is necessary for the random gate
    rng: AesRng,
    // This optional backend is for the extension field associated to the binary field.
    // It is necessary for lifting `F2` values to its tag extension field `F40b`.
    extfield_backend: Option<Box<DietMacAndCheesePlaintext<F40b, F40b>>>,
    // Monitor gates
    monitor: Monitor<V>,
    // The Tag field is not used
    phantom: PhantomData<T>,
}

impl<V: IsSubFieldOf<T>, T: FiniteField> DietMacAndCheesePlaintext<V, T> {
    pub(crate) fn new() -> Result<Self> {
        Ok(Self {
            rng: Default::default(),
            extfield_backend: None,
            monitor: Monitor::default(),
            phantom: Default::default(),
        })
    }

    /// For the `F2` boolean backend this function stores the extension field backend.
    pub(crate) fn set_extfield_backend(&mut self, b: DietMacAndCheesePlaintext<F40b, F40b>) {
        self.extfield_backend = Some(Box::new(b));
    }
}

#[derive(Debug, Default, Copy, Clone)]
pub(crate) struct WirePlaintext<V: IsSubFieldOf<T>, T: FiniteField>(V, PhantomData<T>);

impl<V: IsSubFieldOf<T>, T: FiniteField> MacT for WirePlaintext<V, T> {
    type Value = V;
    type Tag = T;
    type LiftedMac = WirePlaintext<T, T>;
    fn lift(xs: &GenericArray<Self, DegreeModulo<Self::Value, Self::Tag>>) -> Self::LiftedMac {
        let mut value = T::ZERO;
        for (i, x) in xs.iter().enumerate() {
            let x_i: T = make_x_i::<V, T>(i);
            value += x.0 * x_i;
        }
        WirePlaintext(value, PhantomData)
    }
}

impl<V: IsSubFieldOf<T>, T: FiniteField> WirePlaintext<V, T> {
    fn new(v: V) -> Self {
        Self(v, PhantomData)
    }
}

impl<V: IsSubFieldOf<T>, T: FiniteField> BackendT for DietMacAndCheesePlaintext<V, T>
where
    T::PrimeField: IsSubFieldOf<V>,
{
    type Wire = WirePlaintext<V, T>;
    type FieldElement = V;

    fn wire_value(&self, wire: &Self::Wire) -> Option<Self::FieldElement> {
        Some(wire.0)
    }

    fn copy(&mut self, wire: &Self::Wire) -> Result<Self::Wire> {
        Ok(*wire)
    }

    fn random(&mut self) -> Result<Self::FieldElement> {
        Ok(Self::FieldElement::random(&mut self.rng))
    }

    fn one(&self) -> Result<Self::FieldElement> {
        Ok(Self::FieldElement::ONE)
    }

    fn zero(&self) -> Result<Self::FieldElement> {
        Ok(Self::FieldElement::ZERO)
    }

    fn constant(&mut self, val: Self::FieldElement) -> Result<Self::Wire> {
        self.input_public(val)
    }

    fn assert_zero(&mut self, wire: &Self::Wire) -> Result<()> {
        self.monitor.incr_monitor_check_zero();
        if wire.0 == Self::FieldElement::ZERO {
            Ok(())
        } else {
            bail!("Error assert_zero")
        }
    }

    fn add(&mut self, a: &Self::Wire, b: &Self::Wire) -> Result<Self::Wire> {
        self.monitor.incr_monitor_add();
        Ok(WirePlaintext::new(a.0 + b.0))
    }

    fn sub(&mut self, a: &Self::Wire, b: &Self::Wire) -> Result<Self::Wire> {
        self.monitor.incr_monitor_sub();
        Ok(WirePlaintext::new(a.0 - b.0))
    }

    fn mul(&mut self, a: &Self::Wire, b: &Self::Wire) -> Result<Self::Wire> {
        self.monitor.incr_monitor_mul();
        Ok(WirePlaintext::new(a.0 * b.0))
    }

    fn add_constant(&mut self, a: &Self::Wire, b: Self::FieldElement) -> Result<Self::Wire> {
        self.monitor.incr_monitor_addc();
        Ok(WirePlaintext::new(b + a.0))
    }

    fn mul_constant(&mut self, a: &Self::Wire, b: Self::FieldElement) -> Result<Self::Wire> {
        self.monitor.incr_monitor_mulc();
        Ok(WirePlaintext::new(b * a.0))
    }

    fn input_public(&mut self, val: Self::FieldElement) -> Result<Self::Wire> {
        self.monitor.incr_monitor_instance();
        Ok(WirePlaintext::new(val))
    }

    fn input_private(&mut self, val: Option<Self::FieldElement>) -> Result<Self::Wire> {
        self.monitor.incr_monitor_witness();
        Ok(WirePlaintext::new(val.unwrap()))
    }

    fn finalize(&mut self) -> Result<()> {
        self.monitor.log_final_monitor();
        Ok(())
    }
}

impl BackendLiftT for DietMacAndCheesePlaintext<F2, F40b> {
    type LiftedBackend = DietMacAndCheesePlaintext<F40b, F40b>;

    fn lift(&mut self) -> &mut Self::LiftedBackend {
        if self.extfield_backend.is_some() {
            return self.extfield_backend.as_mut().unwrap();
        } else {
            unimplemented!()
        }
    }
}

impl<F: PrimeFiniteField> BackendLiftT for DietMacAndCheesePlaintext<F, F> {
    type LiftedBackend = DietMacAndCheesePlaintext<F, F>;

    fn lift(&mut self) -> &mut Self::LiftedBackend {
        self
    }
}

impl BackendDisjunctionT for DietMacAndCheesePlaintext<F2, F40b> {
    fn disjunction(
        &mut self,
        _inputs: &[Self::Wire],
        _disj: &DisjunctionBody,
    ) -> Result<Vec<Self::Wire>> {
        unimplemented!("The plaintext backend does not support the disjunction plugin")
    }

    fn finalize_disj(&mut self) -> Result<()> {
        Ok(())
    }
}

impl<F: PrimeFiniteField> BackendDisjunctionT for DietMacAndCheesePlaintext<F, F> {
    fn disjunction(
        &mut self,
        _inputs: &[Self::Wire],
        _disj: &DisjunctionBody,
    ) -> Result<Vec<Self::Wire>> {
        unimplemented!("The plaintext backend does not support the disjunction plugin")
    }

    fn finalize_disj(&mut self) -> Result<()> {
        Ok(())
    }
}

impl<P: Party> BackendConvT<P> for DietMacAndCheesePlaintext<F2, F40b> {
    fn assert_conv_to_bits(&mut self, w: &Self::Wire) -> Result<Vec<Mac<P, F2, F40b>>> {
        match P::WHICH {
            WhichParty::Prover(_) => {
                let bmac = Mac::new(ProverPrivateCopy::new(w.0), F40b::ZERO);
                Ok(vec![bmac])
            }
            WhichParty::Verifier(_) => {
                panic!(
                    "calling plaintext evaluator conversion to bits on a Verifier party instead of Prover"
                );
            }
        }
    }

    fn assert_conv_from_bits(&mut self, x: &[Mac<P, F2, F40b>]) -> Result<Self::Wire> {
        match P::WHICH {
            WhichParty::Prover(ev) => Ok(WirePlaintext::new(x[0].value().into_inner(ev))),
            WhichParty::Verifier(_) => {
                panic!(
                    "calling plaintext evaluator conversion from bits on a Verifier party instead of Prover"
                );
            }
        }
    }

    fn finalize_conv(&mut self) -> Result<()> {
        Ok(())
    }
}

impl<P: Party, F: PrimeFiniteField> BackendConvT<P> for DietMacAndCheesePlaintext<F, F> {
    fn assert_conv_to_bits(&mut self, w: &Self::Wire) -> Result<Vec<Mac<P, F2, F40b>>> {
        let mut v;
        let bits = w.0.bit_decomposition();
        match P::WHICH {
            WhichParty::Prover(_) => {
                v = Vec::with_capacity(bits.len());
                for b in bits {
                    let b2 = F2::from(b);
                    let dummy_tag = F40b::ZERO;
                    let bmac = Mac::new(ProverPrivateCopy::new(b2), dummy_tag);
                    v.push(bmac);
                }
            }
            WhichParty::Verifier(_) => {
                panic!(
                    "calling plaintext evaluator conversion to bits on a Verifier party instead of Prover"
                );
            }
        }
        Ok(v)
    }

    fn assert_conv_from_bits(&mut self, x: &[Mac<P, F2, F40b>]) -> Result<Self::Wire> {
        let mut power_twos = F::ONE;
        let mut recomposed_value = F::ZERO;

        if let WhichParty::Prover(ev) = P::WHICH {
            for m in x {
                recomposed_value += (if m.value().into_inner(ev) == F2::ONE {
                    F::ONE
                } else {
                    F::ZERO
                }) * power_twos;
                power_twos += power_twos;
            }
        } else {
            panic!(
                "calling plaintext evaluator conversion from bits on a Verifier party instead of Prover"
            );
        }

        let mac = self.input_private(Some(recomposed_value))?; // `Some` because the plaintext is the prover.

        Ok(mac)
    }

    fn finalize_conv(&mut self) -> Result<()> {
        Ok(())
    }
}
