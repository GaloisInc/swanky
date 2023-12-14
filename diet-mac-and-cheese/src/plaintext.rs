use crate::{
    backend::Monitor,
    backend_multifield::{BackendConvT, BackendDisjunctionT, BackendLiftT},
    backend_trait::BackendT,
    mac::{Mac, MacT},
    plugins::DisjunctionBody,
};
use eyre::{bail, Result};
use generic_array::GenericArray;
use scuttlebutt::AesRng;
use std::marker::PhantomData;
use swanky_field::{DegreeModulo, FiniteField, FiniteRing, IsSubFieldOf, PrimeFiniteField};
use swanky_field_binary::{F40b, F2};
use swanky_party::{private::ProverPrivateCopy, Party, WhichParty};

pub struct DietMacAndCheesePlaintext<V: IsSubFieldOf<T>, T: FiniteField> {
    rng: AesRng,
    monitor: Monitor<V>,
    phantom: PhantomData<T>,
}

impl<V: IsSubFieldOf<T>, T: FiniteField> DietMacAndCheesePlaintext<V, T> {
    pub fn new() -> Result<Self> {
        Ok(Self {
            rng: Default::default(),
            monitor: Monitor::default(),
            phantom: Default::default(),
        })
    }
}

#[derive(Debug, Default, Copy, Clone)]
pub struct WirePlaintext<V: IsSubFieldOf<T>, T: FiniteField>(V, PhantomData<T>);

impl<V: IsSubFieldOf<T>, T: FiniteField> MacT for WirePlaintext<V, T> {
    type Value = V;
    type Tag = T;
    type LiftedMac = WirePlaintext<T, T>;
    fn lift(_xs: &GenericArray<Self, DegreeModulo<Self::Value, Self::Tag>>) -> Self::LiftedMac {
        unimplemented!()
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

impl<V: IsSubFieldOf<T>, T: FiniteField> BackendLiftT for DietMacAndCheesePlaintext<V, T>
where
    T::PrimeField: IsSubFieldOf<T>,
    <T as FiniteField>::PrimeField: IsSubFieldOf<V>,
{
    type LiftedBackend = DietMacAndCheesePlaintext<T, T>;

    fn lift(&mut self) -> &mut Self::LiftedBackend {
        unimplemented!()
    }
}

impl BackendDisjunctionT for DietMacAndCheesePlaintext<F2, F40b> {
    fn disjunction(
        &mut self,
        _inputs: &[Self::Wire],
        _disj: &DisjunctionBody,
    ) -> Result<Vec<Self::Wire>> {
        unimplemented!("disjunction plugin is not sound for GF(2)")
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
        unimplemented!("disjunction plugin is not sound for GF(2)")
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
                    let bmac = Mac::new(ProverPrivateCopy::new(b2), F40b::ZERO);
                    v.push(bmac);
                }
            }
            WhichParty::Verifier(_) => {
                panic!(
                    "calling plaintext evaluator conversion on a Verifier party instead of Prover"
                );
            }
        }
        Ok(v)
    }

    fn assert_conv_from_bits(&mut self, x: &[Mac<P, F2, F40b>]) -> Result<Self::Wire> {
        let mut power_twos = ProverPrivateCopy::new(F::ONE);
        let mut recomposed_value = ProverPrivateCopy::new(F::ZERO);

        let mut bits = Vec::with_capacity(x.len());

        for m in x {
            if let WhichParty::Prover(ev) = P::WHICH {
                *recomposed_value.as_mut().into_inner(ev) += (if m.value().into_inner(ev) == F2::ONE
                {
                    F::ONE
                } else {
                    F::ZERO
                }) * power_twos.into_inner(ev);
                power_twos
                    .as_mut()
                    .map(|power_twos| *power_twos += *power_twos);
            }

            bits.push(*m);
        }

        let mac = self.input_private(match P::WHICH {
            WhichParty::Prover(ev) => Some(recomposed_value.into_inner(ev)),
            WhichParty::Verifier(_) => None,
        })?;

        Ok(mac)
    }

    fn finalize_conv(&mut self) -> Result<()> {
        Ok(())
    }
}
