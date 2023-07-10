//! Implementation of [`ZKBackend`] for [`DietMacAndCheeseProver`] and
//! [`DietMacAndCheeseVerifier`].

use crate::homcom::{MacProver, MacVerifier};
use crate::{
    backend::{from_bytes_le, DietMacAndCheeseProver, DietMacAndCheeseVerifier},
    backend_trait::BackendT,
};
use eyre::Result;
use scuttlebutt::ring::FiniteRing;
use scuttlebutt::{field::FiniteField, AbstractChannel};
use zki_sieve::consumers::evaluator::ZKBackend;
use zki_sieve::Result as ZkiResult;

fn convert<T>(v: Result<T>) -> ZkiResult<T> {
    v.map_err(|e| e.into())
}

impl<FE: FiniteField, C: AbstractChannel> ZKBackend for DietMacAndCheeseProver<FE, C> {
    type Wire = MacProver<FE>;
    type FieldElement = FE::PrimeField;

    fn from_bytes_le(val: &[u8]) -> ZkiResult<Self::FieldElement> {
        convert(from_bytes_le(val))
    }

    fn set_field(&mut self, _modulus: &[u8], _degree: u32, _is_boolean: bool) -> ZkiResult<()> {
        Ok(())
    }

    fn copy(&mut self, wire: &Self::Wire) -> ZkiResult<Self::Wire> {
        Ok(wire.clone())
    }

    fn one(&self) -> ZkiResult<Self::FieldElement> {
        Ok(FE::PrimeField::ONE)
    }

    fn minus_one(&self) -> ZkiResult<Self::FieldElement> {
        Ok(-FE::PrimeField::ONE)
    }

    fn zero(&self) -> ZkiResult<Self::FieldElement> {
        Ok(FE::PrimeField::ZERO)
    }

    fn constant(&mut self, val: Self::FieldElement) -> ZkiResult<Self::Wire> {
        convert(self.input_public(val))
    }

    fn assert_zero(&mut self, wire: &Self::Wire) -> ZkiResult<()> {
        convert(BackendT::assert_zero(self, wire))
    }

    fn add(&mut self, a: &Self::Wire, b: &Self::Wire) -> ZkiResult<Self::Wire> {
        convert(BackendT::add(self, a, b))
    }

    fn multiply(&mut self, a: &Self::Wire, b: &Self::Wire) -> ZkiResult<Self::Wire> {
        convert(self.mul(a, b))
    }

    fn add_constant(&mut self, a: &Self::Wire, b: Self::FieldElement) -> ZkiResult<Self::Wire> {
        convert(BackendT::add_constant(self, a, b))
    }

    fn mul_constant(&mut self, a: &Self::Wire, b: Self::FieldElement) -> ZkiResult<Self::Wire> {
        convert(BackendT::mul_constant(self, a, b))
    }

    fn and(&mut self, a: &Self::Wire, b: &Self::Wire) -> ZkiResult<Self::Wire> {
        convert(self.mul(a, b))
    }

    fn xor(&mut self, a: &Self::Wire, b: &Self::Wire) -> ZkiResult<Self::Wire> {
        convert(BackendT::add(self, a, b))
    }

    fn not(&mut self, a: &Self::Wire) -> ZkiResult<Self::Wire> {
        convert(BackendT::add_constant(self, a, Self::FieldElement::ONE))
    }

    fn instance(&mut self, val: Self::FieldElement) -> ZkiResult<Self::Wire> {
        convert(self.input_public(val))
    }

    fn witness(&mut self, val: Option<Self::FieldElement>) -> ZkiResult<Self::Wire> {
        convert(self.input_private(val))
    }
}

impl<FE: FiniteField, C: AbstractChannel> ZKBackend for DietMacAndCheeseVerifier<FE, C> {
    type Wire = MacVerifier<FE>;
    type FieldElement = FE::PrimeField;

    fn from_bytes_le(val: &[u8]) -> ZkiResult<Self::FieldElement> {
        convert(from_bytes_le(val))
    }

    fn set_field(&mut self, _modulus: &[u8], _degree: u32, _is_boolean: bool) -> ZkiResult<()> {
        Ok(())
    }

    fn copy(&mut self, wire: &Self::Wire) -> ZkiResult<Self::Wire> {
        Ok(wire.clone())
    }

    fn one(&self) -> ZkiResult<Self::FieldElement> {
        Ok(FE::PrimeField::ONE)
    }

    fn minus_one(&self) -> ZkiResult<Self::FieldElement> {
        Ok(-FE::PrimeField::ONE)
    }

    fn zero(&self) -> ZkiResult<Self::FieldElement> {
        Ok(FE::PrimeField::ZERO)
    }

    fn constant(&mut self, val: Self::FieldElement) -> ZkiResult<Self::Wire> {
        convert(self.input_public(val))
    }

    fn assert_zero(&mut self, wire: &Self::Wire) -> ZkiResult<()> {
        convert(BackendT::assert_zero(self, wire))
    }

    fn add(&mut self, a: &Self::Wire, b: &Self::Wire) -> ZkiResult<Self::Wire> {
        convert(BackendT::add(self, a, b))
    }

    fn multiply(&mut self, a: &Self::Wire, b: &Self::Wire) -> ZkiResult<Self::Wire> {
        convert(self.mul(a, b))
    }

    fn add_constant(&mut self, a: &Self::Wire, b: Self::FieldElement) -> ZkiResult<Self::Wire> {
        convert(BackendT::add_constant(self, a, b))
    }

    fn mul_constant(&mut self, a: &Self::Wire, b: Self::FieldElement) -> ZkiResult<Self::Wire> {
        convert(BackendT::mul_constant(self, a, b))
    }

    fn and(&mut self, a: &Self::Wire, b: &Self::Wire) -> ZkiResult<Self::Wire> {
        convert(self.mul(a, b))
    }

    fn xor(&mut self, a: &Self::Wire, b: &Self::Wire) -> ZkiResult<Self::Wire> {
        convert(BackendT::add(self, a, b))
    }

    fn not(&mut self, a: &Self::Wire) -> ZkiResult<Self::Wire> {
        convert(BackendT::add_constant(self, a, Self::FieldElement::ONE))
    }

    fn instance(&mut self, val: Self::FieldElement) -> ZkiResult<Self::Wire> {
        convert(self.input_public(val))
    }

    fn witness(&mut self, val: Option<Self::FieldElement>) -> ZkiResult<Self::Wire> {
        convert(BackendT::input_private(self, val))
    }
}
