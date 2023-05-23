#![allow(clippy::clone_on_copy)]

/*!
Backend trait.

*/
use crate::error::Error::BackendError;
use crate::error::Result;
use crate::{
    backend::{from_bytes_le, DietMacAndCheeseProver, DietMacAndCheeseVerifier},
    homcom::{MacProver, MacVerifier},
};
use rand::{CryptoRng, Rng};
use scuttlebutt::ring::FiniteRing;
use scuttlebutt::{field::FiniteField, AbstractChannel};

/// Trait providing an interface for basic gates.
///
/// This `BackendT` trait is inspired from `ZKBackend` in zkinterface.
pub trait BackendT {
    type Wire;
    type FieldElement: FiniteField;

    fn from_bytes_le(val: &[u8]) -> Result<Self::FieldElement>;
    fn set_field(&mut self, modulus: &[u8], degree: u32, is_boolean: bool) -> Result<()>;
    fn one(&self) -> Result<Self::FieldElement>;
    fn zero(&self) -> Result<Self::FieldElement>;
    fn copy(&mut self, wire: &Self::Wire) -> Result<Self::Wire>;

    fn constant(&mut self, val: Self::FieldElement) -> Result<Self::Wire>;
    fn assert_zero(&mut self, wire: &Self::Wire) -> Result<()>;

    fn add(&mut self, a: &Self::Wire, b: &Self::Wire) -> Result<Self::Wire>;
    fn mul(&mut self, a: &Self::Wire, b: &Self::Wire) -> Result<Self::Wire>;
    fn add_constant(&mut self, a: &Self::Wire, b: Self::FieldElement) -> Result<Self::Wire>;
    fn mul_constant(&mut self, a: &Self::Wire, b: Self::FieldElement) -> Result<Self::Wire>;

    fn input_public(&mut self, val: Self::FieldElement) -> Result<Self::Wire>;
    fn input_private(&mut self, val: Option<Self::FieldElement>) -> Result<Self::Wire>;

    fn finalize(&mut self) -> Result<()>;
    fn reset(&mut self);
}

impl<FE: FiniteField, C: AbstractChannel, RNG: CryptoRng + Rng> BackendT
    for DietMacAndCheeseProver<FE, C, RNG>
{
    type Wire = MacProver<FE>;

    type FieldElement = FE::PrimeField;

    fn from_bytes_le(val: &[u8]) -> Result<Self::FieldElement> {
        from_bytes_le(val)
    }

    fn set_field(&mut self, _modulus: &[u8], _degree: u32, _is_boolean: bool) -> Result<()> {
        Ok(())
    }

    fn copy(&mut self, wire: &Self::Wire) -> Result<Self::Wire> {
        Ok(wire.clone())
    }

    fn one(&self) -> Result<Self::FieldElement> {
        Ok(Self::FieldElement::ONE)
    }

    fn zero(&self) -> Result<Self::FieldElement> {
        Ok(Self::FieldElement::ZERO)
    }

    fn constant(&mut self, val: Self::FieldElement) -> Result<Self::Wire> {
        Ok(self.input_public(val))
    }

    fn assert_zero(&mut self, wire: &Self::Wire) -> Result<()> {
        self.assert_zero(wire)
    }

    fn add(&mut self, a: &Self::Wire, b: &Self::Wire) -> Result<Self::Wire> {
        self.add(a, b)
    }

    fn mul(&mut self, a: &Self::Wire, b: &Self::Wire) -> Result<Self::Wire> {
        self.mul(a, b)
    }

    fn add_constant(&mut self, a: &Self::Wire, b: Self::FieldElement) -> Result<Self::Wire> {
        self.addc(a, b)
    }

    fn mul_constant(&mut self, a: &Self::Wire, b: Self::FieldElement) -> Result<Self::Wire> {
        self.mulc(a, b)
    }

    fn input_public(&mut self, val: Self::FieldElement) -> Result<Self::Wire> {
        Ok(self.input_public(val))
    }

    fn input_private(&mut self, val: Option<Self::FieldElement>) -> Result<Self::Wire> {
        if val.is_none() {
            return Err(BackendError("Should be some".into()));
        }

        self.input_private(val.unwrap())
    }

    fn finalize(&mut self) -> Result<()> {
        self.finalize()
    }
    fn reset(&mut self) {
        self.reset();
    }
}

impl<FE: FiniteField, C: AbstractChannel, RNG: CryptoRng + Rng> BackendT
    for DietMacAndCheeseVerifier<FE, C, RNG>
{
    type Wire = MacVerifier<FE>;

    type FieldElement = FE::PrimeField;

    fn from_bytes_le(val: &[u8]) -> Result<Self::FieldElement> {
        from_bytes_le(val)
    }

    fn set_field(&mut self, _modulus: &[u8], _degree: u32, _is_boolean: bool) -> Result<()> {
        Ok(())
    }

    fn copy(&mut self, wire: &Self::Wire) -> Result<Self::Wire> {
        Ok(wire.clone())
    }

    fn one(&self) -> Result<Self::FieldElement> {
        Ok(Self::FieldElement::ONE)
    }

    fn zero(&self) -> Result<Self::FieldElement> {
        Ok(Self::FieldElement::ZERO)
    }

    fn constant(&mut self, val: Self::FieldElement) -> Result<Self::Wire> {
        Ok(self.input_public(val))
    }

    fn assert_zero(&mut self, wire: &Self::Wire) -> Result<()> {
        self.assert_zero(wire)
    }

    fn add(&mut self, a: &Self::Wire, b: &Self::Wire) -> Result<Self::Wire> {
        self.add(a, b)
    }

    fn mul(&mut self, a: &Self::Wire, b: &Self::Wire) -> Result<Self::Wire> {
        self.mul(a, b)
    }

    fn add_constant(&mut self, a: &Self::Wire, b: Self::FieldElement) -> Result<Self::Wire> {
        self.addc(a, b)
    }

    fn mul_constant(&mut self, a: &Self::Wire, b: Self::FieldElement) -> Result<Self::Wire> {
        self.mulc(a, b)
    }

    fn input_public(&mut self, val: Self::FieldElement) -> Result<Self::Wire> {
        Ok(self.input_public(val))
    }

    fn input_private(&mut self, val: Option<Self::FieldElement>) -> Result<Self::Wire> {
        if val.is_some() {
            return Err(BackendError("Should be none".into()));
        }

        self.input_private()
    }
    fn finalize(&mut self) -> Result<()> {
        self.finalize()
    }
    fn reset(&mut self) {
        self.reset();
    }
}
