/*!
Implementation of ZKInterface `ZKBackend` trait.

*/

use crate::backend::{
    from_bytes_le, DietMacAndCheeseProver, DietMacAndCheeseVerifier, ValueProver, ValueVerifier,
};
use crate::error::Result as BResult;
use rand::{CryptoRng, Rng};
use scuttlebutt::ring::FiniteRing;
use scuttlebutt::{field::FiniteField, AbstractChannel};
use zki_sieve::consumers::evaluator::ZKBackend;
use zki_sieve::Result as ZkiResult;

fn convert<T>(v: BResult<T>) -> ZkiResult<T> {
    match v {
        BResult::Ok(x) => Ok(x),
        BResult::Err(err) => Err(err.into()),
    }
}

impl<FE: FiniteField, C: AbstractChannel, RNG: CryptoRng + Rng> ZKBackend
    for DietMacAndCheeseProver<FE, C, RNG>
{
    type Wire = ValueProver<FE>;

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
        Ok(self.input_public(val))
    }

    fn assert_zero(&mut self, wire: &Self::Wire) -> ZkiResult<()> {
        convert(self.assert_zero(wire))
    }

    fn add(&mut self, a: &Self::Wire, b: &Self::Wire) -> ZkiResult<Self::Wire> {
        convert(self.add(a, b))
    }

    fn multiply(&mut self, a: &Self::Wire, b: &Self::Wire) -> ZkiResult<Self::Wire> {
        convert(self.mul(a, b))
    }

    fn add_constant(&mut self, a: &Self::Wire, b: Self::FieldElement) -> ZkiResult<Self::Wire> {
        convert(self.addc(a, b))
    }

    fn mul_constant(&mut self, a: &Self::Wire, b: Self::FieldElement) -> ZkiResult<Self::Wire> {
        convert(self.mulc(a, b))
    }

    fn and(&mut self, a: &Self::Wire, b: &Self::Wire) -> ZkiResult<Self::Wire> {
        convert(self.mul(a, b))
    }

    fn xor(&mut self, a: &Self::Wire, b: &Self::Wire) -> ZkiResult<Self::Wire> {
        convert(self.add(a, b))
    }

    fn not(&mut self, a: &Self::Wire) -> ZkiResult<Self::Wire> {
        convert(self.addc(a, Self::FieldElement::ONE))
    }

    fn instance(&mut self, val: Self::FieldElement) -> ZkiResult<Self::Wire> {
        Ok(self.input_public(val))
    }

    fn witness(&mut self, val: Option<Self::FieldElement>) -> ZkiResult<Self::Wire> {
        if val.is_none() {
            return Err("Should be some".into());
        }

        convert(self.input_private(val.unwrap()))
    }
}

impl<FE: FiniteField, C: AbstractChannel, RNG: CryptoRng + Rng + Clone> ZKBackend
    for DietMacAndCheeseVerifier<FE, C, RNG>
{
    type Wire = ValueVerifier<FE>;

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
        Ok(self.input_public(val))
    }

    fn assert_zero(&mut self, wire: &Self::Wire) -> ZkiResult<()> {
        convert(self.assert_zero(wire))
    }

    fn add(&mut self, a: &Self::Wire, b: &Self::Wire) -> ZkiResult<Self::Wire> {
        convert(self.add(a, b))
    }

    fn multiply(&mut self, a: &Self::Wire, b: &Self::Wire) -> ZkiResult<Self::Wire> {
        convert(self.mul(a, b))
    }

    fn add_constant(&mut self, a: &Self::Wire, b: Self::FieldElement) -> ZkiResult<Self::Wire> {
        convert(self.addc(a, b))
    }

    fn mul_constant(&mut self, a: &Self::Wire, b: Self::FieldElement) -> ZkiResult<Self::Wire> {
        convert(self.mulc(a, b))
    }

    fn and(&mut self, a: &Self::Wire, b: &Self::Wire) -> ZkiResult<Self::Wire> {
        convert(self.mul(a, b))
    }

    fn xor(&mut self, a: &Self::Wire, b: &Self::Wire) -> ZkiResult<Self::Wire> {
        convert(self.add(a, b))
    }

    fn not(&mut self, a: &Self::Wire) -> ZkiResult<Self::Wire> {
        convert(self.addc(a, Self::FieldElement::ONE))
    }

    fn instance(&mut self, val: Self::FieldElement) -> ZkiResult<Self::Wire> {
        Ok(self.input_public(val))
    }

    fn witness(&mut self, val: Option<Self::FieldElement>) -> ZkiResult<Self::Wire> {
        if val.is_some() {
            return Err("Should be none".into());
        }

        convert(self.input_private())
    }
}
