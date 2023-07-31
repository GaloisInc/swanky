//! Fields supported in Diet Mac'n'Cheese.
//!
//! Note: Any fields added here need to also be added to
//! `backend_multifield::load_backend`!

use eyre::{bail, Result};
use mac_n_cheese_sieve_parser::Number;
use std::any::TypeId;
#[cfg(test)]
use swanky_field::PrimeFiniteField;
use swanky_field_binary::F2;
use swanky_field_f61p::F61p;
use swanky_field_ff_primes::{F128p, F384p, F384q, Secp256k1, Secp256k1order};

// Note: We can't use `PrimeFiniteField::modulus_int` because it is not `const`.

pub(crate) const F2_MODULUS: Number = Number::from_u64(2);
pub(crate) const F61P_MODULUS: Number = Number::from_u64((1 << 61) - 1);
pub(crate) const F128P_MODULUS: Number =
    Number::from_be_hex("0000000000000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffff61");
pub(crate) const SECP256K1_MODULUS: Number =
    Number::from_be_hex("00000000000000000000000000000000fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
pub(crate) const SECP256K1ORDER_MODULUS: Number =
    Number::from_be_hex("00000000000000000000000000000000fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
pub(crate) const F384P_MODULUS: Number =
    Number::from_be_hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff");
pub(crate) const F384Q_MODULUS: Number =
    Number::from_be_hex("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973");

#[test]
fn f2_modulus_is_correct() {
    assert_eq!(F2_MODULUS, F2::modulus_int());
}

#[test]
fn f61p_modulus_is_correct() {
    assert_eq!(F61P_MODULUS, F61p::modulus_int());
}

#[test]
fn f128p_modulus_is_correct() {
    assert_eq!(F128P_MODULUS, F128p::modulus_int());
}

#[test]
fn secp256k1_modulus_is_correct() {
    assert_eq!(SECP256K1_MODULUS, Secp256k1::modulus_int());
}

#[test]
fn secp256k1order_modulus_is_correct() {
    assert_eq!(SECP256K1ORDER_MODULUS, Secp256k1order::modulus_int());
}

#[test]
fn f384p_modulus_is_correct() {
    assert_eq!(F384P_MODULUS, F384p::modulus_int());
}

#[test]
fn f384q_modulus_is_correct() {
    assert_eq!(F384Q_MODULUS, F384q::modulus_int());
}

/// Map a modulus, provided as a [`Number`]s, to its [`TypeId`].
pub fn modulus_to_type_id(modulus: Number) -> Result<TypeId> {
    if modulus == F2_MODULUS {
        Ok(TypeId::of::<F2>())
    } else if modulus == F61P_MODULUS {
        Ok(TypeId::of::<F61p>())
    } else if modulus == F128P_MODULUS {
        Ok(TypeId::of::<F128p>())
    } else if modulus == SECP256K1_MODULUS {
        Ok(TypeId::of::<Secp256k1>())
    } else if modulus == SECP256K1ORDER_MODULUS {
        Ok(TypeId::of::<Secp256k1order>())
    } else if modulus == F384P_MODULUS {
        Ok(TypeId::of::<F384p>())
    } else if modulus == F384Q_MODULUS {
        Ok(TypeId::of::<F384q>())
    } else {
        bail!("Field with modulus {modulus} not supported")
    }
}
