//! Fields supported in Diet Mac'n'Cheese.
//!
//! Note: Any fields added here need to also be added to
//! `backend_multifield::load_backend`!

use eyre::{bail, Result};
use mac_n_cheese_sieve_parser::Number;
use scuttlebutt::field::{F384p, F384q, Secp256k1, Secp256k1order};
use scuttlebutt::field::{F61p, F2};
use std::any::TypeId;

pub(crate) const F2_MODULUS: Number = Number::from_u64(2);
pub(crate) const F61P_MODULUS: Number = Number::from_u64((1 << 61) - 1);
pub(crate) const SECP256K1_MODULUS: Number =
    Number::from_be_hex("00000000000000000000000000000000fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
pub(crate) const SECP256K1ORDER_MODULUS: Number =
    Number::from_be_hex("00000000000000000000000000000000fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
pub(crate) const F384P_MODULUS: Number =
    Number::from_be_hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff");
pub(crate) const F384Q_MODULUS: Number =
    Number::from_be_hex("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973");

/// Map a modulus, provided as a [`Number`]s, to its [`TypeId`].
pub fn modulus_to_type_id(modulus: Number) -> Result<TypeId> {
    if modulus == F2_MODULUS {
        Ok(TypeId::of::<F2>())
    } else if modulus == F61P_MODULUS {
        Ok(TypeId::of::<F61p>())
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
