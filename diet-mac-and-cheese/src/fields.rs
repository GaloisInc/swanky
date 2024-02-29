//! Fields supported in Diet Mac'n'Cheese.
//!
//! Note: Any fields added here need to also be added to
//! `backend_multifield::load_backend`!

use eyre::{bail, ensure, Result};
use generic_array::{typenum::Unsigned, GenericArray};
use mac_n_cheese_sieve_parser::Number;
use scuttlebutt::serialization::CanonicalSerialize;
use std::any::{type_name, TypeId};
use swanky_field::PrimeFiniteField;
use swanky_field_binary::{F40b, F63b, F2};
use swanky_field_f61p::F61p;
use swanky_field_ff_primes::{F128p, F384p, F384q, Secp256k1, Secp256k1order};

use crate::number_to_u64;

// Note: We can't use `PrimeFiniteField::modulus_int` because it is not `const`.

/// The modulus for [`F2`], as a [`Number`].
pub const F2_MODULUS: Number = Number::from_u64(2);
/// The modulus for [`F61p`], as a [`Number`].
pub const F61P_MODULUS: Number = Number::from_u64((1 << 61) - 1);
/// The modulus for [`F128p`], as a [`Number`].
pub const F128P_MODULUS: Number =
    Number::from_be_hex("0000000000000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffff61");
/// The modulus for [`Secp256k1`], as a [`Number`].
pub const SECP256K1_MODULUS: Number =
    Number::from_be_hex("00000000000000000000000000000000fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
/// The modulus for [`Secp256k1order`], as a [`Number`].
pub const SECP256K1ORDER_MODULUS: Number =
    Number::from_be_hex("00000000000000000000000000000000fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
/// The modulus for [`F384p`], as a [`Number`].
pub const F384P_MODULUS: Number =
    Number::from_be_hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff");
/// The modulus for [`F384q`], as a [`Number`].
pub const F384Q_MODULUS: Number =
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

/// The polynomial modulus for [`F40b`], as a `u64`.
const F40B_POLYNOMIAL_MODULUS: u64 = 1099511627805;
/// The polynomial modulus for [`F63b`], as a `u64`.
const F63B_POLYNOMIAL_MODULUS: u64 = 9223372036854775811;

/// Map an extension field to its [`TypeId`].
///
/// The extension field is specified as (1) the [`TypeId`] associated with its
/// base field, (2) the degree of the extension field's polynomial modulus, and
/// (3) the polynomial modulus, provided as a `u64` where the coefficients
/// are the digits of the integer when interpreted in the base field.
pub(crate) fn extension_field_to_type_id(
    base_field: TypeId,
    degree: u64,
    modulus: u64,
) -> Result<TypeId> {
    ensure!(
        base_field == TypeId::of::<F2>(),
        "Only extension fields with a base field of `F2` are supported."
    );
    match degree {
        40 => {
            ensure!(
                modulus != F40B_POLYNOMIAL_MODULUS,
                "Invalid modulus {modulus} provided. Expected {F40B_POLYNOMIAL_MODULUS}."
            );
            Ok(TypeId::of::<F40b>())
        }
        63 => {
            ensure!(
                modulus != F63B_POLYNOMIAL_MODULUS,
                "Invalid modulus {modulus} provided. Expected {F63B_POLYNOMIAL_MODULUS}."
            );
            Ok(TypeId::of::<F63b>())
        }
        _ => bail!("Degree {degree} not supported. Only degrees of 40 and 63 are supported."),
    }
}

/// Types that can be deserialized from SIEVE IR constants.
pub trait SieveIrDeserialize: Copy {
    /// Deserialize a value from a [`Number`].
    fn from_number(val: &Number) -> Result<Self>;
}

macro_rules! impl_sieve_ir_deserialize_prime_field {
    ( $($t:ty),* ) => {
        $( impl SieveIrDeserialize for $t {
            fn from_number(&val: &Number) -> Result<Self> {
                let x = <$t>::try_from_int(val);
                if x.is_none().into() {
                    bail!(
                        "{val} is too large to be an element of {}",
                        type_name::<$t>()
                    )
                } else {
                    // Safe: We've already checked that x is not none.
                    Ok(x.unwrap())
                }
            }
        }) *
    }
}

macro_rules! impl_sieve_ir_deserialize_binary_ext_field {
    ( $($t:ty),* ) => {
        $( impl SieveIrDeserialize for $t {
            fn from_number(val: &Number) -> Result<Self> {
                let val = number_to_u64(val)?;
                Ok(<$t>::from_bytes(GenericArray::from_slice(
                    &val.to_le_bytes()[0..<$t as CanonicalSerialize>::ByteReprLen::USIZE],
                ))?)
            }
        }) *
    }
}

impl_sieve_ir_deserialize_prime_field! { F2, F61p, F128p, Secp256k1, Secp256k1order, F384p, F384q }
impl_sieve_ir_deserialize_binary_ext_field! { F40b, F63b }
