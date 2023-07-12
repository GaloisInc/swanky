//! Fields supported in Diet Mac'n'Cheese.
//!
//! Note: Any fields added here need to also be added to
//! `backend_multifield::load_backend`!

use eyre::eyre;
use scuttlebutt::field::{F384p, F384q, Secp256k1, Secp256k1order};
use scuttlebutt::field::{F61p, F2};
use std::any::TypeId;

/// Map a modulus, as a big-endian vector of [`u8`]s, to its [`TypeId`].
pub fn modulus_to_type_id(modulus: &[u8]) -> eyre::Result<TypeId> {
    match modulus {
        &[2] => Ok(TypeId::of::<F2>()),
        &[255, 255, 255, 255, 255, 255, 255, 31] => Ok(TypeId::of::<F61p>()),
        &[47, 252, 255, 255, 254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255] => {
            Ok(TypeId::of::<Secp256k1>())
        }
        &[65, 65, 54, 208, 140, 94, 210, 191, 59, 160, 72, 175, 230, 220, 174, 186, 254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255] => {
            Ok(TypeId::of::<Secp256k1order>())
        }
        &[255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255] => {
            Ok(TypeId::of::<F384p>())
        }
        &[115, 41, 197, 204, 106, 25, 236, 236, 122, 167, 176, 72, 178, 13, 26, 88, 223, 45, 55, 244, 129, 77, 99, 199, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255] => {
            Ok(TypeId::of::<F384q>())
        }
        _ => Err(eyre!("Field with modulus {modulus:?} not supported")),
    }
}
