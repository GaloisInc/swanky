use proc_macro2::TokenStream;
use quote::{format_ident, quote};

use super::types::VectorType;

use super::{cfg::Cfg, VectorBackend};

const REQUIRED_FEATURES: &[&str] = &["neon", "aes"];

/// The ARM NEON vectoreyes backend
///
/// Vectoreyes supports 256-bit vectors, but NEON only supports 128-bit vectors. So the neon
/// backend will represent a 256-bit vector as an array of two 128-bit vectors. To keep our code
/// consistent between the 128-bit and 256-bit vector types, _all_ neon vectors are arrays.
struct Neon;
impl VectorBackend for Neon {
    fn cfg(&self) -> Cfg {
        let mut requirements = vec![Cfg::Contains {
            key: "target_arch".to_string(),
            value: "aarch64".to_string(),
        }];
        for feature in REQUIRED_FEATURES {
            requirements.push(Cfg::Contains {
                key: "target_feature".to_string(),
                value: feature.to_string(),
            });
        }
        Cfg::All(requirements)
    }
    fn vector_contents(&self, ty: VectorType) -> TokenStream {
        // Number of 128-bit lanes
        let lane_count = ty.bits() / 128;
        // How many elements in each 128-bit lane?
        let elems_per_lane = ty.count() / lane_count;
        let sign = match ty.of().signedness() {
            super::types::Signedness::Signed => "",
            super::types::Signedness::Unsigned => "u",
        };
        let name = format_ident!("{sign}int{}x{elems_per_lane}_t", ty.of().bits());
        quote! { [std::arch::aarch64::#name; #lane_count] }
    }
}

pub fn neon_backend() -> Box<dyn VectorBackend> {
    Box::new(Neon)
}
