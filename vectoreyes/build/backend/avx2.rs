use proc_macro2::TokenStream;
use quote::{format_ident, quote};

use super::types::VectorType;

use super::{cfg::Cfg, VectorBackend};

const REQUIRED_FEATURES: &[&str] = &[
    "avx",
    "avx2",
    "sse4.1",
    "aes",
    "sse4.2",
    "ssse3",
    "pclmulqdq",
];

struct Avx2;
impl VectorBackend for Avx2 {
    fn scalar_docs(&self) -> Docs {
        "# AVX2\nThis function uses a scalar polyfill.\n".to_string()
    }

    fn cfg(&self) -> Cfg {
        let mut requirements = vec![Cfg::Contains {
            key: "target_arch".to_string(),
            value: "x86_64".to_string(),
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
        let bits = ty.bits();
        let name = format_ident!("__m{bits}i");
        quote! { std::arch::x86_64::#name }
    }
}

pub fn avx2_backend() -> Box<dyn VectorBackend> {
    Box::new(Avx2)
}
