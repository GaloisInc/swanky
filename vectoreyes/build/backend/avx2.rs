use std::io::Cursor;

use proc_macro2::TokenStream;
use quote::{format_ident, quote};

use super::types::VectorType;

use super::{cfg::Cfg, VectorBackend};
/// An intel intrinsic.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct Intrinsic {
    name: String,
    /// does the intrinsic correspond to an instruction sequence?
    sequence: bool,
    /// what cpu features are required for this intrinsic?
    cpuid: Vec<String>,
    /// what instructions does/might this intrinsic correspond to?
    instructions: Vec<String>,
}

const REQUIRED_FEATURES: &[&str] = &[
    "avx",
    "avx2",
    "sse4.1",
    "aes",
    "sse4.2",
    "ssse3",
    "pclmulqdq",
];

struct Avx2 {
    intrinsics: HashMap<String, Intrinsic>,
}
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
mod xml {
    use serde::Deserialize;
    #[derive(Deserialize, Debug)]
    pub struct Root {
        pub intrinsic: Vec<Intrinsic>,
    }
    #[derive(Deserialize, Debug)]
    pub struct Intrinsic {
        #[serde(rename = "@name")]
        pub name: String,
        #[serde(rename = "@sequence")]
        pub sequence: Option<bool>,
        #[serde(rename = "CPUID")]
        pub cpuid: Option<Vec<String>>,
        pub instruction: Option<Vec<Instruction>>,
    }
    #[derive(Deserialize, Debug)]
    pub struct Instruction {
        #[serde(rename = "@name")]
        pub name: String,
        #[serde(rename = "@form")]
        pub form: Option<String>,
    }
}

pub fn avx2_backend() -> Box<dyn VectorBackend> {
    let intel_intrinsics_xml = String::from_utf8(
        zstd::decode_all(Cursor::new(
            include_bytes!("avx2/intel-intrinsics.xml.zst").as_slice(),
        ))
        .unwrap(),
    )
    .unwrap();
    let intrinsics: xml::Root = quick_xml::de::from_str(&intel_intrinsics_xml).unwrap();
    let intrinsics: HashMap<String, Intrinsic> = intrinsics
        .intrinsic
        .into_iter()
        .map(|intrinsic| {
            (
                intrinsic.name.clone(),
                Intrinsic {
                    name: intrinsic.name.clone(),
                    sequence: intrinsic.sequence.unwrap_or_default(),
                    cpuid: intrinsic.cpuid.unwrap_or_default(),
                    instructions: intrinsic
                        .instruction
                        .unwrap_or_default()
                        .into_iter()
                        .map(|insn| format!("{} {}", insn.name, insn.form.unwrap_or_default()))
                        .collect(),
                },
            )
        })
        .collect();
    Box::new(Avx2 { intrinsics })
}
