use std::collections::{BTreeSet, HashMap};
use std::fmt::Write;
use std::io::Cursor;

use proc_macro2::TokenStream;
use quote::{format_ident, quote};

use super::types::VectorType;

use super::{cfg::Cfg, VectorBackend};
use super::{Docs, PairwiseOperator};

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

struct Builder<'a> {
    avx2: &'a Avx2,
    // We want a deterministic order.
    intrinsics_used: BTreeSet<&'a Intrinsic>,
}
impl Builder<'_> {
    /// Document the intrinsics used in this builder.
    fn docs(&self) -> Docs {
        if self.intrinsics_used.is_empty() {
            return String::new();
        }
        let mut out = "# AVX2 Intrinsics Used\n\n".to_string();
        for intrinsic in self.intrinsics_used.iter() {
            const BASE_URL: &str =
                "https://software.intel.com/sites/landingpage/IntrinsicsGuide/#text=";
            writeln!(
                &mut out,
                "* [`{}`]({BASE_URL}{})",
                intrinsic.name, intrinsic.name
            )
            .unwrap();
            if intrinsic.sequence {
                writeln!(&mut out, "    - Instruction sequence").unwrap();
            }
            for insn in intrinsic.instructions.iter() {
                writeln!(&mut out, "    - `{insn}`").unwrap();
            }
        }
        out
    }
    /// Return the identifier of the intel intrinsic of the given `name`.
    ///
    /// This function also records that the intrinsic was used.
    fn intrinsic(&mut self, name: &str) -> TokenStream {
        let intrinsic = self
            .avx2
            .intrinsics
            .get(name)
            .unwrap_or_else(|| panic!("unknown intrinsic {name:?}"));
        for feature in intrinsic.cpuid.iter() {
            if feature == "SSE2" {
                // SSE2 is inherent to x86_64, and rust won't let us require it, so we'll manually
                // allow it here.
                continue;
            }
            if !REQUIRED_FEATURES.contains(&feature.to_lowercase().as_str()) {
                panic!("intrinsic {name:?} requires cpu feature {feature:?} which the avx2 backend doesn't require");
            }
        }
        self.intrinsics_used.insert(intrinsic);
        let name = format_ident!("{name}");
        quote! { std::arch::x86_64::#name }
    }
}

struct Avx2 {
    intrinsics: HashMap<String, Intrinsic>,
}
impl Avx2 {
    /// Return the output of `body()` as well as the documentation of which intrsinics it used.
    fn build(&self, body: &mut dyn FnMut(&mut Builder) -> TokenStream) -> (TokenStream, Docs) {
        let mut builder = Builder {
            avx2: self,
            intrinsics_used: BTreeSet::new(),
        };
        let out = body(&mut builder);
        (out, builder.docs())
    }
    fn prefix(&self, ty: VectorType) -> &str {
        match ty.bits() {
            128 => "_mm",
            256 => "_mm256",
            bits => panic!("Unexpected vector size {bits}"),
        }
    }
}
impl VectorBackend for Avx2 {
    fn scalar_docs(&self) -> Docs {
        "# AVX2\nThis function uses a scalar polyfill.\n".to_string()
    }
    fn vector_backend_variant(&self) -> &str {
        "Avx2"
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
    fn pairwise(
        &self,
        ty: VectorType,
        op: super::PairwiseOperator,
        lhs: &dyn quote::ToTokens,
        rhs: &dyn quote::ToTokens,
    ) -> (TokenStream, Docs) {
        self.build(&mut |b| {
            let epi = format!("epi{}", ty.of().bits());
            let si = format!("si{}", ty.bits());
            let (op_name, suffix) = match op {
                PairwiseOperator::WrappingAdd => ("add", epi),
                PairwiseOperator::WrappingSub => ("sub", epi),
                PairwiseOperator::Xor => ("xor", si),
                PairwiseOperator::Or => ("or", si),
                PairwiseOperator::And => ("and", si),
            };
            let intrinsic = b.intrinsic(&format!("{}_{op_name}_{suffix}", self.prefix(ty)));
            quote! {
                unsafe {
                    #ty(#intrinsic(#lhs.0, #rhs.0))
                }
            }
        })
    }
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
