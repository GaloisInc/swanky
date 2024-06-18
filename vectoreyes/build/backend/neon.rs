use proc_macro2::TokenStream;
use quote::{format_ident, quote};

use super::types::VectorType;

use super::{cfg::Cfg, VectorBackend};

const REQUIRED_FEATURES: &[&str] = &["neon", "aes"];

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct Intrinsic {
    /// The function call name of the intrinsic
    name: String,
    /// What `target_feature`s are required for this intrinsic to be used
    required_features: Vec<String>,
    /// Which instructions might this intrinsic generate.
    instructions: Vec<InstructionJson>,
}
/// The ARM NEON vectoreyes backend
///
/// Vectoreyes supports 256-bit vectors, but NEON only supports 128-bit vectors. So the neon
/// backend will represent a 256-bit vector as an array of two 128-bit vectors. To keep our code
/// consistent between the 128-bit and 256-bit vector types, _all_ neon vectors are arrays.
struct Neon {
    intrinsics: HashMap<String, Intrinsic>,
}
impl VectorBackend for Neon {
    fn scalar_docs(&self) -> Docs {
        "# Neon\nThis function uses a scalar polyfill.\n".to_string()
    }

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
/// Unlike Intel, ARM doesn't provide a list of which CPU features are requried for each intrinsic.
/// To fix this, we parse the `arm_neon.h` file from LLVM to figure out which target features are
// required for each intrinsic.
fn parse_target_features() -> HashMap<String, Vec<String>> {
    let arm_neon_h = String::from_utf8(
        zstd::decode_all(std::io::Cursor::new(
            include_bytes!("neon/arm_neon.h.zst").as_slice(),
        ))
        .unwrap(),
    )
    .unwrap();
    // Extract lines like:
    // __ai __attribute__((target("aes"))) uint8x16_t vaeseq_u8(...
    // __ai uint16x8_t vaddq_u16(...
    let mut out = HashMap::new();
    for line in arm_neon_h.lines() {
        let line = line.trim();
        if let Some(line) = line.strip_prefix("__ai ") {
            let features: Vec<_> = if line.contains("__attribute__") {
                line.split_once('"')
                    .expect("unable to parse")
                    .1
                    .split_once('"')
                    .expect("unable to parse")
                    .0
                    .split(',')
                    .map(|feature| feature.trim().to_string())
                    .collect()
            } else {
                Vec::new()
            };
            let name = line
                .rsplit_once('(')
                .expect("unable to parse")
                .0
                .split_whitespace()
                .last()
                .expect("unable to parse")
                .to_string();
            match out.entry(name) {
                std::collections::hash_map::Entry::Occupied(entry) => {
                    assert_eq!(
                        entry.get(),
                        &features,
                        "{:?} occured multiple time with different featurres",
                        entry.key()
                    );
                }
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(features);
                }
            }
        }
    }
    out
}

#[derive(serde::Deserialize, PartialEq, Eq, PartialOrd, Ord)]
struct InstructionListJson {
    base_instruction: String,
    operands: String,
    url: String,
}
#[derive(serde::Deserialize, PartialEq, Eq, PartialOrd, Ord)]
struct InstructionJson {
    preamble: String,
    list: Vec<InstructionListJson>,
}
#[derive(serde::Deserialize)]
struct ArmIntrinsicJson {
    name: String,
    #[serde(default)]
    instructions: Vec<InstructionJson>,
}

pub fn neon_backend() -> Box<dyn VectorBackend> {
    let arm_intrinsics_json: Vec<ArmIntrinsicJson> = serde_json::from_slice(
        zstd::decode_all(std::io::Cursor::new(
            include_bytes!("neon/neon-intrinsics.json.zst").as_slice(),
        ))
        .unwrap()
        .as_slice(),
    )
    .unwrap();
    let mut arm_intrinsics_json: HashMap<String, ArmIntrinsicJson> = arm_intrinsics_json
        .into_iter()
        .map(|intrinsic| {
            let name = intrinsic.name.replace("[__arm_]", "");
            (name, intrinsic)
        })
        .collect();
    let intrinsics: HashMap<String, Intrinsic> = parse_target_features()
        .into_iter()
        .filter_map(|(name, required_features)| {
            arm_intrinsics_json.remove(&name).map(|json| {
                (
                    name.clone(),
                    Intrinsic {
                        name: name.clone(),
                        required_features,
                        instructions: json.instructions,
                    },
                )
            })
        })
        .collect();
    Box::new(Neon { intrinsics })
}
