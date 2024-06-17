use std::ops::Deref;
use std::path::PathBuf;

use proc_macro2::TokenStream;
use quote::{format_ident, quote, TokenStreamExt};

use super::neon::neon_backend;
use super::types::VectorType;
use super::{avx2::avx2_backend, cfg::Cfg, Scalar, VectorBackend};

struct Backends {
    backends_with_cfg: Vec<(Box<dyn VectorBackend>, Cfg)>,
}
impl Backends {
    /// Go through each backend and prepend `#[cfg(...)]` to the output for each backend.
    fn visit(&self, visit: &mut dyn FnMut(&dyn VectorBackend) -> TokenStream) -> TokenStream {
        let mut out = TokenStream::new();
        for (backend, cfg) in self.backends_with_cfg.iter() {
            let body = visit(backend.deref());
            out.append_all(quote! {
                #[cfg(#cfg)]
                #body
            });
        }
        out
    }
}

pub fn generate() {
    let backends = [
        avx2_backend(),
        neon_backend(),
        Box::new(Scalar),
    ];
    let mut previous_success = Cfg::false_();
    // Because backends have overlapping cfgs, we go through them and come up with a new cfg which
    // says that we pick the _first_ valid backend. We then store that list in the Backends struct.
    let mut backends_with_cfg = Vec::new();
    for backend in backends {
        // This backend is active if it's valid and previous backends were invalid.
        let our_success = Cfg::All(vec![
            backend.cfg(),
            Cfg::Not(Box::new(previous_success.clone())),
        ]);
        // Any previous round was successful if we were successful or a previous round was. Rather
        // than writing this as any(our_success, previous_success), we write it this way to avoid
        // duplicating the previous_success expression.
        previous_success = Cfg::Any(vec![backend.cfg(), previous_success]);
        backends_with_cfg.push((backend, our_success.clone()));
    }
    let out = implementation(&Backends { backends_with_cfg });
    std::fs::write(
        PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("backend.rs"),
        prettyplease::unparse(&syn::parse2(out).unwrap()).as_bytes(),
    )
    .unwrap();
}

fn implementation(backends: &Backends) -> TokenStream {
    let internals = backends.visit(&mut |backend| {
        let mut out = TokenStream::new();
        for ty in VectorType::all() {
            let internal_ty = format_ident!("{ty}Internal");
            let vector_contents = backend.vector_contents(ty);
            out.append_all(quote! {
                pub(super) type #internal_ty = #vector_contents;
            });
        }
        quote! {
            mod internals {
                #out
            }
        }
    });
    quote! {
        #internals
        use internals::*;
    }
}
