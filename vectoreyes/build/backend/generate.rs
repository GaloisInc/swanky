use std::ops::Deref;
use std::path::PathBuf;

use proc_macro2::TokenStream;
use quote::{format_ident, quote, TokenStreamExt};
use syn::Ident;

use super::code_block::CodeBlock;
use super::neon::neon_backend;
use super::types::VectorType;
use super::utils::index_literals;
use super::{avx2::avx2_backend, cfg::Cfg, Scalar, VectorBackend};
use super::{Docs, PairwiseOperator};

struct Backends {
    backends_with_cfg: Vec<(Box<dyn VectorBackend>, Cfg)>,
}
impl Backends {
    /// Go through each backend and prepend `#[cfg(...)]` to the output for each backend.
    ///
    /// This function should be avoided since it could cause issues if visit returns too many
    /// tokens. For example if `visit` returned:
    ///
    /// ```ignore
    /// #[cfg(...)]
    /// let a = thing;
    /// let b = a;
    /// ```
    /// then only the `let a =` statement would be conditional, even though the intent was for the
    /// full statement to be conditional.
    fn visit_raw(&self, visit: &mut dyn FnMut(&dyn VectorBackend) -> TokenStream) -> TokenStream {
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

    /// Define a module named `name` whose body is defined by `visit`.
    ///
    /// Prefer using `block`, instead, to ensure the public API doesn't change between backends.
    fn define_module(
        &self,
        name: Ident,
        visit: &mut dyn FnMut(&dyn VectorBackend) -> TokenStream,
    ) -> TokenStream {
        self.visit_raw(&mut |backend| {
            let body = visit(backend);
            quote! {
                mod #name {
                    #body
                }
            }
        })
    }

    /// Return a block whose value is defined by `visit`.
    fn block(&self, visit: &mut dyn FnMut(&dyn VectorBackend) -> TokenStream) -> TokenStream {
        self.visit_raw(&mut |backend| {
            let body = visit(backend);
            quote! {
                {
                     #body
                }
            }
        })
    }
}

pub fn generate() {
    let backends = [avx2_backend(), neon_backend(), Box::new(Scalar)];
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
    let mut out = TokenStream::new();
    let current_vector_backend = backends.block(&mut |backend| {
        let variant = format_ident!("{}", backend.vector_backend_variant());
        quote! { crate::VectorBackend::#variant }
    });
    out.append_all(quote! {
        pub(crate) const fn current_vector_backend() -> crate::VectorBackend {
            #current_vector_backend
        }
    });
    let internals = backends.define_module(format_ident!("internals"), &mut |backend| {
        let mut out = TokenStream::new();
        for ty in VectorType::all() {
            let internal_ty = format_ident!("{ty}Internal");
            let vector_contents = backend.vector_contents(ty);
            out.append_all(quote! {
                pub(super) type #internal_ty = #vector_contents;
            });
        }
        out
    });
    out.append_all(quote! {
        #internals
        use internals::*;
    });
    for ty in VectorType::all() {
        conversions(ty, &mut out);
        binops(backends, ty, &mut out);
    }
    out
}

fn conversions(ty: VectorType, out: &mut TokenStream) {
    let ty_of = ty.of();
    let ty_count = ty.count();
    let example_elements = index_literals(ty.count());
    let example = CodeBlock {
        hidden_prefix: quote! { use vectoreyes::*; },
        body: quote! {
            const MY_EXTREMELY_FUN_VALUE: #ty =
                #ty::from_array([#(#example_elements),*]);
            for (i, value) in MY_EXTREMELY_FUN_VALUE.as_array().iter().copied().enumerate() {
                assert_eq!(i as #ty_of, value);
            }
        },
        ..Default::default()
    };
    out.append_all(quote! {
        impl From<[#ty_of; #ty_count]> for #ty {
            #[inline(always)]
            fn from(arr: [#ty_of; #ty_count]) -> #ty {
                bytemuck::cast(arr)
            }
        }

        impl From<#ty> for [#ty_of; #ty_count] {
            #[inline(always)]
            fn from(arr: #ty) -> [#ty_of; #ty_count] {
                bytemuck::cast(arr)
            }
        }

        impl #ty {
            /// Create a vector from an array.
            ///
            /// Unlike the `From` trait function, the `from_array` function is `const`.
            /// # Example
            #example
            #[inline(always)]
            pub const fn from_array(arr: [#ty_of; #ty_count]) -> Self {
                unsafe {
                    // SAFETY: #ty and [#ty_of; #ty_count] are both plain-old-data of the same
                    // size.
                    // We'd use bytemuck here, but bytemuck's functions aren't const.
                    std::mem::transmute::<[#ty_of; #ty_count], #ty>(arr)
                }
            }
        }

    });
}

/// Generate a vectoreyes function, the usual way.
///
/// The "usual" way means that this function will generate functions which:
///
/// 1. Are `#[inline(always)]`
/// 2. Are documented with the `description` provided, as well as
/// 3. the scalar equivalent of this function (provided by `call_backend(Scalar)`), and
/// 4. any backend-specific documentation
///
/// This function returns a complete function, with the given `prototype` and a body of
/// `call_backend(backend)`.
///
/// # Example
///
/// ```ignore
/// standard_fn(
///     backend,
///     "Perform a pairwise `wrapping_add`"
///     quote! { fn my_addition(self, rhs: #ty) -> #ty },
///     &|bknd| bknd.pairwise(ty, PairwiseOperator::WrappingAdd, &quote! { self }, &quote! { rhs }),
/// );
/// ```
fn standard_fn(
    backends: &Backends,
    description: &str,
    prototype: TokenStream,
    call_backend: &dyn Fn(&dyn VectorBackend) -> (TokenStream, Docs),
) -> TokenStream {
    let scalar_equivalent = CodeBlock {
        body: call_backend(&Scalar).0,
        ignored: true,
        ..Default::default()
    };
    let mut docs = String::new();
    let body = backends.block(&mut |backend| {
        let (body, new_docs) = call_backend(backend);
        docs.push_str(new_docs.as_str());
        body
    });
    quote! {
        #[doc = #description]
        ///
        /// # Scalar Equivalent
        #scalar_equivalent
        ///
        #[doc = #docs]
        #[inline(always)]
        #prototype {
            #body
        }
    }
}

fn binops(backends: &Backends, ty: VectorType, out: &mut TokenStream) {
    use PairwiseOperator::*;
    let mut binop = |name: &str, desc: &str, op: PairwiseOperator| {
        let trait_ = format_ident!("{name}");
        let trait_assign = format_ident!("{name}Assign");
        let trait_method = format_ident!("{}", name.to_lowercase());
        let trait_assign_method = format_ident!("{}_assign", name.to_lowercase());
        let body = standard_fn(
            backends,
            &format!("Perform a pairwise {desc}"),
            quote! { fn #trait_method(self, rhs: #ty) -> #ty },
            &|bknd| bknd.pairwise(ty, op, &quote! { self }, &quote! { rhs }),
        );
        out.append_all(quote! {
            impl std::ops::#trait_ for #ty {
                type Output = #ty;
                #body
            }
            impl std::ops::#trait_assign for #ty {
                #[inline(always)]
                fn #trait_assign_method(&mut self, other: #ty) {
                    *self = std::ops::#trait_::#trait_method(*self, other);
                }
            }
        });
    };
    binop("Add", "`wrapping_add`", WrappingAdd);
    binop("Sub", "`wrapping_sub`", WrappingSub);
    binop("BitOr", "bitwise or", Or);
    binop("BitXor", "bitwise xor", Xor);
    binop("BitAnd", "bitwise and", And);
}
