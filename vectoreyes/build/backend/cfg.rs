use quote::{format_ident, quote, ToTokens, TokenStreamExt};

#[derive(Clone)]
/// A representation of a [`cfg`](https://doc.rust-lang.org/rust-by-example/attribute/cfg.html)
/// string.
pub enum Cfg {
    Not(Box<Cfg>),
    All(Vec<Cfg>),
    Any(Vec<Cfg>),
    /// The cfg string `key = "value"`
    Contains {
        key: String,
        value: String,
    },
}
impl std::fmt::Display for Cfg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Cfg::Not(inner) => write!(f, "not({inner})"),
            Cfg::All(inner) | Cfg::Any(inner) => {
                let name = if matches!(self, Cfg::All(_)) {
                    "all"
                } else {
                    "any"
                };
                write!(f, "{name}(")?;
                for (i, x) in inner.iter().enumerate() {
                    if i == 0 {
                        write!(f, "{x}")?;
                    } else {
                        write!(f, ", {x}")?;
                    }
                }
                write!(f, ")")
            }
            Cfg::Contains { key, value } => write!(f, "{key} = {value:?}"),
        }
    }
}
impl ToTokens for Cfg {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        tokens.append_all(match self {
            Cfg::Not(inner) => quote! { not(#inner) },
            Cfg::All(inner) => quote! { all(#(#inner),*) },
            Cfg::Any(inner) => quote! { any(#(#inner),*) },
            Cfg::Contains { key, value } => {
                let key = format_ident!("{key}");
                quote! { #key = #value }
            }
        });
    }
}
impl Cfg {
    /// A [`Cfg`] which evaluates to `true`.
    pub fn true_() -> Self {
        Self::All(vec![])
    }
    /// A [`Cfg`] which evaluates to `false`.
    pub fn false_() -> Self {
        Self::Any(vec![])
    }
}
