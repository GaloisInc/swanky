use proc_macro2::TokenStream;
use quote::{format_ident, quote, TokenStreamExt};
use std::path::PathBuf;
use syn::Ident;

/// Generate implementations of array_utils traits and write them to
/// `$OUT_DIR/array_utils_impls.rs`
pub fn generate() {
    // The maximum array size to generate implmentations for.
    const MAX_COUNT: usize = 32;
    let mut out = TokenStream::new();
    out.append_all(quote! {
        use crate::array_utils::*;
    });
    // Size zero arrays trigger warnings in the code (such as unused variables). So it's broken out
    // into a separate module so we can silence those warnings.
    let mut zero_impl = TokenStream::new();
    generate_for_count(&mut zero_impl, 0);
    out.append_all(quote! {
        #[allow(unused_variables, unused_mut)]
        mod impl_0 {
            use crate::array_utils::*;
            #zero_impl
        }
    });
    for count in 1..=MAX_COUNT {
        generate_for_count(&mut out, count);
    }
    std::fs::write(
        PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("array_utils_impls.rs"),
        prettyplease::unparse(&syn::parse2(out).unwrap()).as_bytes(),
    )
    .unwrap();
}

fn generate_for_count(out: &mut TokenStream, count: usize) {
    let array_generate = array_generate(count);
    let array_map = array_map(count);
    let array_map_result = array_map_result(count);
    let array_enumerate = array_enumerate(count);
    let array_fold = array_fold(count);
    let array_zip = array_zip(count);
    let array_as_ref = array_as_ref(count);
    let array_as_mut = array_as_mut(count);
    out.append_all(quote! {
        impl UnrollableArraySize<#count> for ArrayUnrolledOps {
            #array_generate
            #array_map
            #array_map_result
            #array_enumerate
            #array_fold
            #array_zip
            #array_as_ref
            #array_as_mut
        }
    });
    out.append_all(pair_adjacent_maybe_odd(count));
    if count % 2 == 0 {
        out.append_all(pair_adjacent(count));
    }
}

/// A helper to move elements out of an array.
///
/// In a lot of functions, we need to move every element out of an array. Rust's type system isn't
/// smart enough to know that arr[0] is distinct from arr[1], and so it complains if we try to
/// construct an array like `[arr[0], arr[1]]` (if `arr` isn't a `Copy` type).
///
/// To work around this, you can use pattern matching like so:
///
/// ```
/// let arr = [String::new(), String::new()];
/// let [arr_0, arr_1] = arr;
/// dbg!(arr_0, arr_1);
/// ```
///
/// This helper generates this let statement and returns
/// (the let statement, a Vec of the defined identifiers.)
fn extract_elems(count: usize, of: Ident) -> (TokenStream, Vec<Ident>) {
    let arr_names: Vec<Ident> = (0..count).map(|i| format_ident!("{of}_{i}")).collect();
    (
        quote! {
            let [#(#arr_names,)*] = #of;
        },
        arr_names,
    )
}

fn array_generate(count: usize) -> TokenStream {
    let mut vars = TokenStream::new();
    let idents: Vec<_> = (0..count).map(|i| format_ident!("arr_{i}")).collect();
    for (i, ident) in idents.iter().enumerate() {
        vars.append_all(quote! { let #ident = f(#i); })
    }
    quote! {
        #[inline(always)]
        fn array_generate<T, F: FnMut(usize) -> T>(mut f: F) -> [T; #count] {
            #vars
            [#(#idents),*]
        }
    }
}

fn array_map(count: usize) -> TokenStream {
    let (lets, elems) = extract_elems(count, format_ident!("arr"));
    quote! {
        #[inline(always)]
        fn array_map<T, U, F: FnMut(T) -> U>(arr: [T; #count], mut f: F) -> [U; #count] {
            #lets
            [#(f(#elems)),*]
        }
    }
}

fn array_map_result(count: usize) -> TokenStream {
    let (lets, elems) = extract_elems(count, format_ident!("arr"));
    quote! {
        #[inline(always)]
        fn array_map_result<T, U, E, F: FnMut(T) -> Result<U, E>>(
            arr: [T; #count], mut f: F
        ) -> Result<[U; #count], E> {
            #lets
            Ok([#(f(#elems)?),*])
        }
    }
}

fn array_enumerate(count: usize) -> TokenStream {
    let (lets, elems) = extract_elems(count, format_ident!("arr"));
    let i = 0..count;
    quote! {
        #[inline(always)]
        fn array_enumerate<T>(arr: [T; #count]) -> [(usize, T); #count] {
            #lets
            [#((#i, #elems)),*]
        }
    }
}

fn array_fold(count: usize) -> TokenStream {
    let (lets, elems) = extract_elems(count, format_ident!("arr"));
    quote! {
        #[allow(clippy::let_and_return)]
        #[inline(always)]
        fn array_fold<T, U, F: FnMut(U, T) -> U>(arr: [T; #count], init: U, mut f: F) -> U {
            let acu = init;
            #lets
            #(let acu = f(acu, #elems);)*
            acu
        }
    }
}

fn array_zip(count: usize) -> TokenStream {
    let (lets1, elems1) = extract_elems(count, format_ident!("arr1"));
    let (lets2, elems2) = extract_elems(count, format_ident!("arr2"));
    quote! {
         #[inline(always)]
        fn array_zip<T1, T2>(arr1: [T1; #count], arr2: [T2; #count]) -> [(T1, T2); #count] {
            #lets1
            #lets2
            [#((#elems1, #elems2)),*]
        }
    }
}

fn array_as_ref(count: usize) -> TokenStream {
    let (lets, elems) = extract_elems(count, format_ident!("arr"));
    quote! {
        #[inline(always)]
        fn array_as_ref<T>(arr: &[T; #count]) -> [&T; #count] {
            #lets
            [#(#elems),*]
        }
    }
}

fn array_as_mut(count: usize) -> TokenStream {
    let (lets, elems) = extract_elems(count, format_ident!("arr"));
    quote! {
        #[inline(always)]
        fn array_as_mut<T>(arr: &mut [T; #count]) -> [&mut T; #count] {
            #lets
            [#(#elems),*]
        }
    }
}

fn pair_adjacent_maybe_odd(count: usize) -> TokenStream {
    let pair_count = count / 2 + count % 2;
    let (lets, elems) = extract_elems(count, format_ident!("this"));
    let mut body = TokenStream::new();
    for i in 0..count / 2 {
        let first = &elems[i * 2];
        let second = &elems[i * 2 + 1];
        body.append_all(quote! { (#first, #second),});
    }
    if count % 2 != 0 {
        let last = elems.last().expect("0 % 2 == 0, so elems.len() > 0");
        body.append_all(quote! {(#last, fallback),})
    }
    quote! {
        impl<T> ArrayAdjacentPairs for [T; #count] {
            type T = T;
            type AdjacentPairs = [(T, T); #pair_count];
            #[inline(always)]
            #[allow(unused_variables)]
            fn pair_adjacent_maybe_odd(self, fallback: T) -> Self::AdjacentPairs {
                let this = self;
                #lets
                [#body]
            }
        }
    }
}

fn pair_adjacent(count: usize) -> TokenStream {
    let (lets, elems) = extract_elems(count, format_ident!("this"));
    let mut body = TokenStream::new();
    for i in 0..count / 2 {
        let first = &elems[i * 2];
        let second = &elems[i * 2 + 1];
        body.append_all(quote! { (#first, #second),});
    }
    quote! {
        impl<T> EvenArrayAdjacentPairs for [T; #count] {
            #[inline(always)]
            fn pair_adjacent(self) -> Self::AdjacentPairs {
                let this = self;
                #lets
                [#body]
            }
        }
    }
}
