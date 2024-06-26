use proc_macro2::Literal;

/// Given `count` produce `vec![ quote!(0), quote!(1), ... ]`
pub fn index_literals(count: usize) -> Vec<Literal> {
    (0..count).map(Literal::usize_unsuffixed).collect()
}
