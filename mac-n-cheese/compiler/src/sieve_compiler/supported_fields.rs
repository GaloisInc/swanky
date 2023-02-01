use crypto_bigint::ArrayEncoding;
use eyre::{Context, ContextCompat};
use lazy_static::lazy_static;
use mac_n_cheese_ir::compilation_format::FieldMacType;
use mac_n_cheese_sieve_parser::Number;
use mac_n_cheese_wire_map::WireMap;
use rustc_hash::{FxHashMap, FxHashSet};
use scuttlebutt::{
    field::{F128p, F61p, FiniteField, F2},
    ring::FiniteRing,
    serialization::CanonicalSerialize,
};
use std::ops::{Deref, DerefMut, Index};
use std::{collections::VecDeque, marker::PhantomData, str::FromStr};
use std::{fmt::Debug, ops::IndexMut};

pub trait ValueParseableFiniteField: FiniteField {
    fn parse_sieve_value(v: &Number) -> eyre::Result<Self>;
}

pub trait CompilerField: ValueParseableFiniteField {
    const FIELD_TYPE: FieldType;
    fn get_product<T: FieldGenericType>(product: FieldGenericProduct<T>) -> T::Out<Self>;
    fn get_coproduct<T: FieldGenericType>(
        coproduct: FieldGenericCoproduct<T>,
    ) -> Option<T::Out<Self>>;
    fn new_coproduct<T: FieldGenericType>(t: T::Out<Self>) -> FieldGenericCoproduct<T>;
}

pub trait FieldGenericType {
    type Out<FE: CompilerField>;
}
impl<'a, T: FieldGenericType> FieldGenericType for &'a T {
    type Out<FE: CompilerField> = &'a T::Out<FE>;
}
impl<'a, T: FieldGenericType> FieldGenericType for &'a mut T {
    type Out<FE: CompilerField> = &'a mut T::Out<FE>;
}
impl<T: FieldGenericType> FieldGenericType for Vec<T> {
    type Out<FE: CompilerField> = Vec<T::Out<FE>>;
}
impl<'a, T: FieldGenericType> FieldGenericType for WireMap<'a, T> {
    type Out<FE: CompilerField> = WireMap<'a, T::Out<FE>>;
}
impl<T: FieldGenericType> FieldGenericType for VecDeque<T> {
    type Out<FE: CompilerField> = VecDeque<T::Out<FE>>;
}
impl<T: FieldGenericType> FieldGenericType for std::vec::IntoIter<T> {
    type Out<FE: CompilerField> = std::vec::IntoIter<T::Out<FE>>;
}
impl<'a, T: FieldGenericType> FieldGenericType for std::slice::Iter<'a, T> {
    type Out<FE: CompilerField> = std::slice::Iter<'a, T::Out<FE>>;
}
impl<A: FieldGenericType, B: FieldGenericType> FieldGenericType for (A, B) {
    type Out<FE: CompilerField> = (A::Out<FE>, B::Out<FE>);
}
impl<T: FieldGenericType> FieldGenericType for eyre::Result<T> {
    type Out<FE: CompilerField> = eyre::Result<T::Out<FE>>;
}
impl<T: FieldGenericType> FieldGenericType for Option<T> {
    type Out<FE: CompilerField> = Option<T::Out<FE>>;
}
impl FieldGenericType for () {
    type Out<FE: CompilerField> = ();
}
pub struct InvariantType<T>(PhantomData<T>);
impl<T> FieldGenericType for InvariantType<T> {
    type Out<FE: CompilerField> = T;
}
pub struct FieldGenericIdentity;
impl FieldGenericType for FieldGenericIdentity {
    type Out<FE: CompilerField> = FE;
}

#[macro_export]
macro_rules! field_generic_type {
    ($vis:vis $out:ident<$FE:ident: CompilerField> => $ty:ty) => {
        #[derive(Default, Clone, Copy, Eq, PartialEq, Hash)]
        $vis struct $out;
        impl $crate::sieve_compiler::supported_fields::FieldGenericType for $out {
            type Out<$FE: $crate::sieve_compiler::supported_fields::CompilerField> = $ty;
        }
    };
    // TODO: it'd be better to have this be general, and not a special case.
    ($vis:vis $out:ident<$P:ident : Party, $FE:ident: CompilerField> => $ty:ty) => {
        #[derive(Default, Clone, Copy, Eq, PartialEq, Hash)]
        $vis struct $out<$P: Party>(std::marker::PhantomData<P>);
        impl<$P: Party> $crate::sieve_compiler::supported_fields::FieldGenericType for $out<$P> {
            type Out<$FE: $crate::sieve_compiler::supported_fields::CompilerField> = $ty;
        }
    };
}

pub trait CompilerFieldVisitor<Arg: FieldGenericType = ()> {
    type Output: FieldGenericType;
    fn visit<FE: CompilerField>(
        self,
        arg: Arg::Out<FE>,
    ) -> <Self::Output as FieldGenericType>::Out<FE>;
}

// TODO: we can probably speed things up with a SmallFieldGenericProduct which contains Option<T>
// and expects only a single field to be set at once.
macro_rules! supported_fields {
    ($({
        modulus: $modulus:expr,
        value_field: $vf:ident,
        field_mac_type: $field_mac_type:expr,
    }),*$(,)?) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub enum FieldType {
            $($vf),*
        }
        impl FieldType {
            pub const ALL: &'static [Self] = &[$(Self::$vf),*];
            const MODULUS_MAP: &'static [(Number, Self)] = &[$((Number::from_be_hex($modulus), Self::$vf)),*];
            pub fn field_mac_type(&self) -> FieldMacType {
                match self {
                    $(FieldType::$vf => $field_mac_type),*
                }
            }
            pub fn visit<CFV: CompilerFieldVisitor<Output=InvariantType<U>>, U>(&self, cfv: CFV) -> U {
                match self {
                    $(FieldType::$vf => cfv.visit::<$vf>(())),*
                }
            }
        }
        $(impl CompilerField for $vf {
            const FIELD_TYPE: FieldType = FieldType::$vf;
            fn get_product<T: FieldGenericType>(product: FieldGenericProduct<T>) -> T::Out<Self> {
                product.$vf
            }
            fn new_coproduct<T: FieldGenericType>(t: T::Out<Self>) -> FieldGenericCoproduct<T> {
                FieldGenericCoproduct::$vf(t)
            }
            fn get_coproduct<T: FieldGenericType>(
                coproduct: FieldGenericCoproduct<T>,
            ) -> Option<T::Out<Self>> {
                match coproduct {
                    FieldGenericCoproduct::$vf(x) => Some(x),
                    _ => None,
                }
            }
        })*
        #[derive(PartialEq, Eq, Hash)]
        pub enum FieldGenericCoproduct<T: FieldGenericType> {
            $($vf(T::Out<$vf>)),*
        }
        impl<T: FieldGenericType> Clone for FieldGenericCoproduct<T>
            where $(T::Out::<$vf>: Clone),*
        {
            fn clone(&self) -> Self {
                match self {
                    $(Self::$vf(x) => Self::$vf(x.clone())),*
                }
            }
        }
        impl<T: FieldGenericType> Copy for FieldGenericCoproduct<T>
            where $(T::Out::<$vf>: Copy),*
        {}
        impl<T: FieldGenericType> FieldGenericCoproduct<T> {
            pub fn as_ref(&self) -> FieldGenericCoproduct<&T> {
                match self {
                    $(FieldGenericCoproduct::$vf(x) => FieldGenericCoproduct::$vf(x)),*
                }
            }
            pub fn as_mut(&mut self) -> FieldGenericCoproduct<&mut T> {
                match self {
                    $(FieldGenericCoproduct::$vf(x) => FieldGenericCoproduct::$vf(x)),*
                }
            }
            pub fn visit<V: CompilerFieldVisitor<T, Output=InvariantType<U>>, U>(self, v: V) -> U {
                match self {
                    $(FieldGenericCoproduct::$vf(x) => v.visit::<$vf>(x)),*
                }
            }
        }
        impl<T: FieldGenericType> Debug for FieldGenericCoproduct<T>
            where $(T::Out<$vf>: Debug),*
        {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                match self {$(
                    Self::$vf(x) =>
                        f.debug_struct(
                            std::any::type_name::<Self>())
                            .field(stringify!($vf), x)
                            .finish(),
                )*}
            }
        }
        pub struct FieldGenericProduct<T: FieldGenericType> {
            $($vf: T::Out<$vf>),*
        }
        impl<T: FieldGenericType> Clone for FieldGenericProduct<T>
            where $(T::Out<$vf>: Clone),*
        {
            fn clone(&self) -> Self {
                Self {
                    $($vf: self.$vf.clone()),*
                }
            }
        }
        impl<T: FieldGenericType> Copy for FieldGenericProduct<T>
            where $(T::Out<$vf>: Copy),*
        {}
        impl<T: FieldGenericType> Default for FieldGenericProduct<T>
            where $(T::Out<$vf>: Default),*
        {
            fn default() -> Self {
                Self {
                    $($vf: Default::default()),*
                }
            }
        }
        impl<T: FieldGenericType> Debug for FieldGenericProduct<T>
            where $(T::Out<$vf>: Debug),*
        {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.debug_struct(std::any::type_name::<Self>())
                    $(.field(stringify!($vf), &self.$vf))*
                    .finish()
            }
        }
        impl<T: FieldGenericType> FieldGenericProduct<T> {
            pub fn as_ref(&self) -> FieldGenericProduct<&T> {
                FieldGenericProduct {
                    $($vf: &self.$vf),*
                }
            }
            pub fn as_mut(&mut self) -> FieldGenericProduct<&mut T> {
                FieldGenericProduct {
                    $($vf: &mut self.$vf),*
                }
            }
            pub fn map<V, U: FieldGenericType>(self, v: &mut V) -> FieldGenericProduct<U>
                where for<'a> &'a mut V: CompilerFieldVisitor<T, Output = U>
            {
                $(let $vf = v.visit::<$vf>(self.$vf);)*
                FieldGenericProduct { $($vf),* }
            }
            pub fn map_result<V, U: FieldGenericType>(
                self, v: &mut V
            ) -> eyre::Result<FieldGenericProduct<U>>
                where for<'a> &'a mut V: CompilerFieldVisitor<T, Output = eyre::Result<U>>
            {
                $(let $vf = v.visit::<$vf>(self.$vf)?;)*
                Ok(FieldGenericProduct { $($vf),* })
            }
            pub fn zip<U: FieldGenericType>(self, other: FieldGenericProduct<U>) -> FieldGenericProduct<(T, U)> {
                FieldGenericProduct {
                    $($vf: (self.$vf, other.$vf)),*
                }
            }
        }
        impl<T> std::ops::Index<FieldType> for FieldGenericProduct<InvariantType<T>> {
            type Output = T;
            fn index(&self, index: FieldType) -> &T {
                match index {
                    $(FieldType::$vf => &self.$vf),*
                }
            }
        }
        impl<T> std::ops::IndexMut<FieldType> for FieldGenericProduct<InvariantType<T>> {
            fn index_mut(&mut self, index: FieldType) -> &mut T {
                match index {
                    $(FieldType::$vf => &mut self.$vf),*
                }
            }
        }
        impl<T: FieldGenericType> Debug for SparseFieldGenericProduct<T>
            where $(T::Out::<$vf>: Debug),*
        {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                todo!()
            }
        }
        impl<T: FieldGenericType> Clone for SparseFieldGenericProduct<T>
            where $(T::Out::<$vf>: Clone),*
        {
            fn clone(&self) -> Self {
                use SparseFieldGenericProductInner::*;
                Self(match &self.0 {
                    Empty => Empty,
                    Single(x) => Single(x.clone()),
                    Several(x) => Several(x.clone()),
                })
            }
        }
    };
}
impl<T: FieldGenericType> FieldGenericCoproduct<T> {
    pub fn new<FE: CompilerField>(t: T::Out<FE>) -> Self {
        FE::new_coproduct(t)
    }
    pub fn get<FE: CompilerField>(self) -> Option<T::Out<FE>> {
        FE::get_coproduct(self)
    }
}
impl<T: FieldGenericType> FieldGenericProduct<T> {
    // TODO: V ought to be able to be mut.
    pub fn new<V>(v: &mut V) -> Self
    where
        for<'a> &'a mut V: CompilerFieldVisitor<(), Output = T>,
    {
        FieldGenericProduct::<()>::default().map(v)
    }
    pub fn get<FE: CompilerField>(self) -> T::Out<FE> {
        FE::get_product(self)
    }
}
#[derive(Default, Clone, Copy, Debug)]
pub struct FieldIndexedArray<T>(pub [T; FieldType::ALL.len()]);
impl<T> Deref for FieldIndexedArray<T> {
    type Target = [T; FieldType::ALL.len()];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl<T> DerefMut for FieldIndexedArray<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl<T> Index<FieldType> for FieldIndexedArray<T> {
    type Output = T;
    fn index(&self, index: FieldType) -> &Self::Output {
        &self.0[index as usize]
    }
}
impl<T> IndexMut<FieldType> for FieldIndexedArray<T> {
    fn index_mut(&mut self, index: FieldType) -> &mut Self::Output {
        &mut self.0[index as usize]
    }
}

enum SparseFieldGenericProductInner<T: FieldGenericType> {
    Empty,
    Single(FieldGenericCoproduct<T>),
    Several(Box<FieldGenericProduct<Option<T>>>),
}
impl<T: FieldGenericType> SparseFieldGenericProductInner<T> {
    fn upgrade_to_several(&mut self) -> &mut FieldGenericProduct<Option<T>> {
        use SparseFieldGenericProductInner::*;
        *self = Several(match std::mem::replace(self, Empty) {
            Empty => Default::default(),
            Single(x) => {
                struct V<T: FieldGenericType>(PhantomData<T>);
                impl<T: FieldGenericType> CompilerFieldVisitor<T> for V<T> {
                    type Output = InvariantType<Box<FieldGenericProduct<Option<T>>>>;
                    fn visit<FE: CompilerField>(
                        self,
                        x: T::Out<FE>,
                    ) -> Box<FieldGenericProduct<Option<T>>> {
                        let mut out = Box::<FieldGenericProduct<Option<T>>>::default();
                        *out.deref_mut().as_mut().get::<FE>() = Some(x);
                        out
                    }
                }
                x.visit(V(PhantomData))
            }
            Several(x) => x,
        });
        match self {
            Several(x) => x,
            _ => unreachable!(),
        }
    }
}
/// `FieldGenericProduct<Option<T>>` which is more efficient if, usually, only one field will be
/// `Some`.
pub struct SparseFieldGenericProduct<T: FieldGenericType>(SparseFieldGenericProductInner<T>);
impl<T: FieldGenericType> SparseFieldGenericProduct<T> {
    pub fn get_mut_or_insert_with<'a, FE: CompilerField>(
        &'a mut self,
        f: impl FnOnce() -> T::Out<FE>,
    ) -> &'a mut T::Out<FE> {
        use SparseFieldGenericProductInner::*;
        // We check whether we need to upgrade the Single case, first, due to
        // https://github.com/rust-lang/rust/issues/21906, the longstanding bane of my existence :)
        if let Single(x) = &self.0 {
            if x.as_ref().get::<FE>().is_none() {
                self.0.upgrade_to_several();
            }
        }
        match &mut self.0 {
            x @ Empty => {
                *x = Single(FieldGenericCoproduct::new(f()));
                match x {
                    Single(x) => x.as_mut().get::<FE>().unwrap(),
                    _ => unreachable!(),
                }
            }
            Single(x) => x.as_mut().get::<FE>().unwrap(),
            Several(x) => x.deref_mut().as_mut().get::<FE>().get_or_insert_with(f),
        }
    }
    // We don't have as_ref and as_mut, since those aren't free (they might allocate), so we prefer
    // to write combination of functions manually.
    pub fn visit_mut<'a, V>(&'a mut self, v: &mut V) -> eyre::Result<()>
    where
        for<'b> &'b mut V:
            CompilerFieldVisitor<&'a mut T, Output = InvariantType<eyre::Result<()>>>,
    {
        use SparseFieldGenericProductInner::*;
        match &mut self.0 {
            Empty => {}
            Single(x) => x.as_mut().visit(v)?,
            Several(x) => todo!(),
        }
        Ok(())
    }
}
impl<T: FieldGenericType> Default for SparseFieldGenericProduct<T> {
    fn default() -> Self {
        Self(SparseFieldGenericProductInner::Empty)
    }
}

impl FieldType {
    pub fn from_modulus(modulus: &Number) -> Option<Self> {
        for (k, ft) in Self::MODULUS_MAP {
            if k == modulus {
                return Some(*ft);
            }
        }
        None
    }
}

#[test]
fn no_duplicate_moduli() {
    assert_eq!(
        FieldType::MODULUS_MAP.len(),
        FieldType::MODULUS_MAP
            .iter()
            .copied()
            .map(|x| x.0)
            .collect::<FxHashSet<Number>>()
            .len()
    );
}

fn num2u128(x: &Number) -> eyre::Result<u128> {
    // TODO: make this function work on 32-bit systems
    let le_words = x.as_words();
    let _: u64 = le_words[0]; // Error out (for now) on 32-bit systems.
    eyre::ensure!(
        le_words[2..].iter().all(|word| *word == 0),
        "{x} can't fit in a u128"
    );
    Ok(u128::from(le_words[0]) | (u128::from(le_words[1]) << 64))
}

#[cfg(test)]
proptest::proptest! {
    #[test]
    fn testnum2u128(x in proptest::prelude::any::<u128>()) {
        proptest::prop_assert_eq!(num2u128(&Number::from_u128(x)).unwrap(), x);
    }
}

//-------------------------------------------------------------------------------------------------
// Insert new fields here!

// Use the following to get the modulus in the needed hex format:
// (384 comes from the fact that Number is a 384-bit number)
//
// python3 -c 'zeroes = 384/4; print(f"%0{zeroes}x" % int(input("Modulus? ")))'

supported_fields! {
    {
        modulus: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002",
        value_field: F2,
        field_mac_type: FieldMacType::BinaryF63b,
    },
    {
        modulus: "000000000000000000000000000000000000000000000000000000000000000000000000000000001fffffffffffffff",
        value_field: F61p,
        field_mac_type: FieldMacType::F61p,
    },
    {
        modulus: "0000000000000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffff61",
        value_field: F128p,
        field_mac_type: FieldMacType::F128p,
    },
}

impl ValueParseableFiniteField for F2 {
    fn parse_sieve_value(v: &Number) -> eyre::Result<Self> {
        if v == &Number::ZERO {
            Ok(Self::ZERO)
        } else if v == &Number::ONE {
            Ok(Self::ONE)
        } else {
            eyre::bail!("0x{v:x} isn't a valid F2 value")
        }
    }
}
impl ValueParseableFiniteField for F61p {
    fn parse_sieve_value(v: &Number) -> eyre::Result<Self> {
        Ok(Self::try_from(num2u128(v)?)?)
    }
}
impl ValueParseableFiniteField for F128p {
    fn parse_sieve_value(v: &Number) -> eyre::Result<Self> {
        Ok(Self::try_from(num2u128(v)?)?)
    }
}
