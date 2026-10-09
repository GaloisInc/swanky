#![deny(missing_docs)]
//! Traits and types for _canonical serialization_ of data.
//!
//! A serialization method for values of type `T` is **canonical** if
//! it is _deterministic_ (every `T` value always has the same
//! serialization) and _stable_ (the serialization will not change
//! across space or time, usually due to a combination of the
//! already-canonical serializations of byte-based primitive types,
//! and the additional mathematical structure we impose on those
//! types).
//!
//! The [`CanonicalSerialize`] trait extends [`serde::Serialize`] and
//! [`serde::de::DeserializeOwned`], requiring in addition methods to
//! (de)serialize individual datum from/to bytes.
//! Note that the [`derive_serde_via_canonical_serialize`] macro can
//! be used to generate suitable implementations of the `serde` traits
//! using the `CanonicalSerialize` implementation.
//!
//! A pair of associated types -- [`CanonicalSerialize::Serializer`]
//! and [`CanonicalSerialize::Deserializer`] -- must also be defined
//! when implementing the trait.
//! This allows for more efficient implementations of batched element
//! serialization, in some cases, as the (de)serialization can be
//! _stateful_.
//! To simply use the
//! [`CanonicalSerialize::to_bytes`]/[`CanonicalSerialize::from_bytes`]
//! methods you defined, see [`ByteElementSerializer`] and
//! [`ByteElementDeserializer`].
//!
//! This crate provides implementations for all fixed-width integer
//! types, `isize` and `usize`, `()`, [`vectoreyes`] vectors,
//! [`Array`], and `[T; N]` for `N <= 32` (a bound inherited
//! from [`serde`]), and all `FiniteRing`s require `CanonicalSerialize`.
//! See the field crates for details on these implementations.

use hybrid_array::typenum::Unsigned;
use hybrid_array::{Array, ArraySize};
use serde::{Serialize, de::DeserializeOwned};
use std::{
    io::{Read, Write},
    marker::PhantomData,
};

mod impls;
pub use impls::{ValueTooBigForIsize, ValueTooBigForUsize};

/// Types that implement this trait have a canonical serialization and
/// a fixed serialization size.
///
/// See the [`crate`] documentation for additional details.
pub trait CanonicalSerialize: 'static + Copy + Serialize + DeserializeOwned {
    /// A way to serialize elements of this type.
    ///
    /// See [`SequenceSerializer`] for more info.
    type Serializer: SequenceSerializer<Self>;
    /// A way to deserialize elements of this type.
    ///
    /// See [`SequenceSerializer`] for more info.
    type Deserializer: SequenceDeserializer<Self>;

    /// The number of bytes in the byte representation for this
    /// element.
    type ByteReprLen: ArraySize;
    /// The error that can result from trying to decode an invalid
    /// byte sequence.
    type FromBytesError: std::error::Error + Send + Sync + 'static;
    /// Deserialize an element from a byte array.
    ///
    /// NOTE: for security purposes, this function will accept exactly
    /// one byte sequence for each element.
    fn from_bytes(bytes: &Array<u8, Self::ByteReprLen>) -> Result<Self, Self::FromBytesError>;
    /// Serialize an element into a byte array.
    ///
    /// Consider using [`Self::Serializer`] if you need to serialize
    /// several elements.
    fn to_bytes(&self) -> Array<u8, Self::ByteReprLen>;
}

/// A way to serialize a sequence of elements.
///
/// The [`CanonicalSerialize::from_bytes`] and
/// [`CanonicalSerialize::to_bytes`] methods for require that elements
/// serialize and deserialize to the byte boundary.
/// For algebraic structures like $`\texsf{GF}(2)`$ (the finite field
/// of integers modulo 2), where each element can be represented in
/// only one bit, using the `to_bytes` and `from_bytes` methods is 8x
/// less efficient than just sending each bit of the elements.
///
/// To enable more efficient communication, we can use the
/// [`SequenceSerializer`] and [`SequenceDeserializer`] types to
/// enable _stateful_ serialization and deserialization.
pub trait SequenceSerializer<E>: Sized {
    /// The exact number of bytes that will be written if `n` elements are serialized.
    fn serialized_size(n: usize) -> usize;
    /// Construct a new serializer
    fn new<W: Write>(dst: &mut W) -> std::io::Result<Self>;
    /// Write a new element.
    fn write<W: Write>(&mut self, dst: &mut W, e: E) -> std::io::Result<()>;
    /// This _must_ be called to flush all outstanding elements.
    fn finish<W: Write>(self, dst: &mut W) -> std::io::Result<()>;
}

/// A way to deserialize a sequence of elements.
///
/// See [`SequenceSerializer`] for more information.
pub trait SequenceDeserializer<E>: Sized {
    /// Construct a new deserializer
    fn new<R: Read>(dst: &mut R) -> std::io::Result<Self>;
    /// Read the next serialized element.
    ///
    /// This may return arbitrary elements, or panic, after the serialized elements
    /// have been read.
    fn read<R: Read>(&mut self, src: &mut R) -> std::io::Result<E>;
}

/// An element serializer that uses the element's
/// [`CanonicalSerialize::to_bytes`] method.
pub struct ByteElementSerializer<E: CanonicalSerialize>(PhantomData<E>);
impl<E: CanonicalSerialize> SequenceSerializer<E> for ByteElementSerializer<E> {
    fn serialized_size(n: usize) -> usize {
        E::ByteReprLen::USIZE * n
    }
    fn new<W: Write>(_dst: &mut W) -> std::io::Result<Self> {
        Ok(ByteElementSerializer(PhantomData))
    }

    fn write<W: Write>(&mut self, dst: &mut W, e: E) -> std::io::Result<()> {
        dst.write_all(&e.to_bytes())
    }

    fn finish<W: Write>(self, _dst: &mut W) -> std::io::Result<()> {
        Ok(())
    }
}

/// An element deserializer that uses the element's
/// [`CanonicalSerialize::from_bytes`] method.
pub struct ByteElementDeserializer<E: CanonicalSerialize>(PhantomData<E>);
impl<E: CanonicalSerialize> SequenceDeserializer<E> for ByteElementDeserializer<E> {
    fn new<R: Read>(_dst: &mut R) -> std::io::Result<Self> {
        Ok(ByteElementDeserializer(PhantomData))
    }

    fn read<R: Read>(&mut self, src: &mut R) -> std::io::Result<E> {
        let mut buf: Array<u8, E::ByteReprLen> = Default::default();
        src.read_exact(&mut buf)?;
        E::from_bytes(&buf).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}

/// An error with no inhabitants, for when an element cannot fail to
/// deserialize.
#[derive(Clone, Copy, Debug)]
pub enum BytesDeserializationCannotFail {}
impl std::fmt::Display for BytesDeserializationCannotFail {
    fn fmt(&self, _: &mut std::fmt::Formatter) -> std::fmt::Result {
        unreachable!("Self has no values that inhabit it")
    }
}
impl std::error::Error for BytesDeserializationCannotFail {}

/// Dependent crates might not neccessarily depend on `serde`,
/// themsevles.
/// Nonetheless, macros written in _this_ crate need to be able to
/// access `serde`, even when those macros are invoked from other
/// crates.
/// To solve this problem, we re-export the crate that our macros
/// need.
#[doc(hidden)]
pub use serde as __serde_for_macro;

/// Implement [`serde::Serialize`] and [`serde::Deserialize`] via an
/// existing [`CanonicalSerialize`] implementation.
///
/// # Example
/// ```
/// use swanky_serialization::*;
/// use hybrid_array::Array;
/// #[derive(Clone, Copy)]
/// pub struct Foo;
/// impl CanonicalSerialize for Foo {
///     type Serializer = ByteElementSerializer<Self>;
///     type Deserializer = ByteElementDeserializer<Self>;
///     type ByteReprLen = hybrid_array::typenum::U0;
///     type FromBytesError = BytesDeserializationCannotFail;
///
///     fn from_bytes(
///         _bytes: &Array<u8, Self::ByteReprLen>,
///     ) -> Result<Self, Self::FromBytesError> {
///         Ok(Foo)
///     }
///
///     fn to_bytes(&self) -> Array<u8, Self::ByteReprLen> {
///         Default::default()
///     }
/// }
/// derive_serde_via_canonical_serialize!(Foo);
/// ````
#[macro_export]
macro_rules! derive_serde_via_canonical_serialize {
    ($f:ident) => {
        impl $crate::__serde_for_macro::Serialize for $f {
            fn serialize<S: $crate::__serde_for_macro::Serializer>(
                &self,
                serializer: S,
            ) -> Result<S::Ok, S::Error> {
                let bytes = <Self as $crate::CanonicalSerialize>::to_bytes(&self);
                serializer.serialize_bytes(&bytes)
            }
        }

        impl<'de> $crate::__serde_for_macro::Deserialize<'de> for $f {
            fn deserialize<D: $crate::__serde_for_macro::Deserializer<'de>>(
                deserializer: D,
            ) -> Result<Self, D::Error> {
                struct FieldVisitor;

                impl<'de> $crate::__serde_for_macro::de::Visitor<'de> for FieldVisitor {
                    type Value = $f;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                        use hybrid_array::typenum::Unsigned;
                        write!(
                            formatter,
                            "a field element {} ({} bytes)",
                            std::any::type_name::<Self>(),
                            <$f as $crate::CanonicalSerialize>::ByteReprLen::USIZE
                        )
                    }

                    fn visit_borrowed_bytes<E: $crate::__serde_for_macro::de::Error>(
                        self,
                        v: &'de [u8],
                    ) -> Result<Self::Value, E> {
                        use hybrid_array::typenum::Unsigned;
                        if v.len() != <$f as $crate::CanonicalSerialize>::ByteReprLen::USIZE {
                            return Err(E::invalid_length(v.len(), &self));
                        }
                        let bytes =
                            hybrid_array::Array::try_from(v).expect("slice is correct size");
                        <$f as $crate::CanonicalSerialize>::from_bytes(&bytes)
                            .map_err($crate::__serde_for_macro::de::Error::custom)
                    }

                    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                    where
                        A: $crate::__serde_for_macro::de::SeqAccess<'de>,
                    {
                        use $crate::__serde_for_macro::de::Error;
                        let mut bytes = hybrid_array::Array::<
                            u8,
                            <$f as $crate::CanonicalSerialize>::ByteReprLen,
                        >::default();
                        for (i, byte) in bytes.iter_mut().enumerate() {
                            *byte = match seq.next_element()? {
                                Some(e) => e,
                                None => return Err(A::Error::invalid_length(i + 1, &self)),
                            };
                        }
                        if let Some(_) = seq.next_element::<u8>()? {
                            return Err(A::Error::invalid_length(bytes.len() + 1, &self));
                        }
                        <$f as $crate::CanonicalSerialize>::from_bytes(&bytes)
                            .map_err($crate::__serde_for_macro::de::Error::custom)
                    }
                }

                deserializer.deserialize_bytes(FieldVisitor)
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::proptest;

    proptest! {
        #[test]
        fn byte_element_sequence_serializer_size(n: usize) {
            assert_eq!(ByteElementSerializer::<()>::serialized_size(n), 0)
        }
    }

    #[test]
    fn byte_element_sequence_serializer() {
        let mut v = vec![];
        let bes = ByteElementSerializer::<()>::new(&mut v);
        assert!(bes.is_ok());

        let mut bes = bes.unwrap();
        let res = bes.write(&mut v, ());
        assert!(res.is_ok());

        let res = bes.finish(&mut v);
        assert!(res.is_ok());
    }

    #[test]
    fn byte_element_sequence_deserializer() {
        let mut v: &[u8] = &[];
        let res = ByteElementDeserializer::<()>::new(&mut v);
        assert!(res.is_ok());

        let mut bes = res.unwrap();
        let res = bes.read(&mut v);
        assert!(res.is_ok());
    }
}
