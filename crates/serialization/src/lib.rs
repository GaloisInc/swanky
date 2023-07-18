//! Serialization types for algebraic structures.

use generic_array::typenum::Unsigned;
use generic_array::{ArrayLength, GenericArray};
use serde::{de::DeserializeOwned, Serialize};
use std::{
    io::{Read, Write},
    marker::PhantomData,
};

mod impls;

/// Types that implement this trait have a canonical serialization and a fixed
/// serialization size.
pub trait CanonicalSerialize: Copy + Serialize + DeserializeOwned {
    /// A way to serialize field elements of this type.
    ///
    /// See [`SequenceSerializer`] for more info.
    type Serializer: SequenceSerializer<Self>;
    /// A way to deserialize field elements of this type.
    ///
    /// See [`SequenceSerializer`] for more info.
    type Deserializer: SequenceDeserializer<Self>;

    /// The number of bytes in the byte representation for this element.
    type ByteReprLen: ArrayLength<u8>;
    /// The error that can result from trying to decode an invalid byte sequence.
    type FromBytesError: std::error::Error + Send + Sync + 'static;
    /// Deserialize an element from a byte array.
    ///
    /// NOTE: for security purposes, this function will accept exactly one byte sequence for each
    /// element.
    fn from_bytes(
        bytes: &GenericArray<u8, Self::ByteReprLen>,
    ) -> Result<Self, Self::FromBytesError>;
    /// Serialize an element into a byte array.
    ///
    /// Consider using [`Self::Serializer`] if you need to serialize several field elements.
    fn to_bytes(&self) -> GenericArray<u8, Self::ByteReprLen>;
}

/// A way to serialize a sequence of elements.
///
/// The [`Serializer::from_bytes`] and [`Serializer::to_bytes`] methods for
/// require that elements serialize and deserialize to the byte boundary.
/// For algebraic structures like [`crate::field::F2`], where
/// each element can be represented in only one bit, using the `to_bytes` and `from_bytes`
/// methods is 8x less efficient than just sending each bit of the elements.
///
/// To enable more efficient communication, we can use the [`SequenceSerializer`] and
/// [`SequenceDeserializer`] types to enable _stateful_ serialization and deserialization.
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
pub trait SequenceDeserializer<E>: Sized {
    /// Construct a new deserializer
    fn new<R: Read>(dst: &mut R) -> std::io::Result<Self>;
    /// Read the next serialized element.
    ///
    /// This may return arbitrary elements, or panic, after the serialized elements
    /// have been read.
    fn read<R: Read>(&mut self, src: &mut R) -> std::io::Result<E>;
}

/// An element serializer that uses the element's [`Serializer::to_bytes`] method.
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

/// An element deserializer that uses the element's [`Serializer::from_bytes`] method.
pub struct ByteElementDeserializer<E: CanonicalSerialize>(PhantomData<E>);
impl<E: CanonicalSerialize> SequenceDeserializer<E> for ByteElementDeserializer<E> {
    fn new<R: Read>(_dst: &mut R) -> std::io::Result<Self> {
        Ok(ByteElementDeserializer(PhantomData))
    }

    fn read<R: Read>(&mut self, src: &mut R) -> std::io::Result<E> {
        let mut buf: GenericArray<u8, E::ByteReprLen> = Default::default();
        src.read_exact(&mut buf)?;
        Ok(E::from_bytes(&buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?)
    }
}

// TODO: move this to swanky-field.
/// The error which occurs if the inputted value or bit pattern doesn't correspond to
/// an element.
#[derive(Debug, Clone, Copy)]
pub struct BiggerThanModulus;
impl std::error::Error for BiggerThanModulus {}
impl std::fmt::Display for BiggerThanModulus {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// An error with no inhabitants, for when an element cannot fail to deserialize.
#[derive(Clone, Copy, Debug)]
pub enum BytesDeserializationCannotFail {}
impl std::fmt::Display for BytesDeserializationCannotFail {
    fn fmt(&self, _: &mut std::fmt::Formatter) -> std::fmt::Result {
        unreachable!("Self has no values that inhabit it")
    }
}
impl std::error::Error for BytesDeserializationCannotFail {}

/// Provides `serde` serialize / deserialize functionality for vectors of elements.
pub mod serde_vec {
    use super::*;

    /// Serializes a vector of elements using `serde`.
    pub fn serialize<E: CanonicalSerialize, S: serde::Serializer>(
        vec: &[E],
        s: S,
    ) -> Result<S::Ok, S::Error> {
        use serde::ser::Error;
        use serde::ser::SerializeTupleStruct;

        let nbytes = E::Serializer::serialized_size(vec.len());
        let mut bytes = Vec::with_capacity(nbytes);
        let mut cursor = std::io::Cursor::new(&mut bytes);
        let mut ser = E::Serializer::new(&mut cursor).map_err(|e| Error::custom(e))?;
        for f in vec.iter() {
            ser.write(&mut cursor, *f).map_err(|e| Error::custom(e))?;
        }
        ser.finish(&mut cursor).map_err(|e| Error::custom(e))?;

        let mut state = s.serialize_tuple_struct("Vec<F>", 2)?;
        state.serialize_field(&(vec.len() as u64))?;
        state.serialize_field(&bytes)?;
        state.end()
    }

    /// Deserializes a vector of elements using `serde`.
    pub fn deserialize<'de, E: CanonicalSerialize, D: serde::de::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<E>, D::Error> {
        use serde::de::Error;

        struct MyVisitor<F: CanonicalSerialize> {
            field: std::marker::PhantomData<F>,
        }

        impl<'de, F: CanonicalSerialize> serde::de::Visitor<'de> for MyVisitor<F> {
            type Value = Vec<F>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(
                    formatter,
                    "a vector of elements of type {}",
                    std::any::type_name::<F>()
                )
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let nelements: u64 = match seq.next_element::<u64>()? {
                    Some(n) => n,
                    None => return Err(A::Error::missing_field("number of elements")),
                };
                let nelements = usize::try_from(nelements).map_err(|e| Error::custom(e))?;
                let nbytes = F::Serializer::serialized_size(nelements);

                let bytes = match seq.next_element::<Vec<u8>>()? {
                    Some(v) => v,
                    None => return Err(A::Error::missing_field("vector of bytes")),
                };
                if let Some(_) = seq.next_element::<u8>()? {
                    return Err(A::Error::custom("extra element encountered"));
                }
                if bytes.len() != nbytes {
                    return Err(A::Error::invalid_length(bytes.len(), &self));
                }

                let mut cursor = std::io::Cursor::new(&bytes);
                let mut de = F::Deserializer::new(&mut cursor).map_err(|e| Error::custom(e))?;

                let mut vec: Vec<F> = Vec::with_capacity(nelements);
                for _ in 0..nelements {
                    let e = de.read(&mut cursor).map_err(|e| Error::custom(e))?;
                    vec.push(e);
                }
                Ok(vec)
            }
        }

        deserializer.deserialize_tuple_struct(
            "Vec<F>",
            2,
            MyVisitor {
                field: std::marker::PhantomData,
            },
        )
    }
}

/// Dependent crates might not neccessarily depend on `serde`, themsevles.
/// Nonetheless, macros written in _this_ crate need to be able to access `serde`, even when
/// those macros are invoked from other crates. To solve this problem, we re-export the crate that
/// our macros need.
#[doc(hidden)]
pub use serde as __serde_for_macro;

/// Implement [`serde::Serialize`] and [`serde::Deserialize`] via an existing
/// [`CanonicalSerialize`] implementation.
///
/// # Example
/// ```
/// use swanky_serialization::*;
/// use generic_array::GenericArray;
/// #[derive(Clone, Copy)]
/// pub struct Foo;
/// impl CanonicalSerialize for Foo {
///     type Serializer = ByteElementSerializer<Self>;
///     type Deserializer = ByteElementDeserializer<Self>;
///     type ByteReprLen = generic_array::typenum::U0;
///     type FromBytesError = BytesDeserializationCannotFail;
///
///     fn from_bytes(
///         _bytes: &GenericArray<u8, Self::ByteReprLen>,
///     ) -> Result<Self, Self::FromBytesError> {
///         Ok(Foo)
///     }
///
///     fn to_bytes(&self) -> GenericArray<u8, Self::ByteReprLen> {
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
                        use generic_array::typenum::Unsigned;
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
                        use generic_array::typenum::Unsigned;
                        if v.len() != <$f as $crate::CanonicalSerialize>::ByteReprLen::USIZE {
                            return Err(E::invalid_length(v.len(), &self));
                        }
                        let bytes = generic_array::GenericArray::from_slice(v);
                        <$f as $crate::CanonicalSerialize>::from_bytes(&bytes)
                            .map_err($crate::__serde_for_macro::de::Error::custom)
                    }

                    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                    where
                        A: $crate::__serde_for_macro::de::SeqAccess<'de>,
                    {
                        use $crate::__serde_for_macro::de::Error;
                        let mut bytes = generic_array::GenericArray::<
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
