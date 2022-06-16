//! Serialization types for finite fields.
//!
//! # Rationale
//! Finite fields have the [`FiniteField::from_bytes`] and [`FiniteField::to_bytes`] methods for
//! converting to/from a byte representation. However, these functions require that finite fields
//! serialize and deserialize to the byte boundary. For a field like [`crate::field::F2`], where
//! each field element can be represented in only one bit, using the `to_bytes` and `from_bytes`
//! methods is 8x less efficient than just sending each bit of the field elements.
//!
//! To enable more efficient communication, we can use the [`FiniteField::Serializer`] and
//! [`FiniteField::Deserializer`] types to enable _stateful_ serialization and deserialization.

use generic_array::typenum::Unsigned;
use generic_array::GenericArray;

use super::FiniteField;
use std::{
    io::{Read, Write},
    marker::PhantomData,
};

/// A way to serialize a sequence of field elements.
pub trait FiniteFieldSerializer<FE: FiniteField>: Sized {
    /// The exact number of bytes that will be written if `n` field elements are serialized.
    fn serialized_size(n: usize) -> usize;
    /// Construct a new serializer
    fn new<W: Write>(dst: &mut W) -> std::io::Result<Self>;
    /// Write a new field element.
    fn write<W: Write>(&mut self, dst: &mut W, fe: FE) -> std::io::Result<()>;
    /// This _must_ be called to flush all outstanding field elements.
    fn finish<W: Write>(self, dst: &mut W) -> std::io::Result<()>;
}

/// A way to deserialize a sequence of field elements.
pub trait FiniteFieldDeserializer<FE: FiniteField>: Sized {
    /// Construct a new deserializer
    fn new<R: Read>(dst: &mut R) -> std::io::Result<Self>;
    /// Read the next serialized field element.
    ///
    /// This may return arbitrary field elements, or panic, after the serialized field elements
    /// have been read.
    fn read<R: Read>(&mut self, src: &mut R) -> std::io::Result<FE>;
}

/// A finite field serializer that writes the field's [`FiniteField::to_bytes`] method.
pub struct ByteFiniteFieldSerializer<FE: FiniteField>(PhantomData<FE>);
impl<FE: FiniteField> FiniteFieldSerializer<FE> for ByteFiniteFieldSerializer<FE> {
    fn serialized_size(n: usize) -> usize {
        FE::ByteReprLen::USIZE * n
    }
    fn new<W: Write>(_dst: &mut W) -> std::io::Result<Self> {
        Ok(ByteFiniteFieldSerializer(PhantomData))
    }

    fn write<W: Write>(&mut self, dst: &mut W, fe: FE) -> std::io::Result<()> {
        dst.write_all(&fe.to_bytes())
    }

    fn finish<W: Write>(self, _dst: &mut W) -> std::io::Result<()> {
        Ok(())
    }
}

/// A finite field deserializer that writes the field's [`FiniteField::from_bytes`] method.
pub struct ByteFiniteFieldDeserializer<FE: FiniteField>(PhantomData<FE>);
impl<FE: FiniteField> FiniteFieldDeserializer<FE> for ByteFiniteFieldDeserializer<FE> {
    fn new<R: Read>(_dst: &mut R) -> std::io::Result<Self> {
        Ok(ByteFiniteFieldDeserializer(PhantomData))
    }

    fn read<R: Read>(&mut self, src: &mut R) -> std::io::Result<FE> {
        let mut buf: GenericArray<u8, FE::ByteReprLen> = Default::default();
        src.read_exact(&mut buf)?;
        Ok(FE::from_bytes(&buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?)
    }
}
