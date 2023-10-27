use super::{
    ByteElementDeserializer, ByteElementSerializer, BytesDeserializationCannotFail,
    CanonicalSerialize,
};
use generic_array::typenum::{self, U};
use generic_array::GenericArray;

macro_rules! pod_impl {
    ($($ty:ty),*$(,)?) => {$(
        impl CanonicalSerialize for $ty {
            type Serializer = ByteElementSerializer<Self>;
            type Deserializer = ByteElementDeserializer<Self>;
            type ByteReprLen = U<{ std::mem::size_of::<$ty>() }>;
            type FromBytesError = BytesDeserializationCannotFail;
            fn from_bytes(
                bytes: &GenericArray<u8, Self::ByteReprLen>,
            ) -> Result<Self, Self::FromBytesError> {
                let arr: [u8; std::mem::size_of::<$ty>()] = bytes.into_array();
                Ok(bytemuck::cast(arr))
            }
            fn to_bytes(&self) -> GenericArray<u8, Self::ByteReprLen> {
                let arr: [u8; std::mem::size_of::<$ty>()] = bytemuck::cast(*self);
                GenericArray::from_array(arr)
            }
        }
    )*};
}
pod_impl!(
    i8,
    u8,
    i16,
    u16,
    i32,
    u32,
    i64,
    u64,
    i128,
    u128,
    vectoreyes::I8x16,
    vectoreyes::I8x32,
    vectoreyes::I16x8,
    vectoreyes::I16x16,
    vectoreyes::I32x4,
    vectoreyes::I32x8,
    vectoreyes::I64x2,
    vectoreyes::I64x4,
    vectoreyes::U8x16,
    vectoreyes::U8x32,
    vectoreyes::U16x8,
    vectoreyes::U16x16,
    vectoreyes::U32x4,
    vectoreyes::U32x8,
    vectoreyes::U64x2,
    vectoreyes::U64x4,
);

#[derive(Debug, Clone, Copy)]
pub struct ValueTooBigForUsize;
impl std::fmt::Display for ValueTooBigForUsize {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "An integer could fit in a u64, but not in a usize")
    }
}
impl std::error::Error for ValueTooBigForUsize {}
impl CanonicalSerialize for usize {
    type Serializer = ByteElementSerializer<Self>;
    type Deserializer = ByteElementDeserializer<Self>;
    type ByteReprLen = <u64 as CanonicalSerialize>::ByteReprLen;
    type FromBytesError = ValueTooBigForUsize;
    fn from_bytes(
        bytes: &GenericArray<u8, Self::ByteReprLen>,
    ) -> Result<Self, Self::FromBytesError> {
        match u64::from_bytes(bytes) {
            Ok(x) => Self::try_from(x).map_err(|_| ValueTooBigForUsize),
            Err(e) => {
                let _: BytesDeserializationCannotFail = e;
                unreachable!("Byte deserialization cannot fail")
            }
        }
    }
    fn to_bytes(&self) -> GenericArray<u8, Self::ByteReprLen> {
        ((*self) as u64).to_bytes()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ValueTooBigForIsize;
impl std::fmt::Display for ValueTooBigForIsize {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "An integer could fit in a i64, but not in a isize")
    }
}
impl std::error::Error for ValueTooBigForIsize {}
impl CanonicalSerialize for isize {
    type Serializer = ByteElementSerializer<Self>;
    type Deserializer = ByteElementDeserializer<Self>;
    type ByteReprLen = <i64 as CanonicalSerialize>::ByteReprLen;
    type FromBytesError = ValueTooBigForIsize;
    fn from_bytes(
        bytes: &GenericArray<u8, Self::ByteReprLen>,
    ) -> Result<Self, Self::FromBytesError> {
        match i64::from_bytes(bytes) {
            Ok(x) => Self::try_from(x).map_err(|_| ValueTooBigForIsize),
            Err(e) => {
                let _: BytesDeserializationCannotFail = e;
                unreachable!("Byte deserialization cannot fail")
            }
        }
    }
    fn to_bytes(&self) -> GenericArray<u8, Self::ByteReprLen> {
        ((*self) as i64).to_bytes()
    }
}

impl CanonicalSerialize for () {
    type Serializer = ByteElementSerializer<Self>;
    type Deserializer = ByteElementDeserializer<Self>;
    type ByteReprLen = typenum::U0;
    type FromBytesError = BytesDeserializationCannotFail;

    fn from_bytes(
        _bytes: &GenericArray<u8, Self::ByteReprLen>,
    ) -> Result<Self, Self::FromBytesError> {
        Ok(())
    }

    fn to_bytes(&self) -> GenericArray<u8, Self::ByteReprLen> {
        Default::default()
    }
}
