use std::mem::MaybeUninit;

use super::{
    ByteElementDeserializer, ByteElementSerializer, BytesDeserializationCannotFail,
    CanonicalSerialize,
};
use hybrid_array::Flatten;
use hybrid_array::typenum::{self, Const, Prod, ToUInt, U, Unsigned};
use hybrid_array::{Array, ArraySize};
use serde::Serialize;
use serde::de::DeserializeOwned;

macro_rules! pod_impl {
    ($($ty:ty),*$(,)?) => {$(
        impl CanonicalSerialize for $ty {
            type Serializer = ByteElementSerializer<Self>;
            type Deserializer = ByteElementDeserializer<Self>;
            type ByteReprLen = U<{ std::mem::size_of::<$ty>() }>;
            type FromBytesError = BytesDeserializationCannotFail;
            fn from_bytes(
                bytes: &Array<u8, Self::ByteReprLen>,
            ) -> Result<Self, Self::FromBytesError> {
                let arr: [u8; std::mem::size_of::<$ty>()] = bytes.0;
                Ok(bytemuck::cast(arr))
            }
            fn to_bytes(&self) -> Array<u8, Self::ByteReprLen> {
                let arr: [u8; std::mem::size_of::<$ty>()] = bytemuck::cast(*self);
                Array(arr)
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

/// A 64-bit integer could fit in a `u64`, but not necessarily in a
/// `usize`, which is architecture dependent.
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
    fn from_bytes(bytes: &Array<u8, Self::ByteReprLen>) -> Result<Self, Self::FromBytesError> {
        match u64::from_bytes(bytes) {
            Ok(x) => Self::try_from(x).map_err(|_| ValueTooBigForUsize),
            Err(e) => {
                let _: BytesDeserializationCannotFail = e;
                unreachable!("Byte deserialization cannot fail")
            }
        }
    }
    fn to_bytes(&self) -> Array<u8, Self::ByteReprLen> {
        ((*self) as u64).to_bytes()
    }
}

/// A 64-bit integer could fit in a `i64`, but not necessarily in a
/// `isize`, which is architecture dependent.
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
    fn from_bytes(bytes: &Array<u8, Self::ByteReprLen>) -> Result<Self, Self::FromBytesError> {
        match i64::from_bytes(bytes) {
            Ok(x) => Self::try_from(x).map_err(|_| ValueTooBigForIsize),
            Err(e) => {
                let _: BytesDeserializationCannotFail = e;
                unreachable!("Byte deserialization cannot fail")
            }
        }
    }
    fn to_bytes(&self) -> Array<u8, Self::ByteReprLen> {
        ((*self) as i64).to_bytes()
    }
}

impl CanonicalSerialize for () {
    type Serializer = ByteElementSerializer<Self>;
    type Deserializer = ByteElementDeserializer<Self>;
    type ByteReprLen = typenum::U0;
    type FromBytesError = BytesDeserializationCannotFail;

    fn from_bytes(_bytes: &Array<u8, Self::ByteReprLen>) -> Result<Self, Self::FromBytesError> {
        Ok(())
    }

    fn to_bytes(&self) -> Array<u8, Self::ByteReprLen> {
        Default::default()
    }
}

impl<T: CanonicalSerialize, N: ArraySize> CanonicalSerialize for Array<T, N>
where
    <N as ArraySize>::ArrayType<T>: Copy,
    <T as CanonicalSerialize>::ByteReprLen: std::ops::Mul<N>,
    <<T as CanonicalSerialize>::ByteReprLen as std::ops::Mul<N>>::Output: ArraySize,
{
    type Serializer = ByteElementSerializer<Self>;
    type Deserializer = ByteElementDeserializer<Self>;
    type ByteReprLen = Prod<T::ByteReprLen, N>;
    type FromBytesError = T::FromBytesError;

    fn from_bytes(bytes: &Array<u8, Self::ByteReprLen>) -> Result<Self, Self::FromBytesError> {
        let mut out: Array<MaybeUninit<T>, N> = Array::uninit();
        if bytes.is_empty() {
            // We need to handle zero bytes separately. This only
            // occurs if:
            debug_assert!(N::USIZE == 0 || <T::ByteReprLen as Unsigned>::USIZE == 0);
            // In this case, chunks_from_slice() doesn't know how many
            // chunks to create (because division by zero is
            // undefined).
            // In this instance, we just initialize all the members
            // separately.
            //
            // The bytes.is_empty() branch should be eliminated in
            // release mode because byte.len() is a constant.
            for dst in out.iter_mut() {
                dst.write(T::from_bytes(&Default::default())?);
            }
        } else {
            let (chunks, remainder) = Array::<u8, T::ByteReprLen>::slice_as_chunks(bytes);
            debug_assert!(remainder.is_empty());

            debug_assert_eq!(chunks.len(), N::USIZE);
            for (dst, chunk) in out.iter_mut().zip(chunks.iter()) {
                dst.write(T::from_bytes(chunk)?);
            }
        }
        Ok(unsafe {
            // SAFETY: we've initialized every element of the array.
            Array::assume_init(out)
        })
    }

    fn to_bytes(&self) -> Array<u8, Self::ByteReprLen> {
        self.map(|x| x.to_bytes()).flatten()
    }
}

/// NOTE: because [`serde`] only `impl`s serialization for arrays up
/// to 32 elements in length, and [`CanonicalSerialize`] requires
/// [`Serialize`], we inherit this restriction.
impl<T: CanonicalSerialize, const N: usize> CanonicalSerialize for [T; N]
where
    Const<N>: ToUInt,
    U<N>: ArraySize,
    <U<N> as ArraySize>::ArrayType<T>: Copy,
    <T as CanonicalSerialize>::ByteReprLen: std::ops::Mul<U<N>>,
    <<T as CanonicalSerialize>::ByteReprLen as std::ops::Mul<U<N>>>::Output: ArraySize,
    [T; N]: Serialize + DeserializeOwned,
{
    type Serializer = ByteElementSerializer<Self>;
    type Deserializer = ByteElementDeserializer<Self>;
    type ByteReprLen = <Array<T, U<N>> as CanonicalSerialize>::ByteReprLen;
    type FromBytesError = <Array<T, U<N>> as CanonicalSerialize>::FromBytesError;

    fn from_bytes(bytes: &Array<u8, Self::ByteReprLen>) -> Result<Self, Self::FromBytesError> {
        Ok(*Array::<T, U<N>>::from_bytes(bytes)?
            .as_array()
            .expect("array is correct size"))
    }

    fn to_bytes(&self) -> Array<u8, Self::ByteReprLen> {
        Array::<T, U<N>>::try_from(self.as_slice())
            .expect("slice is correct size")
            .to_bytes()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;
    fn roundtrip<T: CanonicalSerialize>(t: T) -> T {
        T::from_bytes(&t.to_bytes()).unwrap()
    }
    macro_rules! test_serialize {
        ($(fn $name:ident => $strategy:expr),*$(,)?) => {$(
            proptest! {
                #[test]
                fn $name(x in $strategy) {
                    prop_assert_eq!(x, roundtrip(x));
                }
            }
        )*};
    }
    test_serialize! {
        fn roundtrip_i8 => any::<i8>(),
        fn roundtrip_u8 => any::<u8>(),
        fn roundtrip_i16 => any::<i16>(),
        fn roundtrip_u16 => any::<u16>(),
        fn roundtrip_i32 => any::<i32>(),
        fn roundtrip_u32 => any::<u32>(),
        fn roundtrip_i64 => any::<i64>(),
        fn roundtrip_u64 => any::<u64>(),
        fn roundtrip_i128 => any::<i128>(),
        fn roundtrip_u128 => any::<u128>(),
        fn roundtrip_usize => any::<usize>(),
        fn roundtrip_isize => any::<isize>(),
        fn roundtrip_unit => any::<()>(),
        fn roundtrip_vectoreyes_i8x16 => any::<[i8; 16]>().prop_map(vectoreyes::I8x16::from),
        fn roundtrip_vectoreyes_i8x32 => any::<[i8; 32]>().prop_map(vectoreyes::I8x32::from),
        fn roundtrip_vectoreyes_i16x8 => any::<[i16; 8]>().prop_map(vectoreyes::I16x8::from),
        fn roundtrip_vectoreyes_i16x16 => any::<[i16; 16]>().prop_map(vectoreyes::I16x16::from),
        fn roundtrip_vectoreyes_i32x4 => any::<[i32; 4]>().prop_map(vectoreyes::I32x4::from),
        fn roundtrip_vectoreyes_i32x8 => any::<[i32; 8]>().prop_map(vectoreyes::I32x8::from),
        fn roundtrip_vectoreyes_i64x2 => any::<[i64; 2]>().prop_map(vectoreyes::I64x2::from),
        fn roundtrip_vectoreyes_i64x4 => any::<[i64; 4]>().prop_map(vectoreyes::I64x4::from),
        fn roundtrip_vectoreyes_u8x16 => any::<[u8; 16]>().prop_map(vectoreyes::U8x16::from),
        fn roundtrip_vectoreyes_u8x32 => any::<[u8; 32]>().prop_map(vectoreyes::U8x32::from),
        fn roundtrip_vectoreyes_u16x8 => any::<[u16; 8]>().prop_map(vectoreyes::U16x8::from),
        fn roundtrip_vectoreyes_u16x16 => any::<[u16; 16]>().prop_map(vectoreyes::U16x16::from),
        fn roundtrip_vectoreyes_u32x4 => any::<[u32; 4]>().prop_map(vectoreyes::U32x4::from),
        fn roundtrip_vectoreyes_u32x8 => any::<[u32; 8]>().prop_map(vectoreyes::U32x8::from),
        fn roundtrip_vectoreyes_u64x2 => any::<[u64; 2]>().prop_map(vectoreyes::U64x2::from),
        fn roundtrip_vectoreyes_u64x4 => any::<[u64; 4]>().prop_map(vectoreyes::U64x4::from),
        fn roundtrip_array_0 => any::<u8>(),
        fn roundtrip_array_1 => any::<u16>(),
        fn roundtrip_array_2 => any::<[u8; 0]>(),
        fn roundtrip_array_3 => any::<[u16; 0]>(),
        fn roundtrip_array_4 => any::<[u8; 1]>(),
        fn roundtrip_array_5 => any::<[u16; 1]>(),
        fn roundtrip_array_6 => any::<[u8; 2]>(),
        fn roundtrip_array_7 => any::<[u16; 2]>(),
        fn roundtrip_array_8 => any::<[u8; 0]>(),
        fn roundtrip_array_9 => any::<[u16; 0]>(),
        fn roundtrip_array_10 => any::<[[u8; 0]; 0]>(),
        fn roundtrip_array_11 => any::<[[u16; 0]; 0]>(),
        fn roundtrip_array_12 => any::<[[u8; 1]; 0]>(),
        fn roundtrip_array_13 => any::<[[u16; 1]; 0]>(),
        fn roundtrip_array_14 => any::<[[u8; 2]; 0]>(),
        fn roundtrip_array_15 => any::<[[u16; 2]; 0]>(),
        fn roundtrip_array_16 => any::<[u8; 1]>(),
        fn roundtrip_array_17 => any::<[u16; 1]>(),
        fn roundtrip_array_18 => any::<[[u8; 0]; 1]>(),
        fn roundtrip_array_19 => any::<[[u16; 0]; 1]>(),
        fn roundtrip_array_20 => any::<[[u8; 1]; 1]>(),
        fn roundtrip_array_21 => any::<[[u16; 1]; 1]>(),
        fn roundtrip_array_22 => any::<[[u8; 2]; 1]>(),
        fn roundtrip_array_23 => any::<[[u16; 2]; 1]>(),
        fn roundtrip_array_24 => any::<[u8; 2]>(),
        fn roundtrip_array_25 => any::<[u16; 2]>(),
        fn roundtrip_array_26 => any::<[[u8; 0]; 2]>(),
        fn roundtrip_array_27 => any::<[[u16; 0]; 2]>(),
        fn roundtrip_array_28 => any::<[[u8; 1]; 2]>(),
        fn roundtrip_array_29 => any::<[[u16; 1]; 2]>(),
        fn roundtrip_array_30 => any::<[[u8; 2]; 2]>(),
        fn roundtrip_array_31 => any::<[[u16; 2]; 2]>(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_value_too_big_for_usize() {
        assert_eq!(
            "An integer could fit in a u64, but not in a usize".to_string(),
            format!("{ValueTooBigForUsize}")
        )
    }

    #[test]
    fn display_value_too_big_for_isize() {
        assert_eq!(
            "An integer could fit in a i64, but not in a isize",
            format!("{ValueTooBigForIsize}"),
        )
    }
}
