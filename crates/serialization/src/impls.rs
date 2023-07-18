use generic_array::GenericArray;

use super::{
    ByteElementDeserializer, ByteElementSerializer, BytesDeserializationCannotFail,
    CanonicalSerialize,
};

impl CanonicalSerialize for () {
    type Serializer = ByteElementSerializer<Self>;
    type Deserializer = ByteElementDeserializer<Self>;
    type ByteReprLen = generic_array::typenum::U0;
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
