/// This module (de)serializes the `Index` type as a `u32`.
pub mod serde_index {
    use crate::circuit::Index;

    pub fn serialize<S: serde::Serializer>(value: &Index, ser: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error;

        let value = u32::try_from(*value).map_err(Error::custom)?;
        ser.serialize_u32(value)
    }

    pub fn deserialize<'de, D: serde::de::Deserializer<'de>>(de: D) -> Result<Index, D::Error> {
        use serde::de::Error;

        struct MyVisitor;

        impl<'de> serde::de::Visitor<'de> for MyVisitor {
            type Value = Index;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "a wire index")
            }

            fn visit_u32<E: Error>(self, v: u32) -> Result<Self::Value, E> {
                usize::try_from(v).map_err(|e| Error::custom(e))
            }
        }

        de.deserialize_u32(MyVisitor)
    }
}

#[cfg(test)]
mod tests {
    use crate::{circuitgen::random_circuit, Circuit};
    use proptest::prelude::*;
    use rand::{distributions::Uniform, prelude::Distribution, SeedableRng};
    use scuttlebutt::{AesRng, Block};

    fn any_seed() -> impl Strategy<Value = Block> {
        any::<u128>().prop_map(Block::from)
    }

    macro_rules! test_serialization {
        ($name:ident, $f:ty) => {
            proptest! {
                #[test]
                fn $name(seed in any_seed()) {
                    let mut rng = AesRng::from_seed(seed);
                    let ninputs_range = Uniform::from(2..100);
                    let noutputs_range = Uniform::from(2..100);
                    let ngates_range = Uniform::from(200..2000);
                    let ninputs = ninputs_range.sample(&mut rng);
                    let noutputs = noutputs_range.sample(&mut rng);
                    let ngates = ngates_range.sample(&mut rng);
                    let (circuit, witness): (Circuit<$f>, Vec<_>) =
                        random_circuit(ninputs, ngates, noutputs, &mut rng);
                    let mut wires = Vec::with_capacity(circuit.nwires());
                    let outputs = circuit.eval(&witness, &mut wires).to_vec();
                    let serialized = bincode::serialize(&circuit).unwrap();
                    let circuit_: Circuit<$f> = bincode::deserialize(&serialized).unwrap();
                    let outputs_ = circuit_.eval(&witness, &mut wires).to_vec();
                    for (x, y) in outputs.iter().zip(outputs_.iter()) {
                        assert_eq!(x, y);
                    }
                }
            }
        };
    }

    test_serialization!(test_serialization_f2, scuttlebutt::field::F2);
    test_serialization!(test_serialization_f61p, scuttlebutt::field::F61p);
}
