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
    use crate::{Circuit, circuitgen::random_circuit};
    use proptest::prelude::*;
    use rand::{SeedableRng, distr::Uniform, prelude::Distribution};
    use swanky_rng::SwankyRng;
    use vectoreyes::U8x16;

    fn any_seed() -> impl Strategy<Value = U8x16> {
        any::<u128>().prop_map(U8x16::from)
    }

    macro_rules! test_serialization {
        ($name:ident, $f:ty) => {
            proptest! {
                #[test]
                fn $name(seed in any_seed()) {
                    let mut rng = SwankyRng::from_seed(seed);
                    let ninputs_range = Uniform::try_from(2..100).expect("bounds finite and low < high");
                    let noutputs_range = Uniform::try_from(2..100).expect("bounds finite and low < high");
                    let ngates_range = Uniform::try_from(200..2000).expect("bounds finite and low < high");
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

    test_serialization!(test_serialization_f2, swanky_field_binary::F2);
    test_serialization!(test_serialization_f61p, swanky_field_f61p::F61p);
}
