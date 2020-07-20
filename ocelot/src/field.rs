use ff::PrimeFieldDecodingError;
//use ff::PrimeField;
extern crate  rand;
#[derive(PrimeField)]
#[PrimeFieldModulus = "52435875175126190479447740508185965837690552500527637822603658699938581184513"]
#[PrimeFieldGenerator = "7"]
struct Fp(FpRepr);