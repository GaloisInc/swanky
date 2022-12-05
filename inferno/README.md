# `inferno`

`inferno` is an implementation of the non-interactive variant of the
[Limbo zero knowledge proof protocol](https://eprint.iacr.org/2021/215).

## Example

```rust
let mut rng = AesRng::new();
let (circuit, witness) = simple_arith_circuit::circuitgen::random_zero_circuit::<F64b>(10, 100, &mut rng);
let proof = Proof::<F64b, 16>::new(&circuit, &witness, 8, 40, &mut rng).unwrap();
let result = proof.verify(&circuit, 8, 40).unwrap();
assert_eq!(result, true);
```