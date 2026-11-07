use criterion::criterion_main;

use swanky_field_ff_primes::{
    F2e19x3e26, F127p, F128p, F256p, F384p, F384q, F400p, Fbls12381, Fbn254, Secp256k1,
    Secp256k1order,
};
use swanky_field_test::bench_field;

bench_field!(f2e19x3226, F2e19x3e26);
bench_field!(f127p, F127p);
bench_field!(f128p, F128p);
bench_field!(f256p, F256p);
bench_field!(f384p, F384p);
bench_field!(f384q, F384q);
bench_field!(f400p, F400p);
bench_field!(fbls12381, Fbls12381);
bench_field!(fbn254, Fbn254);
bench_field!(secp256k1, Secp256k1);
bench_field!(secp256k1order, Secp256k1order);

criterion_main!(
    f2e19x3226::f2e19x3226,
    f127p::f127p,
    f128p::f128p,
    f256p::f256p,
    f384p::f384p,
    f384q::f384q,
    f400p::f400p,
    fbls12381::fbls12381,
    fbn254::fbn254,
    secp256k1::secp256k1,
    secp256k1order::secp256k1order
);
