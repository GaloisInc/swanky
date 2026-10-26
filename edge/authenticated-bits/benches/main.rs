use std::iter::Copied;
use std::slice::Iter;

use criterion::{Criterion, criterion_group, criterion_main, measurement::WallTime};
use rand::RngExt;
use swanky_authenticated_bits::and_triples::{AndTriple, AndTripleGenerator};
use swanky_authenticated_bits::authbits::{AuthBit, AuthBitGenerator};
use swanky_authenticated_bits::authshares::{AuthShare, AuthShareGenerator};
use swanky_field_binary::F2;
use swanky_party::{either::PartyEither, party_system, private::PartyPrivate, ty_eq::Witness};
use swanky_rng::SwankyRng;

party_system! {
    mod ps {
        PartyA,
        PartyB,
    }
}
use ps::{PartyA, PartyB};

fn authbit_generators(
    prover_rng: &mut SwankyRng,
    verifier_rng: &mut SwankyRng,
) -> (AuthBitGenerator<PartyA>, AuthBitGenerator<PartyB>) {
    swanky_channel::local::local_channel_pair(
        |c| AuthBitGenerator::new(c, prover_rng),
        |c| AuthBitGenerator::new(c, verifier_rng),
    )
    .unwrap()
}

fn bench_auth_bits(c: &mut Criterion<WallTime>) {
    const COUNT: usize = 100_000;
    let mut prover_rng = swanky_rng::SwankyRng::new();
    let mut verifier_rng = swanky_rng::SwankyRng::new();
    let bits: Vec<F2> = (0..COUNT).map(|_| prover_rng.random::<F2>()).collect();

    let (mut generator_a, mut generator_b) = authbit_generators(&mut prover_rng, &mut verifier_rng);

    c.bench_function(&format!("generate_authbits::{COUNT}"), |b| {
        b.iter(|| {
            swanky_channel::local::local_channel_pair(
                |c| {
                    // The prover.
                    let mut authbits: Vec<AuthBit<PartyA>> = vec![];
                    generator_a.generate(
                        PartyEither::new(Witness::EQUAL_TYPES, bits.iter().copied()),
                        &mut authbits,
                        c,
                        &mut prover_rng,
                    )?;
                    Ok(())
                },
                |c| {
                    // The verifier.
                    let mut authbits: Vec<AuthBit<PartyB>> = vec![];
                    let input: PartyEither<_, Copied<Iter<'_, F2>>, _> =
                        PartyEither::new(Witness::EQUAL_TYPES, COUNT);
                    generator_b.generate(input, &mut authbits, c, &mut verifier_rng)?;
                    Ok(())
                },
            )
            .unwrap();
        });
    });
}

fn bench_auth_bits_open(c: &mut Criterion<WallTime>) {
    const COUNT: usize = 100_000;
    let mut prover_rng = swanky_rng::SwankyRng::new();
    let mut verifier_rng = swanky_rng::SwankyRng::new();
    let bits: Vec<F2> = (0..COUNT).map(|_| prover_rng.random::<F2>()).collect();

    let (mut generator_a, mut generator_b) = authbit_generators(&mut prover_rng, &mut verifier_rng);

    let (authbits_a, authbits_b) = swanky_channel::local::local_channel_pair(
        |c| {
            // The prover.
            let mut authbits: Vec<AuthBit<PartyA>> = vec![];
            generator_a.generate(
                PartyEither::new(Witness::EQUAL_TYPES, bits.iter().copied()),
                &mut authbits,
                c,
                &mut prover_rng,
            )?;
            Ok(authbits)
        },
        |c| {
            // The verifier.
            let mut authbits: Vec<AuthBit<PartyB>> = vec![];
            let input: PartyEither<_, Copied<Iter<'_, F2>>, _> =
                PartyEither::new(Witness::EQUAL_TYPES, COUNT);

            generator_b.generate(input, &mut authbits, c, &mut verifier_rng)?;
            Ok(authbits)
        },
    )
    .unwrap();
    c.bench_function(&format!("open_authbits::{COUNT}"), |b| {
        b.iter(|| {
            swanky_channel::local::local_channel_pair(
                |c| generator_a.open(&authbits_a, PartyPrivate::empty(Witness::EQUAL_TYPES), c),
                |c| {
                    let mut outputs = Vec::with_capacity(COUNT);
                    generator_b.open(&authbits_b, PartyPrivate::new(&mut outputs), c)
                },
            )
            .unwrap();
        });
    });
}

fn bench_auth_shares(c: &mut Criterion<WallTime>) {
    const COUNT: usize = 100_000;
    let mut prover_rng = swanky_rng::SwankyRng::new();
    let mut verifier_rng = swanky_rng::SwankyRng::new();

    let (mut generator_a, mut generator_b) = swanky_channel::local::local_channel_pair(
        |c| AuthShareGenerator::new(c, &mut prover_rng),
        |c| AuthShareGenerator::new(c, &mut verifier_rng),
    )
    .unwrap();

    c.bench_function(&format!("generate_authshares::{COUNT}"), |b| {
        b.iter(|| {
            swanky_channel::local::local_channel_pair(
                |c| {
                    // Party A (the "prover").
                    let mut authshares: Vec<AuthShare<PartyA>> = vec![];
                    generator_a.generate(COUNT, &mut authshares, c, &mut prover_rng)?;
                    Ok(())
                },
                |c| {
                    // Party B (the "verifier").
                    let mut authshares: Vec<AuthShare<PartyB>> = vec![];
                    generator_b.generate(COUNT, &mut authshares, c, &mut verifier_rng)?;
                    Ok(())
                },
            )
            .unwrap();
        });
    });
}

fn bench_and_triples(c: &mut Criterion<WallTime>) {
    const COUNT: usize = 100_000;
    let mut prover_rng = swanky_rng::SwankyRng::new();
    let mut verifier_rng = swanky_rng::SwankyRng::new();

    let (mut generator_a, mut generator_b) = swanky_channel::local::local_channel_pair(
        |c| AndTripleGenerator::new(c, &mut prover_rng),
        |c| AndTripleGenerator::new(c, &mut verifier_rng),
    )
    .unwrap();

    c.bench_function(&format!("generate_and_triples::{COUNT}"), |b| {
        b.iter(|| {
            swanky_channel::local::local_channel_pair(
                |c| {
                    // Party A (the "prover").
                    let mut triples: Vec<AndTriple<PartyA>> = vec![];
                    generator_a.generate(COUNT, &mut triples, c, &mut prover_rng)?;
                    Ok(())
                },
                |c| {
                    // Party B (the "verifier").
                    let mut triples: Vec<AndTriple<PartyB>> = vec![];
                    generator_b.generate(COUNT, &mut triples, c, &mut verifier_rng)?;
                    Ok(())
                },
            )
            .unwrap();
        });
    });
}

fn bench_fix_and_triples(c: &mut Criterion<WallTime>) {
    const COUNT: usize = 100_000;
    let mut prover_rng = swanky_rng::SwankyRng::new();
    let mut verifier_rng = swanky_rng::SwankyRng::new();

    let (mut generator_a, mut generator_b) = swanky_channel::local::local_channel_pair(
        |c| AndTripleGenerator::new(c, &mut prover_rng),
        |c| AndTripleGenerator::new(c, &mut verifier_rng),
    )
    .unwrap();

    let (triples_a, triples_b) = swanky_channel::local::local_channel_pair(
        |c| {
            // Party A (the "prover").
            let mut triples: Vec<AndTriple<PartyA>> = vec![];
            generator_a.generate(COUNT, &mut triples, c, &mut prover_rng)?;
            Ok(triples)
        },
        |c| {
            // Party B (the "verifier").
            let mut triples: Vec<AndTriple<PartyB>> = vec![];
            generator_b.generate(COUNT, &mut triples, c, &mut verifier_rng)?;
            Ok(triples)
        },
    )
    .unwrap();

    let (shares_a, shares_b) = swanky_channel::local::local_channel_pair(
        |c| {
            // Party A (the "prover").
            let mut authshares: Vec<AuthShare<PartyA>> = vec![];
            let mut generator: AuthShareGenerator<_> = AuthShareGenerator::new(c, &mut prover_rng)?;
            generator.generate(2 * COUNT, &mut authshares, c, &mut prover_rng)?;
            Ok(authshares)
        },
        |c| {
            // Party B (the "verifier").
            let mut authshares: Vec<AuthShare<PartyB>> = vec![];
            let mut generator: AuthShareGenerator<_> =
                AuthShareGenerator::new(c, &mut verifier_rng)?;
            generator.generate(2 * COUNT, &mut authshares, c, &mut verifier_rng)?;
            Ok(authshares)
        },
    )
    .unwrap();

    c.bench_function(&format!("fix_and_triples::{COUNT}"), |b| {
        b.iter(|| {
            // Convert the random triples to known triples.
            let mut cs_a = vec![];
            let mut cs_b = vec![];
            swanky_channel::local::local_channel_pair(
                |channel| {
                    generator_a.to_known_triple(
                        &triples_a,
                        &shares_a[..COUNT],
                        &shares_a[COUNT..],
                        &mut cs_a,
                        channel,
                    )?;
                    Ok(())
                },
                |channel| {
                    generator_b.to_known_triple(
                        &triples_b,
                        &shares_b[..COUNT],
                        &shares_b[COUNT..],
                        &mut cs_b,
                        channel,
                    )?;
                    Ok(())
                },
            )
            .unwrap();
        });
    });
}

criterion_group!(authbits, bench_auth_bits, bench_auth_bits_open);
criterion_group!(authshares, bench_auth_shares);
criterion_group!(and_triples, bench_and_triples);
criterion_group!(fix_and_triples, bench_fix_and_triples);

criterion_main!(authbits, authshares, and_triples, fix_and_triples);
