#[test]
fn test_arithmetic_ram() {
    use rand::SeedableRng;
    use swanky_channel::local::local_channel_pair;
    use swanky_field_f61p::F61p;
    use swanky_rng::SwankyRng;
    use swanky_svole_wykw::{LPN_EXTEND_SMALL, LPN_SETUP_SMALL};

    use crate::{
        DietMacAndCheese,
        backend_trait::BackendT,
        party::{Prover, Verifier},
        svole_trait::Svole,
    };

    use super::{Arithmetic, protocol::DoraRam};

    const RAM_SIZE: usize = 100;
    const RAM_STEPS: usize = 100;

    local_channel_pair(
        |channel| {
            let rng = SwankyRng::from_seed(Default::default());
            let mut verifier: DietMacAndCheese<Verifier, F61p, F61p, Svole<_, _, _>> =
                DietMacAndCheese::init(channel, rng, LPN_SETUP_SMALL, LPN_EXTEND_SMALL, false)?;

            let mut ram = DoraRam::<Verifier, F61p, F61p, _, _>::new(
                vec![Default::default()],
                2,
                Arithmetic::new(RAM_SIZE),
            );
            for _ in 0..RAM_STEPS {
                let addr = verifier.input_private(None, channel)?;
                let value = ram.remove(&mut verifier, &[addr], channel)?;
                ram.insert(&mut verifier, &[addr], &value)?;
            }

            ram.finalize(&mut verifier, channel)?;
            verifier.finalize(channel)
        },
        |channel| {
            let rng = SwankyRng::from_seed(Default::default());
            let mut prover: DietMacAndCheese<Prover, F61p, F61p, Svole<_, _, _>> =
                DietMacAndCheese::init(channel, rng, LPN_SETUP_SMALL, LPN_EXTEND_SMALL, false)?;

            let mut ram = DoraRam::<Prover, F61p, F61p, _, _>::new(
                vec![Default::default()],
                2,
                Arithmetic::new(RAM_SIZE),
            );

            for _ in 0..RAM_STEPS {
                let addr = rand::random::<u32>() % (RAM_SIZE as u32);
                let addr = F61p::try_from(addr as u128).unwrap();
                let addr = prover.input_private(Some(addr), channel)?;

                let value = ram.remove(&mut prover, &[addr], channel)?;

                ram.insert(&mut prover, &[addr], &value)?;
            }

            ram.finalize(&mut prover, channel)?;
            prover.finalize(channel)
        },
    )
    .unwrap();
}

#[test]
fn test_boolean_ram() {
    use rand::SeedableRng;
    use swanky_channel::local::local_channel_pair;
    use swanky_field::FiniteRing;
    use swanky_field_binary::{F2, F40b};
    use swanky_rng::SwankyRng;
    use swanky_svole_wykw::{LPN_EXTEND_SMALL, LPN_SETUP_SMALL};

    use crate::{
        DietMacAndCheese,
        backend_trait::BackendT,
        party::{Prover, Verifier},
        svole_trait::Svole,
    };

    use super::{Boolean, protocol::DoraRam};

    const RAM_SIZE: usize = 100;
    const RAM_STEPS: usize = 100;

    local_channel_pair(
        |channel| {
            let rng = SwankyRng::from_seed(Default::default());
            let mut verifier: DietMacAndCheese<Verifier, F2, F40b, Svole<_, _, _>> =
                DietMacAndCheese::init(channel, rng, LPN_SETUP_SMALL, LPN_EXTEND_SMALL, false)?;

            let mut ram = DoraRam::<Verifier, F2, F40b, _, _>::new(
                vec![Default::default(); 7],
                2,
                Boolean::new(7, 7, RAM_SIZE),
            );
            for _ in 0..RAM_STEPS {
                let addr: Vec<_> = (0..7)
                    .map(|_| verifier.input_private(None, channel).unwrap())
                    .collect();
                let value = ram.remove(&mut verifier, &addr, channel)?;
                ram.insert(&mut verifier, &addr, &value)?;
            }

            ram.finalize(&mut verifier, channel)?;
            verifier.finalize(channel)
        },
        |channel| {
            let rng = SwankyRng::from_seed(Default::default());
            let mut prover: DietMacAndCheese<Prover, F2, F40b, Svole<_, _, _>> =
                DietMacAndCheese::init(channel, rng, LPN_SETUP_SMALL, LPN_EXTEND_SMALL, false)?;

            let mut ram = DoraRam::<Prover, F2, F40b, _, _>::new(
                vec![Default::default(); 7],
                2,
                Boolean::new(7, 7, RAM_SIZE),
            );

            for _ in 0..RAM_STEPS {
                let addr = vec![
                    F2::ZERO,
                    rand::random::<F2>(),
                    rand::random::<F2>(),
                    rand::random::<F2>(),
                    rand::random::<F2>(),
                    rand::random::<F2>(),
                    rand::random::<F2>(),
                ];
                let addr: Vec<_> = addr
                    .into_iter()
                    .map(|b| prover.input_private(Some(b), channel).unwrap())
                    .collect();

                let value = ram.remove(&mut prover, &addr, channel)?;

                ram.insert(&mut prover, &addr, &value)?;
            }

            ram.finalize(&mut prover, channel)?;
            prover.finalize(channel)
        },
    )
    .unwrap();
}
