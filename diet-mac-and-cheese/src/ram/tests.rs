#[test]
fn test_ram() {
    use std::{
        io::{BufReader, BufWriter},
        os::unix::net::UnixStream,
    };

    use ocelot::svole::{LPN_EXTEND_MEDIUM, LPN_SETUP_MEDIUM};
    use rand::SeedableRng;
    use scuttlebutt::{AesRng, Channel};
    use swanky_field_f61p::F61p;
    use swanky_party::{Prover, Verifier};

    use crate::{backend_trait::BackendT, svole_trait::Svole, DietMacAndCheese};

    use super::{protocol::DoraRam, Arithmetic, PRE_ALLOC_MEM, PRE_ALLOC_STEPS};

    const REPEATS: usize = 5;
    let (sender, receiver) = UnixStream::pair().unwrap();

    let handle = std::thread::spawn(move || {
        let rng = AesRng::from_seed(Default::default());
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = Channel::new(reader, writer);

        let mut prover: DietMacAndCheese<Prover, F61p, F61p, _, Svole<_, _, _>> =
            DietMacAndCheese::init(
                &mut channel,
                rng,
                LPN_SETUP_MEDIUM,
                LPN_EXTEND_MEDIUM,
                false,
            )
            .unwrap();

        for _ in 0..REPEATS {
            let mut ram = DoraRam::<Prover, F61p, F61p, _, _, _>::new(
                &mut prover,
                2,
                Arithmetic::new(PRE_ALLOC_MEM),
            );

            for i in 0..(PRE_ALLOC_STEPS - PRE_ALLOC_MEM) {
                if i & 0xffff == 0 {
                    println!("{:x} {:x} {:x}", i, 1 << 20, 1 << 23);
                }
                let addr = rand::random::<u32>() % (PRE_ALLOC_MEM as u32);
                let addr = F61p::try_from(addr as u128).unwrap();
                let addr = prover.input_private(Some(addr)).unwrap();

                let value = ram.remove(&mut prover, &[addr]).unwrap();

                ram.insert(&mut prover, &[addr], &value).unwrap();
            }
            ram.finalize(&mut prover).unwrap();
        }

        prover.finalize().unwrap();

        println!("done");
    });

    {
        let rng = AesRng::from_seed(Default::default());
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);

        let mut verifier: DietMacAndCheese<Verifier, F61p, F61p, _, Svole<_, _, _>> =
            DietMacAndCheese::init(
                &mut channel,
                rng,
                LPN_SETUP_MEDIUM,
                LPN_EXTEND_MEDIUM,
                false,
            )
            .unwrap();

        for _ in 0..REPEATS {
            let mut ram = DoraRam::<Verifier, F61p, F61p, _, _, _>::new(
                &mut verifier,
                2,
                Arithmetic::new(PRE_ALLOC_MEM),
            );
            for _ in 0..(PRE_ALLOC_STEPS - PRE_ALLOC_MEM) {
                let addr = verifier.input_private(None).unwrap();
                let value = ram.remove(&mut verifier, &[addr]).unwrap();
                ram.insert(&mut verifier, &[addr], &value).unwrap();
            }
            ram.finalize(&mut verifier).unwrap();
        }
        verifier.finalize().unwrap();
    }

    handle.join().unwrap();
}
