//! Testing the initialization phase in Base Psi
#[cfg(test)]
mod tests {

    use crate::psi::circuit_psi::base_psi::{
        receiver::OpprfReceiver, sender::OpprfSender, BasePsi,
    };
    use rand::SeedableRng;
    use scuttlebutt::{AesRng, Channel};

    use proptest::prelude::*;
    use std::{
        io::{BufReader, BufWriter},
        os::unix::net::UnixStream,
    };
    proptest! {
            #[test]
            fn test_psty_init_receiver_succeeded(seed_sx in any::<u64>(), seed_rx in any::<u64>()){
                let (sender, receiver) = UnixStream::pair().unwrap();

                std::thread::spawn(move || {
                    let mut rng = AesRng::seed_from_u64(seed_sx);
                    let reader = BufReader::new(sender.try_clone().unwrap());
                    let writer = BufWriter::new(sender);
                    let mut channel = Channel::new(reader, writer);

                    let _ = OpprfSender::init(&mut channel, &mut rng, true);
                });
                let mut rng = AesRng::seed_from_u64(seed_rx);
                let reader = BufReader::new(receiver.try_clone().unwrap());
                let writer = BufWriter::new(receiver);
                let mut channel = Channel::new(reader, writer);

                let receiver = OpprfReceiver::init(&mut channel, &mut rng, true);
                prop_assert!(
                    !receiver.is_err(),
                    "PSTY Initialization failed on the receiver side"
                );

        }
        #[test]
         fn test_psty_init_sender_succeeded(seed_sx in any::<u64>(), seed_rx in any::<u64>()){
                let (sender, receiver) = UnixStream::pair().unwrap();

                let sender = std::thread::spawn(move || {
                    let mut rng = AesRng::seed_from_u64(seed_sx);
                    let reader = BufReader::new(sender.try_clone().unwrap());
                    let writer = BufWriter::new(sender);
                    let mut channel = Channel::new(reader, writer);

                   OpprfSender::init(&mut channel, &mut rng, true)

                });
                let mut rng = AesRng::seed_from_u64(seed_rx);
                let reader = BufReader::new(receiver.try_clone().unwrap());
                let writer = BufWriter::new(receiver);
                let mut channel = Channel::new(reader, writer);

                let _ = OpprfReceiver::init(&mut channel, &mut rng, true);

                 prop_assert!(
                    !sender.join().unwrap().is_err(),
                    "PSTY Initialization failed on the sender side"
                );
        }
    }
}
