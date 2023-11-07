use proptest::collection::vec as pvec;
use proptest::prelude::*;

use crate::{local::LocalSocket, BufferSizes, Channel};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sender {
    A,
    B,
}
use Sender::*;

fn runit(mut sock: LocalSocket, whoami: Sender, data: Vec<(Vec<u8>, Sender)>) {
    Channel::with_sizes(&mut sock, BufferSizes { read: 2, write: 2 }, |channel| {
        let mut read_buf = vec![0; 256];
        for (bytes, who_sends) in data.into_iter() {
            if who_sends == whoami {
                channel.write_bytes(&bytes).unwrap();
            } else {
                channel.read_bytes(&mut read_buf[0..bytes.len()]).unwrap();
                assert_eq!(&read_buf[0..bytes.len()], bytes.as_slice());
            }
        }
        Ok(())
    })
    .unwrap();
}

proptest! {
    #[test]
    fn test_channel(
        data in pvec((
            prop_oneof![
                pvec(any::<u8>(), 0..=2),
                pvec(any::<u8>(), 2..=8),
            ],
            // The sender
            prop_oneof![
                Just(A),
                Just(B),
            ]
        ), 0..512),
    ) {
        let (a, b) = LocalSocket::pair().unwrap();
        std::thread::scope(|scope|{
            let data2 = data.clone();
            scope.spawn(move ||runit(b, B, data2));
            runit(a, A, data);
        });
    }
}
