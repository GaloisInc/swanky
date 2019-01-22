use crate::comm;
use failure::Error;
use fancy_garbling::garble;
use fancy_garbling::garble::Message;
use ocelot::ot::ObliviousTransfer;
use ocelot::util::u128_to_bitvec;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

pub fn garble<S, OT>(stream: S, input: &[u16]) -> Result<garble::Garbler, Error>
where
    S: Read + Write + Send + 'static,
    OT: ObliviousTransfer<S>,
{
    let mut input = input.to_vec().into_iter();
    let stream = Arc::new(Mutex::new(stream));
    let callback = move |msg: Message| {
        let m = match msg {
            Message::UnencodedGarblerInput { zero, delta } => {
                Message::GarblerInput(zero.plus(&delta.cmul(input.next().unwrap())))
            }
            Message::UnencodedEvaluatorInput { zero, delta } => {
                let mut ot = OT::new(stream.clone());
                ot.send(&[(
                    u128_to_bitvec(zero.as_u128()),
                    u128_to_bitvec(zero.plus(&delta).as_u128()),
                )])
                .unwrap();
                return ();
            }
            m => m,
        };
        let mut stream = stream.lock().unwrap();
        comm::send(&mut *stream, &m.to_bytes()).expect("Unable to send message");
    };
    Ok(garble::Garbler::new(callback))
}
