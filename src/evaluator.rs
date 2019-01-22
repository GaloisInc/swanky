use crate::comm;
use failure::Error;
use fancy_garbling::garble;
use fancy_garbling::garble::{Evaluator, GateType, Message};
use fancy_garbling::wire::Wire;
use ocelot::ot::ObliviousTransfer;
use ocelot::util::bitvec_to_u128;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

pub fn evaluate<S, OT>(stream: S, input: &[u16]) -> Result<garble::Evaluator, Error>
where
    S: Read + Write + Send + 'static,
    OT: ObliviousTransfer<S>,
{
    let stream = Arc::new(Mutex::new(stream));
    let mut input = input.to_vec().into_iter();
    let callback = move |gate| {
        let bv = match gate {
            GateType::EvaluatorInput { modulus } => {
                let mut ot = OT::new(stream.clone());
                let wire = ot.receive(&[input.next().unwrap()], 128).unwrap();
                Message::EvaluatorInput(Wire::from_u128(bitvec_to_u128(&wire[0]), modulus))
            }
            GateType::Other => {
                let mut stream = stream.lock().unwrap();
                let bytes = comm::receive(&mut *stream).expect("Failed to receive message");
                let msg = Message::from_bytes(&bytes).expect("Failed to convert bytes to message");
                msg
            }
        };
        bv
    };
    Ok(Evaluator::new(callback))
}
