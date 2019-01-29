use crate::comm;
use fancy_garbling::Garbler as Gb;
use fancy_garbling::{Fancy, Message, SyncIndex, Wire};
use ocelot::ObliviousTransfer;
use std::io::{Read, Write};
use std::marker::PhantomData;
use std::sync::{Arc, Mutex};

pub struct Garbler<S: Send + Read + Write, OT: ObliviousTransfer<S>> {
    garbler: Gb,
    stream: Arc<Mutex<S>>,
    phantom: PhantomData<OT>,
}

impl<S: Send + Read + Write + 'static, OT: ObliviousTransfer<S>> Garbler<S, OT> {
    pub fn new(stream: S, inputs: &[u16]) -> Self {
        let stream = Arc::new(Mutex::new(stream));
        let inputs = inputs.to_vec();
        let mut inputs = inputs.into_iter();
        let stream_ = stream.clone();
        let callback = move |_idx, msg| {
            let m = match msg {
                Message::UnencodedGarblerInput { zero, delta } => {
                    let input = inputs.next().unwrap();
                    Message::GarblerInput(zero.plus(&delta.cmul(input)))
                }
                Message::UnencodedEvaluatorInput { zero: _, delta: _ } => {
                    panic!("There should not be an UnencodedEvaluatorInput message in the garbler");
                }
                Message::EvaluatorInput(_) => {
                    panic!("There should not be an EvaluatorInput message in the garbler");
                }
                m => m,
            };
            let mut stream = stream_.lock().unwrap();
            comm::send(&mut *stream, &m.to_bytes()).expect("Unable to send message");
        };
        let gb = Gb::new(callback);
        Garbler {
            garbler: gb,
            stream: stream,
            phantom: PhantomData,
        }
    }
}

impl<S: Send + Read + Write, OT: ObliviousTransfer<S>> Fancy for Garbler<S, OT> {
    type Item = Wire;

    fn garbler_input(&self, ix: Option<SyncIndex>, q: u16) -> Wire {
        self.garbler.garbler_input(ix, q)
    }

    fn evaluator_input(&self, _ix: Option<SyncIndex>, q: u16) -> Wire {
        let ℓ = (q as f64).log(2.0).ceil() as u16;
        let δ = self.garbler.delta(q);
        let mut ot = OT::new(self.stream.clone());
        let mut wire = Wire::zero(q);
        let inputs = (0..ℓ)
            .into_iter()
            .map(|i| {
                let zero = Wire::rand(&mut rand::thread_rng(), q);
                let one = zero.plus(&δ);
                wire = wire.plus(&zero.cmul(1 << i));
                (super::wire_to_u8vec(zero), super::wire_to_u8vec(one))
            })
            .collect::<Vec<(Vec<u8>, Vec<u8>)>>();
        ot.send(&inputs).unwrap(); // XXX: remove unwrap
        wire
    }

    fn constant(&self, ix: Option<SyncIndex>, x: u16, q: u16) -> Wire {
        self.garbler.constant(ix, x, q)
    }

    fn add(&self, x: &Wire, y: &Wire) -> Wire {
        self.garbler.add(x, y)
    }

    fn sub(&self, x: &Wire, y: &Wire) -> Wire {
        self.garbler.sub(x, y)
    }

    fn cmul(&self, x: &Wire, c: u16) -> Wire {
        self.garbler.cmul(x, c)
    }

    fn mul(&self, ix: Option<SyncIndex>, x: &Wire, y: &Wire) -> Wire {
        self.garbler.mul(ix, x, y)
    }

    fn proj(&self, ix: Option<SyncIndex>, x: &Wire, q: u16, tt: &[u16]) -> Wire {
        self.garbler.proj(ix, x, q, tt)
    }

    fn output(&self, ix: Option<SyncIndex>, x: &Wire) {
        self.garbler.output(ix, x)
    }
}
