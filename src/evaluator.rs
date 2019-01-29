use crate::comm;
use fancy_garbling::Evaluator as Ev;
use fancy_garbling::{Fancy, Message, SyncIndex, Wire};
use ocelot::ObliviousTransfer;
use std::io::{Read, Write};
use std::marker::PhantomData;
use std::sync::{Arc, Mutex};

pub struct Evaluator<S: Send + Read + Write, OT: ObliviousTransfer<S>> {
    evaluator: Ev,
    stream: Arc<Mutex<S>>,
    inputs: Arc<Mutex<Vec<u16>>>,
    phantom: PhantomData<OT>,
}

impl<S: Send + Read + Write + 'static, OT: ObliviousTransfer<S>> Evaluator<S, OT> {
    pub fn new(stream: S, inputs: &[u16]) -> Self {
        let stream = Arc::new(Mutex::new(stream));
        let inputs = Arc::new(Mutex::new(inputs.to_vec()));
        let stream_ = stream.clone();
        let callback = move || {
            let mut stream = stream_.lock().unwrap();
            let bytes = comm::receive(&mut *stream).unwrap(); // XXX: unwrap
            let msg = Message::from_bytes(&bytes).unwrap(); // XXX: unwrap
            (None, msg)
        };
        let ev = Ev::new(callback);
        Evaluator {
            evaluator: ev,
            stream: stream,
            inputs: inputs,
            phantom: PhantomData,
        }
    }

    pub fn decode_output(&self) -> Vec<u16> {
        self.evaluator.decode_output()
    }
}

impl<S: Send + Read + Write, OT: ObliviousTransfer<S>> Fancy for Evaluator<S, OT> {
    type Item = Wire;

    fn garbler_input(&self, ix: Option<SyncIndex>, q: u16) -> Wire {
        self.evaluator.garbler_input(ix, q)
    }

    fn evaluator_input(&self, _ix: Option<SyncIndex>, q: u16) -> Wire {
        let ℓ = (q as f64).log(2.0).ceil() as u16;
        let input = self.inputs.lock().unwrap().pop().unwrap(); // XXX: unwrap
        let bs = (0..ℓ)
            .into_iter()
            .map(|i| input & (1 << i) != 0)
            .collect::<Vec<bool>>();
        let mut ot = OT::new(self.stream.clone());
        let mut wire = Wire::zero(q);
        for (i, b) in bs.into_iter().enumerate() {
            let w = ot.receive(&[b], 16).unwrap(); // XXX: unwrap
            let w = super::u8vec_to_wire(&w[0], q);
            wire = wire.plus(&w.cmul((1 << i) as u16));
        }
        wire
    }

    fn constant(&self, ix: Option<SyncIndex>, x: u16, q: u16) -> Wire {
        self.evaluator.constant(ix, x, q)
    }

    fn add(&self, x: &Wire, y: &Wire) -> Wire {
        self.evaluator.add(&x, &y)
    }

    fn sub(&self, x: &Wire, y: &Wire) -> Wire {
        self.evaluator.sub(&x, &y)
    }

    fn cmul(&self, x: &Wire, c: u16) -> Wire {
        self.evaluator.cmul(&x, c)
    }

    fn mul(&self, ix: Option<SyncIndex>, x: &Wire, y: &Wire) -> Wire {
        self.evaluator.mul(ix, &x, &y)
    }

    fn proj(&self, ix: Option<SyncIndex>, x: &Wire, q: u16, tt: &[u16]) -> Wire {
        self.evaluator.proj(ix, &x, q, tt)
    }

    fn output(&self, ix: Option<SyncIndex>, x: &Wire) {
        self.evaluator.output(ix, &x)
    }
}
