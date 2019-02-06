use crate::comm;
use fancy_garbling::Evaluator as Ev;
use fancy_garbling::{Fancy, Message, SyncIndex, Wire};
use ocelot::BlockObliviousTransfer;
use std::io::{Read, Write};
use std::marker::PhantomData;
use std::sync::{Arc, Mutex};

pub struct Evaluator<S: Send + Read + Write, OT: BlockObliviousTransfer<S>> {
    evaluator: Ev,
    stream: Arc<Mutex<S>>,
    inputs: Arc<Mutex<Vec<u16>>>,
    phantom: PhantomData<OT>,
}

impl<S: Send + Read + Write + 'static, OT: BlockObliviousTransfer<S>> Evaluator<S, OT> {
    pub fn new(stream: S, inputs: &[u16]) -> Self {
        let inputs = Arc::new(Mutex::new(inputs.to_vec()));
        let stream = Arc::new(Mutex::new(stream));
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

impl<S: Send + Read + Write, OT: BlockObliviousTransfer<S>> Fancy for Evaluator<S, OT> {
    type Item = Wire;

    fn garbler_input(&self, ix: Option<SyncIndex>, q: u16) -> Wire {
        self.evaluator.garbler_input(ix, q)
    }

    fn evaluator_input(&self, ix: Option<SyncIndex>, q: u16) -> Wire {
        assert!(ix.is_none());
        let ℓ = (q as f32).log(2.0).ceil() as u16;
        let input = self.inputs.lock().unwrap().pop().unwrap(); // XXX: unwrap
        let bs = (0..ℓ)
            .into_iter()
            .map(|i| input & (1 << i) != 0)
            .collect::<Vec<bool>>();
        let mut ot = OT::new();
        let mut stream = self.stream.lock().unwrap();
        let wires = ot.receive(&mut *stream, &bs).unwrap(); // XXX: remove unwrap
        let wire = wires
            .into_iter()
            .enumerate()
            .fold(Wire::zero(q), |r, (i, w)| {
                let w = super::block_to_wire(w, q);
                r.plus(&w.cmul((1 << i) as u16))
            });
        wire
    }

    fn evaluator_inputs(&self, ix: Option<SyncIndex>, qs: &[u16]) -> Vec<Wire> {
        assert!(ix.is_none());
        let ℓs = qs
            .into_iter()
            .map(|q| (*q as f32).log(2.0).ceil() as usize)
            .collect::<Vec<usize>>();
        let mut bs = Vec::with_capacity(ℓs.iter().sum());
        for ℓ in ℓs.iter() {
            let input = self.inputs.lock().unwrap().pop().unwrap(); // XXX: unwrap
            let mut bs_ = (0..*ℓ)
                .into_iter()
                .map(|i| input & (1 << i) != 0)
                .collect::<Vec<bool>>();
            bs.append(&mut bs_);
        }
        let mut ot = OT::new();
        let mut stream = self.stream.lock().unwrap();
        let wires_ = ot.receive(&mut *stream, &bs).unwrap(); // XXX: remove unwrap
        let mut start = 0;
        ℓs.into_iter()
            .zip(qs.into_iter())
            .map(|(ℓ, q)| {
                let range = start..start + ℓ;
                let chunk = &wires_[range];
                start = start + ℓ;
                let wire = chunk
                    .into_iter()
                    .enumerate()
                    .fold(Wire::zero(*q), |r, (i, w)| {
                        let w = super::block_to_wire(*w, *q);
                        r.plus(&w.cmul((1 << i) as u16))
                    });
                wire
            })
            .collect::<Vec<Wire>>()
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

    fn proj(&self, ix: Option<SyncIndex>, x: &Wire, q: u16, tt: Option<Vec<u16>>) -> Wire {
        self.evaluator.proj(ix, &x, q, tt)
    }

    fn output(&self, ix: Option<SyncIndex>, x: &Wire) {
        self.evaluator.output(ix, &x)
    }
}
