use crate::comm;
use fancy_garbling::Garbler as Gb;
use fancy_garbling::{Fancy, Message, SyncIndex, Wire};
use ocelot::{Block, BlockObliviousTransfer};
use rand::rngs::ThreadRng;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

pub struct Garbler<S: Send + Read + Write, OT: BlockObliviousTransfer<S>> {
    garbler: Gb,
    stream: Arc<Mutex<S>>,
    ot: Arc<Mutex<OT>>,
    rng: Arc<Mutex<ThreadRng>>,
}

impl<S: Send + Read + Write + 'static, OT: BlockObliviousTransfer<S>> Garbler<S, OT> {
    pub fn new(stream: S, inputs: &[u16]) -> Self {
        let inputs = inputs.to_vec();
        let mut inputs = inputs.into_iter();
        let stream = Arc::new(Mutex::new(stream));
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
        let garbler = Gb::new(callback);
        let rng = Arc::new(Mutex::new(rand::thread_rng()));
        let ot = Arc::new(Mutex::new(OT::new()));
        Garbler {
            garbler,
            stream,
            ot,
            rng,
        }
    }

    fn _evaluator_input(&self, q: u16) -> (Wire, Vec<(Block, Block)>) {
        let ℓ = (q as f64).log(2.0).ceil() as u16;
        let δ = self.garbler.delta(q);
        let mut wire = Wire::zero(q);
        let mut rng = self.rng.lock().unwrap();
        let inputs = (0..ℓ)
            .into_iter()
            .map(|i| {
                let zero = Wire::rand(&mut *rng, q);
                let one = zero.plus(&δ);
                wire = wire.plus(&zero.cmul(1 << i));
                (super::wire_to_block(zero), super::wire_to_block(one))
            })
            .collect::<Vec<(Block, Block)>>();
        (wire, inputs)
    }
}

impl<S: Send + Read + Write + 'static, OT: BlockObliviousTransfer<S>> Fancy for Garbler<S, OT> {
    type Item = Wire;

    fn garbler_input(&self, ix: Option<SyncIndex>, q: u16) -> Wire {
        self.garbler.garbler_input(ix, q)
    }

    fn evaluator_input(&self, ix: Option<SyncIndex>, q: u16) -> Wire {
        assert!(ix.is_none());
        let (wire, inputs) = self._evaluator_input(q);
        let mut stream = self.stream.lock().unwrap();
        let mut ot = self.ot.lock().unwrap();
        ot.send(&mut *stream, &inputs).unwrap(); // XXX: remove unwrap
        wire
    }

    fn evaluator_inputs(&self, ix: Option<SyncIndex>, qs: &[u16]) -> Vec<Wire> {
        assert!(ix.is_none());
        let n = qs.len();
        let ℓs = qs.into_iter().map(|q| (*q as f32).log(2.0).ceil() as usize);
        let mut wires = Vec::with_capacity(n);
        let mut inputs = Vec::with_capacity(ℓs.sum());
        for q in qs.into_iter() {
            let (wire, mut input) = self._evaluator_input(*q);
            wires.push(wire);
            inputs.append(&mut input);
        }
        let mut stream = self.stream.lock().unwrap();
        let mut ot = self.ot.lock().unwrap();
        ot.send(&mut *stream, &inputs).unwrap(); // XXX: remove unwrap
        wires
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

    fn proj(&self, ix: Option<SyncIndex>, x: &Wire, q: u16, tt: Option<Vec<u16>>) -> Wire {
        self.garbler.proj(ix, x, q, tt)
    }

    fn output(&self, ix: Option<SyncIndex>, x: &Wire) {
        self.garbler.output(ix, x)
    }
}
