use failure::Error;
use fancy_garbling::circuit::Circuit as _Circuit;
use fancy_garbling::garble;
use fancy_garbling::garble::{Decoder, GarbledCircuit};
use fancy_garbling::wire;
use std::path::Path;

pub struct Circuit {
    circ: _Circuit,
}

impl Circuit {
    pub fn new(circuit: &Path) -> Result<Self, Error> {
        let circuit = circuit.to_str().unwrap();
        let c = _Circuit::from_file(circuit)?;
        Ok(Circuit { circ: c })
    }

    pub fn info(&self) -> Result<(), Error> {
        self.circ.print_info();
        Ok(())
    }

    pub fn garble(&self, inputs: &[u16]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), Error> {
        let (en, de, ev) = garble::garble(&self.circ);
        if inputs.len() != self.circ.num_garbler_inputs() {
            return Err(failure::err_msg("Invalid number of inputs to encode"));
        }
        let inputs = en.encode_garbler_inputs(inputs);
        let en = wire::wires_to_bytes(&inputs);
        let de = de.to_bytes();
        let ev = ev.to_bytes();
        Ok((en, de, ev))
    }

    pub fn evaluate(&self, inputs: &[u8], de: &[u8], ev: &[u8]) -> Result<Vec<u16>, Error> {
        let inputs = wire::wires_from_bytes(inputs)?;
        let de = Decoder::from_bytes(de)?;
        let ev = GarbledCircuit::from_bytes(ev)?;
        let outputs = ev.eval(&self.circ, &inputs, &[]);
        let outputs = de.decode(&outputs);
        Ok(outputs)
    }
}
