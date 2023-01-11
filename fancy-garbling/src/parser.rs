// -*- mode: rust; -*-
//
// This file is part of fancy-garbling.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Functions for parsing and running a circuit file based on the format given
//! here: <https://homes.esat.kuleuven.be/~nsmart/MPC/>.

use crate::{
    circuit::{Circuit, CircuitRef, Gate},
    errors::CircuitParserError as Error,
};
use regex::{Captures, Regex};
use std::{
    fs::File,
    io::{BufRead, BufReader},
    str::FromStr,
};

enum GateType {
    AndGate,
    XorGate,
}

fn cap2int(cap: &Captures, idx: usize) -> Result<usize, Error> {
    let s = cap.get(idx).ok_or(Error::ParseIntError)?;
    FromStr::from_str(s.as_str()).map_err(Error::from)
}

fn cap2typ(cap: &Captures, idx: usize) -> Result<GateType, Error> {
    let s = cap.get(idx).ok_or(Error::ParseIntError)?;
    let s = s.as_str();
    match s {
        "AND" => Ok(GateType::AndGate),
        "XOR" => Ok(GateType::XorGate),
        s => Err(Error::ParseGateError(s.to_string())),
    }
}

fn regex2captures<'t>(re: &Regex, line: &'t str) -> Result<Captures<'t>, Error> {
    re.captures(&line)
        .ok_or_else(|| Error::ParseLineError(line.to_string()))
}

impl Circuit {
    /// Generates a new `Circuit` from file `filename`. The file must follow the
    /// format given here: <https://homes.esat.kuleuven.be/~nsmart/MPC/>,
    /// otherwise a `CircuitParserError` is returned.
    pub fn parse(filename: &str) -> Result<Self, Error> {
        let f = File::open(filename)?;
        let mut reader = BufReader::new(f);

        // Parse first line: ngates nwires\n
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let re = Regex::new(r"(\d+)\s+(\d+)")?;
        let cap = regex2captures(&re, &line)?;
        let ngates = cap2int(&cap, 1)?;
        let nwires = cap2int(&cap, 2)?;

        // Parse second line: n1 n2 n3\n
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let re = Regex::new(r"(\d+)\s+(\d+)\s+(\d+)")?;
        let cap = regex2captures(&re, &line)?;
        let n1 = cap2int(&cap, 1)?; // Number of garbler inputs
        let n2 = cap2int(&cap, 2)?; // Number of evaluator inputs
        let n3 = cap2int(&cap, 3)?; // Number of outputs

        // Parse third line: \n
        let mut line = String::new();
        reader.read_line(&mut line)?;
        #[allow(clippy::trivial_regex)]
        let re = Regex::new(r"\n")?;
        let _ = regex2captures(&re, &line)?;

        let mut circ = Self::new(Some(ngates));

        let re1 = Regex::new(r"1 1 (\d+) (\d+) INV")?;
        let re2 = Regex::new(r"2 1 (\d+) (\d+) (\d+) ((AND|XOR))")?;

        let mut id = 0;

        // Process garbler inputs.
        for i in 0..n1 {
            circ.gates.push(Gate::GarblerInput { id: i });
            circ.garbler_input_refs
                .push(CircuitRef { ix: i, modulus: 2 });
        }
        // Process evaluator inputs.
        for i in 0..n2 {
            circ.gates.push(Gate::EvaluatorInput { id: i });
            circ.evaluator_input_refs.push(CircuitRef {
                ix: n1 + i,
                modulus: 2,
            });
        }
        // Create a constant wire for negations.
        circ.gates.push(Gate::Constant { val: 1 });
        let oneref = CircuitRef {
            ix: n1 + n2,
            modulus: 2,
        };
        circ.const_refs.push(oneref);
        // Process outputs.
        for i in 0..n3 {
            circ.output_refs.push(CircuitRef {
                ix: nwires - n3 + i,
                modulus: 2,
            });
        }
        for line in reader.lines() {
            let line = line?;
            match line.chars().next() {
                Some('1') => {
                    let cap = regex2captures(&re1, &line)?;
                    let yref = cap2int(&cap, 1)?;
                    let out = cap2int(&cap, 2)?;
                    let yref = CircuitRef {
                        ix: yref,
                        modulus: 2,
                    };
                    circ.gates.push(Gate::Sub {
                        xref: oneref,
                        yref,
                        out: Some(out),
                    })
                }
                Some('2') => {
                    let cap = regex2captures(&re2, &line)?;
                    let xref = cap2int(&cap, 1)?;
                    let yref = cap2int(&cap, 2)?;
                    let out = cap2int(&cap, 3)?;
                    let typ = cap2typ(&cap, 4)?;
                    let xref = CircuitRef {
                        ix: xref,
                        modulus: 2,
                    };
                    let yref = CircuitRef {
                        ix: yref,
                        modulus: 2,
                    };
                    let gate = match typ {
                        GateType::AndGate => {
                            let gate = Gate::Mul {
                                xref,
                                yref,
                                id,
                                out: Some(out),
                            };
                            id += 1;
                            gate
                        }
                        GateType::XorGate => Gate::Add {
                            xref,
                            yref,
                            out: Some(out),
                        },
                    };
                    circ.gates.push(gate);
                }
                None => break,
                _ => {
                    return Err(Error::ParseLineError(line.to_string()));
                }
            }
        }
        circ.gate_moduli = vec![2u16; circ.gates.len()];
        Ok(circ)
    }
}

#[cfg(test)]
mod tests {
    use crate::{circuit::Circuit, classic::garble};

    #[test]
    fn test_parser() {
        let circ = Circuit::parse("circuits/AES-non-expanded.txt").unwrap();
        let key = vec![0u16; 128];
        let pt = vec![0u16; 128];
        let output = circ.eval_plain(&pt, &key).unwrap();
        assert_eq!(output.iter().map(|i| i.to_string()).collect::<String>(),
                   "01100110111010010100101111010100111011111000101000101100001110111000100001001100111110100101100111001010001101000010101100101110");
        let key = vec![1u16; 128];
        let pt = vec![0u16; 128];
        let output = circ.eval_plain(&pt, &key).unwrap();
        assert_eq!(output.iter().map(|i| i.to_string()).collect::<String>(),
                   "10100001111101100010010110001100100001110111110101011111110011011000100101100100010010000100010100111000101111111100100100101100");
        let mut key = vec![0u16; 128];
        for i in 0..8 {
            key[i] = 1;
        }
        let pt = vec![0u16; 128];
        let output = circ.eval_plain(&pt, &key).unwrap();
        assert_eq!(output.iter().map(|i| i.to_string()).collect::<String>(),
                   "10110001110101110101100000100101011010110010100011111101100001010000101011010100100101000100001000001000110011110001000101010101");
        let mut key = vec![0u16; 128];
        key[7] = 1;
        let pt = vec![0u16; 128];
        let output = circ.eval_plain(&pt, &key).unwrap();
        assert_eq!(output.iter().map(|i| i.to_string()).collect::<String>(),
                   "11011100000011101101100001011101111110010110000100011010101110110111001001001001110011011101000101101000110001010100011001111110");
    }

    #[test]
    fn test_gc_eval() {
        let circ = Circuit::parse("circuits/AES-non-expanded.txt").unwrap();
        let (en, gc) = garble(circ).unwrap();
        let gb = en.encode_garbler_inputs(&vec![0u16; 128]);
        let ev = en.encode_evaluator_inputs(&vec![0u16; 128]);
        gc.eval(&gb, &ev).unwrap();
    }
}
