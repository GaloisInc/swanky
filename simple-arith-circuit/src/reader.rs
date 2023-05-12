//! This module implements a reader for "Bristol Fashion" circuit definition files.

use crate::circuit::{Circuit, Index, Op};
use scuttlebutt::field::F2;
use scuttlebutt::ring::FiniteRing;
use std::{
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
};

/// Specifies what debug information `Circuit::read_bristol_fashion` emits.
/// When specified, this emits information through `log::debug!`.
#[derive(Clone, Default)]
pub struct DebugInfo {
    /// Show brief info about the circuit.
    pub meta: bool,
    /// Show mappings used to construct circuit.
    pub mapping: bool,
}

/// Errors produced by `Circuit::read_bristol_fashion`.
#[derive(Debug)]
pub enum Error {
    /// Integer parsing error.
    ParseIntError(std::num::ParseIntError),
    /// Input/output error.
    IoError(std::io::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Error::ParseIntError(e) => format!("Integer parsing error: {e}"),
                Error::IoError(e) => format!("I/O error: {e}"),
            }
        )
    }
}

impl std::error::Error for Error {}

impl From<std::num::ParseIntError> for Error {
    fn from(e: std::num::ParseIntError) -> Self {
        Error::ParseIntError(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::IoError(e)
    }
}

impl Circuit<F2> {
    /// Generate a new `Circuit` from the Bristol Fashion file `filename`.
    /// The file must follow the "Bristol Fashion" *basic* (no MAND gates) format:
    /// <https://homes.esat.kuleuven.be/~nsmart/MPC/>.
    pub fn read_bristol_fashion(filename: &Path, trace: Option<&DebugInfo>) -> Result<Self, Error> {
        let f = File::open(filename)?;
        let mut reader = BufReader::new(f);
        let trace = trace.unwrap_or(&DebugInfo {
            meta: false,
            mapping: false,
        });

        // Read one line and parse whitespace-separated integers to a vector.
        fn line_to_nums(
            reader: &mut BufReader<File>,
            line: &mut String,
            nums: &mut Vec<usize>,
        ) -> Result<(), Error> {
            line.clear();
            nums.clear();
            reader.read_line(line)?;
            for token in line.split_whitespace() {
                let num = token.parse()?;
                nums.push(num);
            }
            Ok(())
        }

        // Read one line and parse whitespace-separated tokens.
        // All but the last token must be integers.
        fn line_to_nums_and_token(
            reader: &mut BufReader<File>,
            line: &mut String,
            nums: &mut Vec<usize>,
            token: &mut String,
        ) -> Result<(), Error> {
            line.clear();
            nums.clear();
            token.clear();
            reader.read_line(line)?;
            let n = line.split_whitespace().count();
            for token in line.split_whitespace().take(n - 1) {
                let num = token.parse()?;
                nums.push(num)
            }
            if let Some(t) = line.split_whitespace().last() {
                token.push_str(t)
            } else {
                return Err(Error::IoError(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Missing gate name",
                )));
            }
            Ok(())
        }

        let fail = |linenum: usize, message: &str| -> Result<Self, Error> {
            Err(Error::IoError(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{}:{}:{}", filename.display(), linenum, message),
            )))
        };

        let mut nums = Vec::new();
        let mut line = String::new();

        // Line 1: number-of-gates number-of-wires
        line_to_nums(&mut reader, &mut line, &mut nums)?;
        if nums.len() != 2 {
            return fail(1, "Unable to parse line");
        }
        let ngates = nums[0];
        let nwires = nums[1];

        // Line 2: number-of-input-values number-of-wires-per-value...
        line_to_nums(&mut reader, &mut line, &mut nums)?;
        if nums.is_empty() {
            return fail(2, "Unable to parse line");
        }
        let niv = nums[0];
        if nums.len() - 1 != niv {
            return fail(2, "Not enough wires specified");
        }

        let mut wiv: Vec<usize> = Vec::with_capacity(niv);
        let mut tniw = 0;
        for num in &nums[1..] {
            tniw += num;
            wiv.push(*num);
        }

        // Line 3: number-of-output-values number-of-wires-per-value...
        line_to_nums(&mut reader, &mut line, &mut nums)?;
        if nums.is_empty() {
            return fail(3, "param error");
        }
        let nov = nums[0];
        if nums.len() - 1 != nov {
            return fail(3, "Not enough wires specified");
        }

        let mut wov: Vec<usize> = Vec::with_capacity(nov);
        let mut tnow = 0;
        for num in &nums[1..] {
            tnow += num;
            wov.push(*num);
        }

        // Line 4: <empty>
        line_to_nums(&mut reader, &mut line, &mut nums)?;
        if !nums.is_empty() {
            return fail(4, "expected empty line");
        }

        // We establish a mapping from the output wire labels as denoted
        // in the Bristol Fashion circuit to labels that are named
        // sequentially based upon order of gate appearance; this is needed
        // because the gate implementations' outputs are assigned to the
        // "next available" wire.
        //
        // Additionally, we must arrange to emulate INV gates since the
        // underlying Op::Neg does not function properly in the F2 (binary)
        // case. The INV gate is replaced with an XOR gate having a
        // constant "one" input on its second input pin; the required
        // constant is emitted as an Op::Constant instruction immediately
        // following the input wires and preceeding the first emitted
        // output wire.

        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        enum WireKind {
            Unassigned,
            Input,
            Output,
            Constant,
        }

        #[derive(Debug, Clone, Copy)]
        enum GateKind {
            Unassigned,
            And,
            Xor,
            Eq,
            Eqw,
            Inv,
        }

        // Wire indices are origin-0.
        let nconstants = 1; // number of constant wires
        let mut wl: Vec<(Index, WireKind)> = vec![(0, WireKind::Unassigned); nwires + nconstants];
        let mut ciw = 0; // current input wire
        let mut cow = tniw; // current output wire
        let constant_one = cow; // index of constant wire for use in synthesizing INV
        let mut gl: Vec<(GateKind, [Index; 3])> = vec![(GateKind::Unassigned, [0; 3]); 1 + ngates]; // ignore zeroth element

        // Reserve space for constant wires following input wires.
        // Constant wires are instantiated while building the circuit (see below).
        let constant_wires_base = cow;
        wl[cow] = (cow, WireKind::Constant);
        cow += 1;
        assert_eq!(constant_wires_base + nconstants, cow);

        let mut map_wires_and_gates = |gwdef: &mut Vec<Index>, gate: GateKind, gatenum: Index| {
            // gwdef is: number-in-wires number-out-wires in-wires... out-wires...
            gl[gatenum].0 = gate;
            let mut gatewires = [0; 3];
            gatewires[0] = gwdef[2];
            gatewires[1] = gwdef[3];
            assert!(gwdef[1] == 1);
            if gwdef[0] == 2 {
                gatewires[2] = gwdef[4];
            } else {
                assert!(gwdef[0] == 1);
            }
            // Adjust wire indices to account for allocated constants.
            if gatewires[0] >= tniw {
                gatewires[0] += nconstants;
            }
            if gatewires[1] >= tniw {
                gatewires[1] += nconstants;
            }
            if gatewires[2] >= tniw {
                gatewires[2] += nconstants;
            }
            gl[gatenum].1 = gatewires;
            let niw = gwdef[0];
            let now = gwdef[1];
            let iwl = &gatewires[0..niw];
            let owl = &gatewires[niw..niw + now];

            for iw in iwl {
                if wl[*iw].1 == WireKind::Unassigned {
                    wl[*iw] = (ciw, WireKind::Input);
                    ciw += 1;
                };
            }

            for ow in owl {
                if wl[*ow].1 == WireKind::Unassigned {
                    wl[*ow] = (cow, WireKind::Output);
                    cow += 1;
                };
            }
        };

        // Line 5 and later (number-of-gates lines):
        // number-in-wires number-out-wires in-wires... out-wires... gate-type
        let mut gatekind = String::new();
        for i in 1..=ngates {
            line_to_nums_and_token(&mut reader, &mut line, &mut nums, &mut gatekind)?;
            let gateniw = nums[0];
            let gatenow = nums[1];
            let gate = match gatekind.as_str() {
                "AND" => {
                    if gateniw != 2 || gatenow != 1 {
                        return fail(4 + i, "param error");
                    }
                    GateKind::And
                }
                "XOR" => {
                    if gateniw != 2 || gatenow != 1 {
                        return fail(4 + i, "param error");
                    }
                    GateKind::Xor
                }
                "EQW" => {
                    if gateniw != 1 || gatenow != 1 {
                        return fail(4 + i, "param error");
                    }
                    GateKind::Eqw
                }
                "EQ" => {
                    // IMPORTANT: input wire is a constant value; not a label.
                    if gateniw != 1 || gatenow != 1 {
                        return fail(4 + 1, "param error");
                    }
                    GateKind::Eq
                }
                "INV" => {
                    if gateniw != 1 || gatenow != 1 {
                        return fail(4 + 1, "param error");
                    }
                    GateKind::Inv
                }
                "MAND" => return fail(4 + i, "MAND unsupported"),
                _ => return fail(4 + i, "invalid gate"),
            };
            map_wires_and_gates(&mut nums, gate, i);
        }

        // Trace the circuit metadata.
        if trace.meta {
            log::debug!(
                "read_bristol_fasion: filename = {};\
            \n ngates = {}; nwires = {};\n niv = {}; tniw = {}; wiv = {:?};\
            \n nov = {}; tnow = {}; wov = {:?}",
                filename.display(),
                ngates,
                nwires,
                niv,
                tniw,
                wiv,
                nov,
                tnow,
                wov
            );
        }

        // Build the circuit from the gate definitions; trace gate mappings.
        //
        // Ops <= AND as Mul; XOR as Add; INV rewrittens as XOR w/
        //   constant 1 on second input, implemented using Add (not Neg);
        //   EQ as LDI (modified to accept constant value),
        //   and EQW as Copy (new op).
        //
        // The initial tniw wires are always input and are preallocated.
        // The final tnow wires are always output. Because
        // gates must be scheduled as they appear in the input,
        // output wires are routed to the end of the result vector
        // by synthesizing appropriate EQW pseudo-gates in a later step.
        //
        // Constant wires (used to synthesize INV gate from XOR) are
        // allocated immediately after input wires and before the first
        // output wire instantiated by the circuit.
        assert!(ngates == gl.len() - 1); // Zeroth element empty
        let mut ops: Vec<Op<_>> = Vec::with_capacity(ngates);
        let mut owl: Vec<Index> = vec![0; tnow + nconstants];
        let mut cow = tniw;
        // Emit `nconstants` constants (see above).
        ops.push(Op::Constant(F2::ONE));
        cow += 1;
        assert_eq!(constant_wires_base + nconstants, cow);
        for i in 1..=ngates {
            let wire1 = gl[i].1[0];
            let wk1 = wl[wire1].1;
            let wire2 = gl[i].1[1];
            let wk2 = wl[wire2].1;
            let wire3 = gl[i].1[2];
            let wk3 = wl[wire3].1;
            let trace_mapping2 = || {
                if trace.mapping {
                    log::debug!(
                        "i: {}; gk: {:?}; wire1: {} {:?} [{}]; wire2: {} {:?} [{}]",
                        i,
                        gl[i].0,
                        wire1,
                        wk1,
                        wl[wire1].0,
                        wire2,
                        wk2,
                        wl[wire2].0
                    );
                };
            };
            let trace_mapping3 = || {
                if trace.mapping {
                    log::debug!(
                    "i: {}; gk: {:?}; wire1: {} {:?} [{}]; wire2: {} {:?} [{}]; wire3: {} {:?} [{}]",
                    i, gl[i].0, wire1, wk1, wl[wire1].0, wire2, wk2, wl[wire2].0, wire3, wk3, wl[wire3].0,
                );
                };
            };
            match gl[i].0 {
                GateKind::And => {
                    trace_mapping3();
                    assert!(wire1 < tniw && wk1 == WireKind::Input || wk1 == WireKind::Output);
                    assert!(wire2 < tniw && wk2 == WireKind::Input || wk2 == WireKind::Output);
                    assert!(wk3 == WireKind::Output);
                    ops.push(Op::Mul(wl[wire1].0, wl[wire2].0));
                    if wire3 >= nwires - tnow {
                        owl[tnow - (nwires - wire3)] = cow;
                    };
                }
                GateKind::Xor => {
                    trace_mapping3();
                    assert!(wire1 < tniw && wk1 == WireKind::Input || wk1 == WireKind::Output);
                    assert!(wire2 < tniw && wk2 == WireKind::Input || wk2 == WireKind::Output);
                    assert!(wk3 == WireKind::Output);
                    ops.push(Op::Add(wl[wire1].0, wl[wire2].0));
                    if wire3 >= nwires - tnow {
                        owl[tnow - (nwires - wire3)] = cow;
                    };
                }
                GateKind::Eq => {
                    trace_mapping2();
                    assert!(wk1 == WireKind::Input);
                    assert!(wk2 == WireKind::Output);
                    // Interpret input wire as a constant value.
                    let cval;
                    match wire1 {
                        0 => {
                            cval = F2::ZERO;
                        }
                        1 => {
                            cval = F2::ONE;
                        }
                        _ => {
                            panic!("EQ not 0 or 1");
                        }
                    }
                    ops.push(Op::Constant(cval));
                    if wire2 >= nwires - tnow {
                        owl[tnow - (nwires - wire2)] = cow;
                    };
                }
                GateKind::Eqw => {
                    trace_mapping2();
                    assert!(wk1 == WireKind::Input);
                    assert!(wk2 == WireKind::Output);
                    ops.push(Op::Copy(wl[wire1].0));
                    if wire2 >= nwires - tnow {
                        owl[tnow - (nwires - wire2)] = cow;
                    };
                }
                GateKind::Inv => {
                    trace_mapping2();
                    assert!(wire1 < tniw && wk1 == WireKind::Input || wk1 == WireKind::Output);
                    assert!(wk2 == WireKind::Output);
                    ops.push(Op::Add(wl[wire1].0, constant_one));
                    if wire2 >= nwires - tnow {
                        owl[tnow - (nwires - wire2)] = cow;
                    };
                }
                GateKind::Unassigned => {
                    panic!("Unassigned gate kind");
                }
            }
            cow += 1;
        }

        // Synthesize the output wires.
        for i in 0..tnow {
            if trace.mapping {
                log::debug!(
                    "synthesize output wire {} => {} <= {}",
                    nwires + nconstants - tnow + i, // from
                    nwires + nconstants + i,        // to
                    owl[i]                          // source
                );
            }
            ops.push(Op::Copy(owl[i + nconstants]));
        }

        Ok(Circuit::new(tniw, tnow, ops))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn bits_to_wires(bitstr: &[u8]) -> Vec<F2> {
        let nbits = bitstr.len();
        let mut wires = Vec::with_capacity(nbits);
        for i in 0..nbits {
            match &bitstr[i] {
                b'0' => wires.push(scuttlebutt::field::F2::ZERO),
                b'1' => wires.push(scuttlebutt::field::F2::ONE),
                _ => {
                    panic!("bit must be 0 or 1")
                }
            }
        }
        wires
    }

    fn eval_and_check(circuit: &Circuit<F2>, wires_in: Vec<F2>, wires_out: Vec<F2>) {
        let mut eval_out: Vec<F2> = Vec::new();
        let _ = circuit.eval(&wires_in, &mut eval_out);
        let eval_len = eval_out.len();
        let result_len = wires_out.len();
        let result = &eval_out[eval_len - result_len..];
        assert_eq!(result, wires_out);
    }

    fn cat<T: Clone>(a: &[T], b: &[T]) -> Vec<T> {
        let mut v = Vec::with_capacity(a.len() + b.len());
        v.extend_from_slice(a);
        v.extend_from_slice(b);
        v
    }

    #[allow(dead_code)]
    fn eval_and_print(circuit: &Circuit<F2>, wires_in: Vec<F2>, nouts: usize) {
        let mut eval_out: Vec<F2> = Vec::new();
        let _ = circuit.eval(&wires_in, &mut eval_out);
        let eval_len = eval_out.len();
        let result = &eval_out[eval_len - nouts..];
        for i in 0..nouts {
            match bool::from(result[i]) {
                false => {
                    print!("0");
                }
                true => {
                    print!("1");
                }
            }
        }
        println!();
    }

    #[test]
    // Confirm that all of the KU Leuven BF circuits are readable
    // and exhibit the expected metrics.
    pub(crate) fn test_circuitread() {
        struct Ckt<'a> {
            nwires: usize,
            nmuls: usize,
            nnonmuls: usize,
            file: &'a str,
        }
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("circuits/bristol");
        let circuits = [
            Ckt {
                file: "adder64.txt",
                nwires: 569,
                nmuls: 63,
                nnonmuls: 378,
            },
            Ckt {
                file: "divide64.txt",
                nwires: 30119,
                nmuls: 4664,
                nnonmuls: 25327,
            },
            Ckt {
                file: "mult2_64.txt",
                nwires: 28289,
                nmuls: 8128,
                nnonmuls: 20033,
            },
            Ckt {
                file: "mult64.txt",
                nwires: 13868,
                nmuls: 4033,
                nnonmuls: 9707,
            },
            Ckt {
                file: "neg64.txt",
                nwires: 319,
                nmuls: 62,
                nnonmuls: 193,
            },
            Ckt {
                file: "sub64.txt",
                nwires: 632,
                nmuls: 63,
                nnonmuls: 441,
            },
            Ckt {
                file: "udivide64.txt",
                nwires: 17145,
                nmuls: 4285,
                nnonmuls: 12732,
            },
            Ckt {
                file: "zero_equal.txt",
                nwires: 193,
                nmuls: 63,
                nnonmuls: 66,
            },
            Ckt {
                file: "aes_128.txt",
                nwires: 37048,
                nmuls: 6400,
                nnonmuls: 30392,
            },
            Ckt {
                file: "aes_192.txt",
                nwires: 42014,
                nmuls: 7168,
                nnonmuls: 34526,
            },
            Ckt {
                file: "aes_256.txt",
                nwires: 51179,
                nmuls: 8832,
                nnonmuls: 41963,
            },
            Ckt {
                file: "Keccak_f.txt",
                nwires: 195287,
                nmuls: 38400,
                nnonmuls: 155287,
            },
            Ckt {
                file: "sha256.txt",
                nwires: 136098,
                nmuls: 22573,
                nnonmuls: 112757,
            },
            Ckt {
                file: "sha512.txt",
                nwires: 351666,
                nmuls: 57947,
                nnonmuls: 292183,
            },
        ];
        for ckt in circuits {
            let path = base.join(ckt.file);
            if path.exists() {
                match Circuit::read_bristol_fashion(&path, None) {
                    Ok(foo) => {
                        assert_eq!(foo.nwires(), ckt.nwires);
                        assert_eq!(foo.nmuls(), ckt.nmuls);
                        assert_eq!(foo.nnonmuls(), ckt.nnonmuls);
                    }
                    Err(e) => {
                        eprintln!("ERROR:Bristol Fashion:{:?}", e);
                        assert!(false);
                    }
                };
            }
        }
    }

    #[test]
    // This test is useful because it's small enough that proper
    // function can be confirmed by exhaustive testing (only 8 cases).
    // If you're so inclined, you could also print!() the circuit and
    // its evaluation result to confirm that all of the internal
    // states (i.e. individual gate outputs) are correct.
    pub(crate) fn test_circuitread_eval_full_adder() {
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("circuits/bristol");
        let ckt = base.join("unit-test/one-bit-full-adder.txt");
        match Circuit::read_bristol_fashion(&ckt, None) {
            Ok(foo) => {
                let a_b_ci = bits_to_wires(b"000");
                let co_s = bits_to_wires(b"00");
                eval_and_check(&foo, a_b_ci, co_s);
                let a_b_ci = bits_to_wires(b"001");
                let co_s = bits_to_wires(b"01");
                eval_and_check(&foo, a_b_ci, co_s);
                let a_b_ci = bits_to_wires(b"010");
                let co_s = bits_to_wires(b"01");
                eval_and_check(&foo, a_b_ci, co_s);
                let a_b_ci = bits_to_wires(b"011");
                let co_s = bits_to_wires(b"10");
                eval_and_check(&foo, a_b_ci, co_s);
                let a_b_ci = bits_to_wires(b"100");
                let co_s = bits_to_wires(b"01");
                eval_and_check(&foo, a_b_ci, co_s);
                let a_b_ci = bits_to_wires(b"101");
                let co_s = bits_to_wires(b"10");
                eval_and_check(&foo, a_b_ci, co_s);
                let a_b_ci = bits_to_wires(b"110");
                let co_s = bits_to_wires(b"10");
                eval_and_check(&foo, a_b_ci, co_s);
                let a_b_ci = bits_to_wires(b"111");
                let co_s = bits_to_wires(b"11");
                eval_and_check(&foo, a_b_ci, co_s);
            }
            Err(e) => {
                eprintln!("ERROR:Bristol Fashion:{:?}", e);
                assert!(false);
            }
        };
    }

    /* "Arithmetic" Circuits
       The following are named for various arithmetic functions.
       However, the semantics are not what one would expect.
       Consider these tests as no more than checking that their
       evaluation continues to produce the same result, even
       though the result seems "wrong". We do not have a way to
       inspect these circuits to determine the intended function
       and the way they map input and output bits relative to the
       notion of input and output vectors.
    */

    #[test]
    pub(crate) fn test_circuitread_eval_adder64() {
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("circuits/bristol");
        let ckt = base.join("adder64.txt");
        if ckt.exists() {
            match Circuit::read_bristol_fashion(&ckt, None) {
                Ok(foo) => {
                    let a = bits_to_wires(
                        b"0000000000000000000000000000000000000000000000000000000000000000",
                    );
                    let b = bits_to_wires(
                        b"0000000000000000000000000000000000000000000000000000000000000000",
                    );
                    let ab = cat(&a, &b);
                    let expect = bits_to_wires(
                        b"0000000000000000000000000000000000000000000000000000000000000000",
                    );
                    eval_and_check(&foo, ab, expect);
                    let a = bits_to_wires(
                        b"1111111111111111111111111111111111111111111111111111111111111111",
                    );
                    let b = bits_to_wires(
                        b"0000000000000000000000000000000000000000000000000000000000000000",
                    );
                    let ab = cat(&a, &b);
                    let expect = bits_to_wires(
                        b"0000000000000000000000000000000001111111111111111111111111111111",
                    );
                    eval_and_check(&foo, ab, expect);
                }
                Err(e) => {
                    eprintln!("ERROR:Bristol Fashion:{:?}", e);
                    assert!(false);
                }
            };
        }
    }

    #[test]
    pub(crate) fn test_circuitread_eval_divide64() {
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("circuits/bristol");
        let ckt = base.join("divide64.txt");
        if ckt.exists() {
            match Circuit::read_bristol_fashion(&ckt, None) {
                Ok(foo) => {
                    let a = bits_to_wires(
                        b"1110000000000000000000000000000000000000000000000000000000000000",
                    );
                    let b = bits_to_wires(
                        b"0100000000000000000000000000000000000000000000000000000000000000",
                    );
                    let ab = cat(&a, &b);
                    let expect = bits_to_wires(
                        b"0000000000000000000000000000000000000000000000000000000000001110",
                    );
                    eval_and_check(&foo, ab, expect);
                }
                Err(e) => {
                    eprintln!("ERROR:Bristol Fashion:{:?}", e);
                    assert!(false);
                }
            };
        }
    }

    #[test]
    pub(crate) fn test_circuitread_eval_mult2_64() {
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("circuits/bristol");
        let ckt = base.join("mult2_64.txt");
        if ckt.exists() {
            match Circuit::read_bristol_fashion(&ckt, None) {
                Ok(foo) => {
                    let a = bits_to_wires(
                        b"1110000000000000000000000000000000000000000000000000000000001000",
                    );
                    let b = bits_to_wires(
                        b"0100000000000000000000000000000000000000000000000000000100000000",
                    );
                    let ab = cat(&a, &b);
                    let xa = bits_to_wires(
                        b"0011001100000000000000000000000000000000000000000000000000001001",
                    );
                    let xb = bits_to_wires(
                        b"0000000000001000000000000000000000000000000000000000000000000000",
                    );
                    let expect = cat(&xa, &xb);
                    eval_and_check(&foo, ab, expect);
                }
                Err(e) => {
                    eprintln!("ERROR:Bristol Fashion:{:?}", e);
                    assert!(false);
                }
            };
        }
    }

    #[test]
    pub(crate) fn test_circuitread_eval_mult64() {
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("circuits/bristol");
        let ckt = base.join("mult64.txt");
        if ckt.exists() {
            match Circuit::read_bristol_fashion(&ckt, None) {
                Ok(foo) => {
                    let a = bits_to_wires(
                        b"1110000000000000000000000000000000000000000000000000000000001000",
                    );
                    let b = bits_to_wires(
                        b"0100000000000000000000000000000000000000000000000000000100000000",
                    );
                    let ab = cat(&a, &b);
                    let expect = bits_to_wires(
                        b"0000000000000000000000000000000001000000000000000000000000000011",
                    );
                    eval_and_check(&foo, ab, expect);
                }
                Err(e) => {
                    eprintln!("ERROR:Bristol Fashion:{:?}", e);
                    assert!(false);
                }
            };
        }
    }

    #[test]
    pub(crate) fn test_circuitread_eval_neg64() {
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("circuits/bristol");
        let ckt = base.join("neg64.txt");
        if ckt.exists() {
            match Circuit::read_bristol_fashion(&ckt, None) {
                Ok(foo) => {
                    let a = bits_to_wires(
                        b"0000000000000000000000000000000000000000000000000000000000000000",
                    );
                    let expect = bits_to_wires(
                        b"0000000000000000000000000000000000000000000000000000000000000000",
                    );
                    eval_and_check(&foo, a, expect);
                    let a = bits_to_wires(
                        b"1111111111111111111111111111111111111111111111111111111111111111",
                    );
                    let expect = bits_to_wires(
                        b"1000000000000000000000000000000000000000000000000000000000000000",
                    );
                    eval_and_check(&foo, a, expect);
                }
                Err(e) => {
                    eprintln!("ERROR:Bristol Fashion:{:?}", e);
                    assert!(false);
                }
            };
        }
    }

    #[test]
    pub(crate) fn test_circuitread_eval_sub64() {
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("circuits/bristol");
        let ckt = base.join("sub64.txt");
        if ckt.exists() {
            match Circuit::read_bristol_fashion(&ckt, None) {
                Ok(foo) => {
                    let a = bits_to_wires(
                        b"1110000000000000000000000000000000000000000000000000000000000000",
                    );
                    let b = bits_to_wires(
                        b"0100000000000000000000000000000000000000000000000000000000000000",
                    );
                    let ab = cat(&a, &b);
                    let expect = bits_to_wires(
                        b"0000000000000000000000000000000111111111111111111111111111111100",
                    );
                    eval_and_check(&foo, ab, expect);
                }
                Err(e) => {
                    eprintln!("ERROR:Bristol Fashion:{:?}", e);
                    assert!(false);
                }
            };
        }
    }

    #[test]
    pub(crate) fn test_circuitread_eval_udivide64() {
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("circuits/bristol");
        let ckt = base.join("udivide64.txt");
        if ckt.exists() {
            match Circuit::read_bristol_fashion(&ckt, None) {
                Ok(foo) => {
                    let a = bits_to_wires(
                        b"1111111111111111111111111111111111111111111111111111111111111111",
                    );
                    let b = bits_to_wires(
                        b"1111111111111111111111111111111111111111111111111111111111111111",
                    );
                    let ab = cat(&a, &b);
                    let expect = bits_to_wires(
                        b"1000000000000000000000000000000000000000000000000000000000000000",
                    );
                    eval_and_check(&foo, ab, expect);
                }
                Err(e) => {
                    eprintln!("ERROR:Bristol Fashion:{:?}", e);
                    assert!(false);
                }
            };
        }
    }

    #[test]
    pub(crate) fn test_circuitread_eval_zero_equal() {
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("circuits/bristol");
        let ckt = base.join("zero_equal.txt");
        if ckt.exists() {
            match Circuit::read_bristol_fashion(&ckt, None) {
                Ok(foo) => {
                    let a = bits_to_wires(
                        b"0000000000000000000000000000000000000000000000000000000000000000",
                    );
                    let expect = bits_to_wires(b"1");
                    eval_and_check(&foo, a, expect);
                    let a = bits_to_wires(
                        b"0000000000010000000000000000000000000000000000000000000000000000",
                    );
                    let expect = bits_to_wires(b"0");
                    eval_and_check(&foo, a, expect);
                }
                Err(e) => {
                    eprintln!("ERROR:Bristol Fashion:{:?}", e);
                    assert!(false);
                }
            };
        }
    }

    /* Crypto Circuits
       At least one of these has been confirmed correct, modulo
       endianness of the bit vectors, against an independent
       implementation.
    */

    #[test]
    pub(crate) fn test_circuitread_eval_aes_128() {
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("circuits/bristol");
        let ckt = base.join("aes_128.txt");
        if ckt.exists() {
            match Circuit::read_bristol_fashion(&ckt, None) {
                Ok(foo) => {
                    let a = bits_to_wires(
                        b"0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000",
                    );
                    let b = bits_to_wires(
                        b"0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000",
                    );
                    let ab = cat(&a, &b);
                    let expect = bits_to_wires(
                        b"0111010011010100001011000101001110011010010111110011001000010001\
                    1101110000110100010100011111011100101011110100101001011101100110",
                    );
                    eval_and_check(&foo, ab, expect);
                }
                Err(e) => {
                    eprintln!("ERROR:Bristol Fashion:{:?}", e);
                    assert!(false);
                }
            };
        }
    }

    #[test]
    pub(crate) fn test_circuitread_eval_aes_192() {
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("circuits/bristol");
        let ckt = base.join("aes_192.txt");
        if ckt.exists() {
            match Circuit::read_bristol_fashion(&ckt, None) {
                Ok(foo) => {
                    let a = bits_to_wires(
                        b"0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000",
                    );
                    let b = bits_to_wires(
                        b"0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000",
                    );
                    let ab = cat(&a, &b);
                    let expect = bits_to_wires(
                        b"1110101111010000000011001001001101110110100101010010111100010111\
                    1100010101001010111111010011010101001001100101100000011101010101",
                    );
                    eval_and_check(&foo, ab, expect);
                }
                Err(e) => {
                    eprintln!("ERROR:Bristol Fashion:{:?}", e);
                    assert!(false);
                }
            };
        }
    }

    #[test]
    pub(crate) fn test_circuitread_eval_aes_256() {
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("circuits/bristol");
        let ckt = base.join("aes_256.txt");
        if ckt.exists() {
            match Circuit::read_bristol_fashion(&ckt, None) {
                Ok(foo) => {
                    let a = bits_to_wires(
                        b"0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000",
                    );
                    let b = bits_to_wires(
                        b"0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000",
                    );
                    let ab = cat(&a, &b);
                    let expect = bits_to_wires(
                        b"1110000100000100001000010100100100101000010001010001001010110101\
                    1001000110010001000000100100010100011110000000111010100100111011",
                    );
                    eval_and_check(&foo, ab, expect);
                }
                Err(e) => {
                    eprintln!("ERROR:Bristol Fashion:{:?}", e);
                    assert!(false);
                }
            };
        }
    }

    #[test]
    pub(crate) fn test_circuitread_eval_keccack_f1600() {
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("circuits/bristol");
        let ckt = base.join("Keccak_f.txt");
        if ckt.exists() {
            match Circuit::read_bristol_fashion(&ckt, None) {
                Ok(foo) => {
                    let a = bits_to_wires(
                        b"0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000",
                    );
                    let expect = bits_to_wires(
                        b"0101011110001111111111111101111000111010001101110100010110010010\
                    1010111001101111001000101001011111111110000011001000010111011100\
                    0110100010101111101011000110010011100111001000001010011001000011\
                    0001100010000010100111110010010001000101101000111001000000100111\
                    0010100100110000100111100100010001110101010111000110010000101000\
                    0011000101111100000101110101000100111000111100110100110000010011\
                    0001110100111110010110101010101011110010000010110111000011010011\
                    1000011001101100000011101010100111011110001000110110011010001000\
                    0010011001111101011111110100111100110001100100110000111001001111\
                    1010000010100111110001100101101010000100100110110111010110000110\
                    1000000001001111111101000101100010001000101001010110101011111001\
                    1100001000011101100011001011001111000000111000100001001101100100\
                    1000000110100101001111100110100011011011111100111010101011111010\
                    1001010101100101011001110110010010110000100011101000010011000000\
                    1101011101011010100101011111110011000100111010000110101110101100\
                    0000110011001001010110101110110100001011111100010011111100100110\
                    1011010100001100011001011110111111011000100110001010000000111001\
                    0011000111011010010110110011000001101011100110000111010001101110\
                    0000100101111111101001110000010100100101011000101110001000100011\
                    1111111111101001001001011011010011111110011100011111011000101011\
                    1101000100010100011100101010000001000110110010100000101111101010\
                    1011110110101000111000100000110011110110000000011001001010110010\
                    1010101100011001011001000111100001100101010110101001010101110111\
                    0010000110101011001100111001111111001100000000111110001001010001\
                    1000111110100100111100011001111000000010100001111011101111100111",
                    );
                    eval_and_check(&foo, a, expect);
                }
                Err(e) => {
                    eprintln!("ERROR:Bristol Fashion:{:?}", e);
                    assert!(false);
                }
            };
        }
    }

    #[test]
    pub(crate) fn test_circuitread_eval_sha256() {
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("circuits/bristol");
        let ckt = base.join("sha256.txt");
        if ckt.exists() {
            match Circuit::read_bristol_fashion(&ckt, None) {
                Ok(foo) => {
                    let a = bits_to_wires(
                        b"0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000",
                    );
                    let b = bits_to_wires(
                        b"0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000",
                    );
                    let ab = cat(&a, &b);
                    let expect = bits_to_wires(
                        b"0110010111100111110100001111110100110011011001000111111001110101\
                    1111000010110110110010000001100110001011001011101010011101101101\
                    1110011101010000010000000100001111110100101110110010101001110011\
                    0001010111011100001110100100001000101000011010001010010100111110",
                    );
                    eval_and_check(&foo, ab, expect);
                }
                Err(e) => {
                    eprintln!("ERROR:Bristol Fashion:{:?}", e);
                    assert!(false);
                }
            };
        }
    }

    #[test]
    pub(crate) fn test_circuitread_eval_sha512() {
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("circuits/bristol");
        let ckt = base.join("sha512.txt");
        if ckt.exists() {
            match Circuit::read_bristol_fashion(&ckt, None) {
                Ok(foo) => {
                    let a = bits_to_wires(
                        b"0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000",
                    );
                    let b = bits_to_wires(
                        b"0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000\
                    0000000000000000000000000000000000000000000000000000000000000000",
                    );
                    let ab = cat(&a, &b);
                    let expect = bits_to_wires(
                        b"0011110000111011011010101110101110011001101100000011000101101010\
                    0000101000101000110010100110111000100100101100011010110000111000\
                    0101110011110001011101001111101010111000000010001110101111110110\
                    0001100010101100010010011001000101001010100010100110111110010100\
                    1111110111010000111010111001110000001101101010001101011000111000\
                    1001100101010011111011110110101101100001111111010001010111111110\
                    1101101101111101001111111010000111111111010000101000111010111010\
                    0000110000011111110101110001110000010101101110100101110010110101",
                    );
                    eval_and_check(&foo, ab, expect);
                }
                Err(e) => {
                    eprintln!("ERROR:Bristol Fashion:{:?}", e);
                    assert!(false);
                }
            };
        }
    }
}
