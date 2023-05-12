use clap::Args;
use mac_n_cheese_ir::circuit_builder::vole_supplier::VoleSupplier;
use mac_n_cheese_ir::circuit_builder::{build_circuit, build_privates};
use mac_n_cheese_ir::compilation_format::wire_format::Wire;
use mac_n_cheese_ir::compilation_format::{FieldMacType, Type, WireSize};
use rand::RngCore;

use scuttlebutt::field::F2;
use scuttlebutt::ring::FiniteRing;
use std::{cmp::Reverse, collections::BinaryHeap, str::FromStr};
use vectoreyes::{
    array_utils::ArrayUnrolledExt, Aes128EncryptOnly, AesBlockCipher, SimdBase, U8x16,
};

fn own_wire(idx: impl TryInto<WireSize>) -> Wire {
    Wire::own_wire(ws(idx))
}
fn input_wire(which_input: impl TryInto<WireSize>, which_wire: impl TryInto<WireSize>) -> Wire {
    Wire::input_wire(ws(which_input), ws(which_wire))
}

type WireId = usize;
#[derive(Debug, Clone, Copy)]
enum WireBody {
    Inv(WireId),
    Xor(WireId, WireId),
    And(WireId, WireId),
    Input(usize),
}

const NUM_INPUTS: usize = 256;
const NUM_OUTPUTS: usize = 128;

#[derive(Default, Clone)]
struct Circuit {
    wires: Vec<WireBody>,
    reverse_deps: Vec<Vec<WireId>>,
    outputs: Vec<WireId>,
}
impl Circuit {
    fn add_wire(&mut self, body: WireBody) -> WireId {
        let out = self.wires.len();
        self.reverse_deps.push(Vec::new());
        match body {
            WireBody::Inv(x) => self.reverse_deps[x].push(out),
            WireBody::Xor(a, b) => {
                self.reverse_deps[a].push(out);
                if a != b {
                    self.reverse_deps[b].push(out);
                }
            }
            WireBody::And(a, b) => {
                self.reverse_deps[a].push(out);
                if a != b {
                    self.reverse_deps[b].push(out);
                }
            }
            WireBody::Input(_) => {}
        }
        self.wires.push(body);
        out
    }
}

fn parse_circuit() -> Circuit {
    let src = include_str!("aes_128.txt");
    // We're parsing the initial version of bristol circuits, not the newer version.
    let mut lines = src.trim().split('\n');
    let hdr = Vec::from_iter(lines.next().unwrap().split_ascii_whitespace());
    let _num_gates = usize::from_str(hdr[0]).unwrap();
    let num_wires = usize::from_str(hdr[1]).unwrap();
    let mut bristol2wire = vec![None; num_wires];
    let mut circuit = Circuit::default();
    for i in 0..NUM_INPUTS {
        bristol2wire[i] = Some(circuit.add_wire(WireBody::Input(i)));
    }
    let _ = lines.next().unwrap(); // Skip number of input and output wires
    let mut buf = Vec::new();
    for line in lines {
        buf.clear();
        buf.extend(line.split_ascii_whitespace());
        match *buf.last().unwrap() {
            "XOR" => {
                assert_eq!(buf[0], "2");
                assert_eq!(buf[1], "1");
                let in0 = usize::from_str(buf[2]).unwrap();
                let in1 = usize::from_str(buf[3]).unwrap();
                let output = usize::from_str(buf[4]).unwrap();
                let in0 = bristol2wire[in0].unwrap();
                let in1 = bristol2wire[in1].unwrap();
                assert!(bristol2wire[output].is_none());
                bristol2wire[output] = Some(circuit.add_wire(WireBody::Xor(in0, in1)));
            }
            "AND" => {
                assert_eq!(buf[0], "2");
                assert_eq!(buf[1], "1");
                let in0 = usize::from_str(buf[2]).unwrap();
                let in1 = usize::from_str(buf[3]).unwrap();
                let output = usize::from_str(buf[4]).unwrap();
                let in0 = bristol2wire[in0].unwrap();
                let in1 = bristol2wire[in1].unwrap();
                assert!(bristol2wire[output].is_none());
                bristol2wire[output] = Some(circuit.add_wire(WireBody::And(in0, in1)));
            }
            "INV" => {
                assert_eq!(buf[0], "1");
                assert_eq!(buf[1], "1");
                let input = usize::from_str(buf[2]).unwrap();
                let output = usize::from_str(buf[3]).unwrap();
                let input = bristol2wire[input].unwrap();
                assert!(bristol2wire[output].is_none());
                bristol2wire[output] = Some(circuit.add_wire(WireBody::Inv(input)));
            }
            cmd => panic!("unknown gate {cmd:?}"),
        }
    }
    assert_eq!(circuit.wires.len(), num_wires);
    circuit.outputs = bristol2wire[bristol2wire.len() - NUM_OUTPUTS..]
        .iter()
        .copied()
        .map(|x| x.unwrap())
        .collect();
    circuit
}

fn do_aes(m: U8x16) -> U8x16 {
    Aes128EncryptOnly::new_with_key(m).encrypt(m)
}

const MAC_TY: FieldMacType = FieldMacType::BinaryF63b;
const WITNESS: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

#[derive(Args)]
pub struct AesArgs {
    #[clap(long, default_value_t = 1)]
    vole_concurrency: usize,
    #[clap(long, default_value_t = 2)]
    num_aes_groups: usize,
    #[clap(long, default_value_t = 2)]
    aes_per_group: usize,
}

fn ws(x: impl TryInto<WireSize>) -> WireSize {
    match x.try_into() {
        Ok(y) => y,
        Err(_) => panic!("wire size overflow"),
    }
}

pub fn aes_main(args: AesArgs) -> eyre::Result<()> {
    let vole_concurrency = args.vole_concurrency;
    let num_aes_groups = args.num_aes_groups;
    let aes_per_group = args.aes_per_group;
    let circuit = {
        let single_circuit = parse_circuit();
        let mut circuit = single_circuit.clone();
        assert!(aes_per_group >= 1);
        for _ in 1..aes_per_group {
            let mut mapping = Vec::new();
            for wire in single_circuit.wires.iter().copied() {
                mapping.push(match wire {
                    WireBody::Inv(x) => circuit.add_wire(WireBody::Inv(mapping[x])),
                    WireBody::Xor(x, y) => circuit.add_wire(WireBody::Xor(mapping[x], mapping[y])),
                    WireBody::And(x, y) => circuit.add_wire(WireBody::And(mapping[x], mapping[y])),
                    // mod 128 since message and key are the same
                    WireBody::Input(i) => circuit.outputs[i % 128],
                });
            }
            circuit.outputs.clear();
            circuit
                .outputs
                .extend(single_circuit.outputs.iter().copied().map(|x| mapping[x]));
        }
        circuit
    };
    for _ in 0..16 {
        // Check that plaintext evaluation works.
        let mut m = [0; 16];
        rand::thread_rng().fill_bytes(&mut m);
        let m = U8x16::from(m);
        let mut expected = m;
        for _ in 0..aes_per_group {
            expected = do_aes(expected);
        }
        let mut values = Vec::<bool>::with_capacity(circuit.wires.len());
        for body in circuit.wires.iter().copied() {
            let new_value = match body {
                WireBody::Inv(x) => !values[x],
                WireBody::Xor(a, b) => values[a] ^ values[b],
                WireBody::And(a, b) => values[a] & values[b],
                WireBody::Input(idx) => {
                    let i = idx % 128; // Same key and message
                    ((m.as_array()[15 - i / 8] >> (i % 8)) & 1) != 0
                }
            };
            values.push(new_value);
        }
        let actual_bits: Vec<bool> = circuit.outputs.iter().copied().map(|i| values[i]).collect();
        for (i, bit) in actual_bits.iter().enumerate() {
            assert_eq!(
                *bit,
                ((expected.as_array()[15 - i / 8] >> (i % 8)) & 1) != 0
            );
        }
    }
    let mut aes_iterations = Vec::with_capacity(num_aes_groups);
    let mut final_aes_output = U8x16::from(WITNESS);
    for _ in 0..num_aes_groups {
        aes_iterations.push(final_aes_output);
        for _ in 0..aes_per_group {
            final_aes_output = do_aes(final_aes_output);
        }
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum AesWire {
        ConstOne,
        XorOutput(usize),
        // First 128 are the message. The next wires are multiplies.
        FixOutput(usize),
    }
    const XOR_SIMD_SIZE: usize = 4;
    let (xors, mapping) = {
        let mut xors: Vec<[(AesWire, AesWire); XOR_SIMD_SIZE]> =
            Vec::with_capacity(circuit.wires.len());
        let mut mapping: Vec<Option<AesWire>> = vec![None; circuit.wires.len()];
        let mut next_mult = 0;
        for (i, wire) in circuit.wires.iter().copied().enumerate() {
            match wire {
                WireBody::Inv(_) | WireBody::Xor(_, _) => {}
                WireBody::And(_, _) => {
                    mapping[i] = Some(AesWire::FixOutput(next_mult + 128));
                    next_mult += 1;
                }
                WireBody::Input(j) => {
                    // mod 128 since message and key are the same
                    mapping[i] = Some(AesWire::FixOutput(j % 128));
                    assert!(j < NUM_INPUTS)
                }
            }
        }
        let mut ready_to_compute: BinaryHeap<Reverse<usize>> = Default::default();
        ready_to_compute.extend(circuit.wires.iter().copied().enumerate().filter_map(
            |(i, wire)| match wire {
                WireBody::Inv(x) => {
                    if mapping[x].is_some() {
                        Some(Reverse(i))
                    } else {
                        None
                    }
                }
                WireBody::Xor(x, y) => {
                    if mapping[x].is_some() && mapping[y].is_some() {
                        Some(Reverse(i))
                    } else {
                        None
                    }
                }
                WireBody::And(_, _) | WireBody::Input(_) => None,
            },
        ));
        let mut next_xor = 0;
        let mut buf = Vec::<(AesWire, AesWire)>::new();
        let mut out_ids = Vec::new();
        while !ready_to_compute.is_empty() {
            while !ready_to_compute.is_empty() && buf.len() < XOR_SIMD_SIZE {
                let Reverse(i) = ready_to_compute
                    .pop()
                    .expect("we just confirmed it's nonempty!");
                buf.push(match circuit.wires[i] {
                    WireBody::Inv(x) => (AesWire::ConstOne, mapping[x].unwrap()),
                    WireBody::Xor(x, y) => (mapping[x].unwrap(), mapping[y].unwrap()),
                    WireBody::And(_, _) | WireBody::Input(_) => unreachable!(),
                });
                out_ids.push(i);
            }
            for oid in out_ids.iter().copied() {
                assert!(mapping[oid].is_none());
                mapping[oid] = Some(AesWire::XorOutput(next_xor));
                next_xor += 1;
                for reverse_dep in circuit.reverse_deps[oid].iter().copied() {
                    match circuit.wires[reverse_dep] {
                        WireBody::Inv(x) => {
                            assert_eq!(x, oid);
                            assert!(mapping[reverse_dep].is_none());
                            ready_to_compute.push(Reverse(reverse_dep));
                        }
                        WireBody::Xor(x, y) => {
                            assert!(x == oid || y == oid);
                            assert!(mapping[reverse_dep].is_none());
                            if mapping[x].is_some() && mapping[y].is_some() {
                                ready_to_compute.push(Reverse(reverse_dep));
                            }
                        }
                        WireBody::And(_, _) | WireBody::Input(_) => continue,
                    }
                }
            }
            while buf.len() < XOR_SIMD_SIZE {
                let pair = *buf.first().unwrap();
                next_xor += 1;
                buf.push(pair);
            }
            xors.push(*<&[(AesWire, AesWire); XOR_SIMD_SIZE]>::try_from(buf.as_slice()).unwrap());
            buf.clear();
            out_ids.clear();
        }
        // DEBUG
        for (i, x) in mapping.iter().enumerate() {
            assert!(x.is_some(), "{} {:?}", i, circuit.wires[i]);
        }
        (
            xors,
            mapping.into_iter().map(|x| x.unwrap()).collect::<Vec<_>>(),
        )
    };
    eprintln!("Finished fast linear AES evaluation");
    let num_mults = ws(circuit
        .wires
        .iter()
        .filter(|x| matches!(x, WireBody::And(_, _)))
        .count());
    build_privates("aes.priv.bin", |pb| {
        build_circuit("aes.bin", |cb| {
            let mut vs = VoleSupplier::new(vole_concurrency, Default::default());
            let one = cb.new_constant_prototype(MAC_TY, [F2::ONE])?;
            let one = cb.instantiate(&one, &[], &[])?.outputs(Type::Mac(MAC_TY));
            let fix_proto = cb.new_fix_prototype(MAC_TY, 128 + num_mults)?;
            let xors_proto = cb.new_xor4_prototype(
                MAC_TY,
                &[1 /*one*/, 128 + num_mults /*fixed*/],
                xors.iter().copied().map(|entry| {
                    entry.array_map(|(a, b)| {
                        let convert = |wire| match wire {
                            AesWire::ConstOne => input_wire(0, 0),
                            AesWire::XorOutput(i) => own_wire(i),
                            AesWire::FixOutput(i) => input_wire(1, i),
                        };
                        [convert(a), convert(b)]
                    })
                }),
            )?;
            let assert_multiply_proto = cb.new_assert_multiply_prototype(
                MAC_TY,
                &[
                    ws(128 + num_mults),            /*fixed*/
                    ws(xors.len() * XOR_SIMD_SIZE), /*xors*/
                ],
                circuit
                    .wires
                    .iter()
                    .copied()
                    .enumerate()
                    .filter_map(|(i, wire)| match wire {
                        WireBody::Inv(_) | WireBody::Xor(_, _) | WireBody::Input(_) => None,
                        WireBody::And(x, y) => Some({
                            let convert = |j| match mapping[j] {
                                AesWire::ConstOne => unreachable!(),
                                AesWire::XorOutput(idx) => input_wire(1, idx),
                                AesWire::FixOutput(idx) => input_wire(0, idx),
                            };
                            [convert(x), convert(y), convert(i)]
                        }),
                    }),
            )?;
            let chaining_xor_proto = cb.new_add_prototype(
                MAC_TY,
                &[
                    128 + num_mults,                // old fixed
                    ws(xors.len() * XOR_SIMD_SIZE), // old xors
                    128 + num_mults,                // new fixed
                ],
                circuit.outputs.iter().copied().enumerate().map(|(i, o)| {
                    [
                        input_wire(2, i),
                        match mapping[o] {
                            AesWire::ConstOne => unreachable!(),
                            AesWire::XorOutput(j) => input_wire(1, j),
                            AesWire::FixOutput(j) => input_wire(0, j),
                        },
                    ]
                }),
            )?;
            let assert_zero_128_proto =
                cb.new_assert_zero_prototype(MAC_TY, &[128], (0..128).map(|i| input_wire(0, i)))?;
            let mut old_outputting_tasks = None;
            let num_threads = num_cpus::get();
            let mut channels = Vec::with_capacity(num_threads);
            for _ in 0..num_threads {
                channels.push(crossbeam::channel::bounded(2));
            }
            crossbeam::scope::<_, eyre::Result<()>>(|scope| {
                for (mut i, (channel_send, _)) in channels.iter().enumerate() {
                    let aes_iterations = &aes_iterations;
                    let circuit = &circuit;
                    let channels = &channels;
                    scope.spawn(move |_| {
                        let mut values: Vec<bool> = Vec::with_capacity(circuit.wires.len());
                        while i < aes_iterations.len() {
                            values.clear();
                            let starting_point = aes_iterations[i];
                            // TODO: we could also do the serialization in the background.
                            let mut fix_data = Vec::with_capacity(128 + num_mults as usize);
                            fix_data.extend((0..128).map(|idx| {
                                let i = idx % 128; // Same key and message
                                ((starting_point.as_array()[15 - i / 8] >> (i % 8)) & 1) != 0
                            }));
                            for gate in circuit.wires.iter().copied() {
                                let v = match gate {
                                    WireBody::Inv(x) => !values[x],
                                    WireBody::Xor(x, y) => values[x] ^ values[y],
                                    WireBody::And(x, y) => {
                                        let v = values[x] & values[y];
                                        fix_data.push(v);
                                        v
                                    }
                                    WireBody::Input(x) => fix_data[x % 128],
                                };
                                values.push(v);
                            }
                            channel_send.send((i, fix_data)).unwrap();
                            i += channels.len();
                        }
                    });
                }
                for i in 0..aes_iterations.len() {
                    let (j, fix_data) = channels[i % channels.len()].1.recv().unwrap();
                    assert_eq!(j, i);
                    let fixed_voles = vs.supply_voles(cb, &fix_proto)?;
                    let fix = cb.instantiate(&fix_proto, &[], &[fixed_voles])?;
                    pb.write_fix_data::<_, F2>(&fix, |s| {
                        for bit in fix_data.into_iter() {
                            s.add(F2::from(bit))?;
                        }
                        Ok(())
                    })?;
                    let fix = fix.outputs(Type::Mac(MAC_TY));
                    let xor = cb
                        .instantiate(&xors_proto, &[one, fix], &[])?
                        .outputs(Type::Mac(MAC_TY));
                    cb.instantiate(&assert_multiply_proto, &[fix, xor], &[])?;
                    if let Some((old_fix, old_xor)) = old_outputting_tasks {
                        let supposed_zeroes = cb
                            .instantiate(&chaining_xor_proto, &[old_fix, old_xor, fix], &[])?
                            .outputs(Type::Mac(MAC_TY));
                        cb.instantiate(&assert_zero_128_proto, &[supposed_zeroes], &[])?;
                    }
                    old_outputting_tasks = Some((fix, xor));
                }
                Ok(())
            })
            .unwrap()?;
            let (fix, xor) = old_outputting_tasks.unwrap();
            // FINAL STEP: Check that the output matches what was expected.
            let expected_value_bits: Vec<_> = (0..128)
                .map(|i| F2::from(((final_aes_output.as_array()[15 - i / 8] >> (i % 8)) & 1) != 0))
                .collect();
            let expected_value_proto =
                cb.new_constant_prototype(MAC_TY, expected_value_bits.into_iter())?;
            let expected_value = cb
                .instantiate(&expected_value_proto, &[], &[])?
                .outputs(Type::Mac(MAC_TY));
            let xor_expected_value_proto = cb.new_add_prototype(
                MAC_TY,
                &[128, ws(128 + num_mults), ws(xors.len() * XOR_SIMD_SIZE)],
                circuit
                    .outputs
                    .iter()
                    .copied()
                    .enumerate()
                    .map(|(i, wire)| {
                        [
                            input_wire(0, i),
                            match mapping[wire] {
                                AesWire::ConstOne => unreachable!(),
                                AesWire::XorOutput(j) => input_wire(2, j),
                                AesWire::FixOutput(j) => input_wire(1, j),
                            },
                        ]
                    }),
            )?;
            let xor_expected_value = cb
                .instantiate(&xor_expected_value_proto, &[expected_value, fix, xor], &[])?
                .outputs(Type::Mac(MAC_TY));
            cb.instantiate(&assert_zero_128_proto, &[xor_expected_value], &[])?;
            Ok(())
        })
    })?;
    Ok(())
}
