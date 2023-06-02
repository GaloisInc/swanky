use crate::backend_multifield::{GateM, GatesBody, TypeId, WireCount};
use eyre::eyre;
use scuttlebutt::{field::F2, ring::FiniteRing, serialization::CanonicalSerialize};

pub(crate) struct PluginMuxV0;

impl PluginMuxV0 {
    pub(crate) fn gates_body(
        operation: &str,
        count: u64,
        input_counts: &[(TypeId, WireCount)],
        output_counts: &[(TypeId, WireCount)],
    ) -> eyre::Result<GatesBody> {
        if operation != "strict" {
            return Err(eyre!(
                "mux_v0 implementation only handles strict permissiveness: {operation}",
            ));
        }

        // r <- mux(cond, b_0, b_1)
        // cond_neg = cond + 1
        // r = b_0 * cond_neg + b_1 * cond
        // TODO: could minimize the number of multiplication gates

        let field = input_counts[0].0;
        let callframe_size = count;

        let mut vec_gates = vec![];

        // 1) find where the condition is:
        let mut prev = 0;
        // assert_eq!(out_ranges.len(), func.output_counts.len());
        for (_field_idx, count) in output_counts {
            prev += *count;
        }

        // assert_eq!(in_ranges.len(), func.input_counts.len());
        let cond = prev;

        // 2) MUX dedicated circuit

        // wire_cond_neg <- cond - 1
        let wire_cond_neg = callframe_size;
        vec_gates.push(
            GateM::AddConstant(
                field,
                wire_cond_neg,
                cond,
                Box::from(F2::ONE.to_bytes().to_vec()),
            ), // WARNING only works in F2
        );

        let middle_index = input_counts.len() / 2; // WARNING: works for F2, Should divide by the number of possibilities

        let mut pos = 0;
        for i in 0..middle_index {
            let (field, how_many) = input_counts[1 + i];
            for idx in 0..how_many {
                // Allocate one new wire per input.
                //println!("WIRE 0: {:?}", callframe_size + 1 + pos + idx);
                //println!("WIRE 0: {:?}", wire_cond_neg);
                //println!("WIRE 0: {:?}", cond + 1 + pos + idx);
                vec_gates.push(GateM::Mul(
                    field,
                    callframe_size + 1 + pos + idx,
                    wire_cond_neg,
                    cond + 1 + pos + idx,
                ));
            }
            pos += how_many;
        }

        let input_range = pos;

        let mut pos = 0;
        for i in 0..middle_index {
            let (field, how_many) = input_counts[1 + middle_index + i];
            for idx in 0..how_many {
                //println!("WIRE 1: {:?}", callframe_size + 1 + input_range + pos + idx);
                //println!("WIRE 1: {:?}", cond);
                //println!("WIRE 1: {:?}", cond + 1 + input_range + pos + idx);
                vec_gates.push(GateM::Mul(
                    field,
                    callframe_size + 1 + input_range + pos + idx,
                    cond,
                    cond + 1 + input_range + pos + idx,
                ));
            }
            pos += how_many;
        }

        let mut pos = 0;
        for (field, how_many) in output_counts {
            for idx in 0..*how_many {
                //println!("WIRE 2: {:?}", pos + idx);
                //println!("WIRE 2: {:?}", callframe_size + 1 + pos + idx);
                //println!("WIRE 2: {:?}", callframe_size + 1 + input_range + pos + idx);
                vec_gates.push(GateM::Add(
                    *field,
                    pos + idx,
                    callframe_size + 1 + pos + idx,
                    callframe_size + 1 + input_range + pos + idx,
                ));
            }
            pos += how_many;
        }

        Ok(GatesBody::new(vec_gates))
    }
}
