use crate::circuit_ir::{GateM, GatesBody, TypeSpecification};

use super::Plugin;

pub(crate) struct VectorsV1;

impl Plugin for VectorsV1 {
    const NAME: &'static str = "vectors_v1";

    fn gates_body(
        operation: &str,
        params: &[String],
        count: u64,
        output_counts: &[(crate::circuit_ir::TypeId, crate::circuit_ir::WireCount)],
        input_counts: &[(crate::circuit_ir::TypeId, crate::circuit_ir::WireCount)],
        type_store: &crate::circuit_ir::TypeStore,
    ) -> eyre::Result<crate::circuit_ir::GatesBody> {
        match operation {
            "add" | "mul" => {
                eyre::ensure!(
                    params.len() == 0,
                    "{}: {operation} expects 0 parameters, but {} were given.",
                    Self::NAME,
                    params.len(),
                );

                eyre::ensure!(
                    output_counts.len() == 1,
                    "{}: {operation} outputs 1 wire range, but this declaration specifies {}.",
                    Self::NAME,
                    output_counts.len(),
                );

                eyre::ensure!(
                    input_counts.len() == 2,
                    "{}: {operation} takes 2 wire ranges as input, but this declaration specifics {}.",
                    Self::NAME,
                    input_counts.len(),
                );

                eyre::ensure!(
                    input_counts[0].0 == input_counts[1].0,
                    "{}: The type indices of the inputs to {operation} must match: {} != {}.",
                    Self::NAME,
                    input_counts[0].0,
                    input_counts[1].0,
                );

                eyre::ensure!(
                    input_counts[0].1 == input_counts[1].1,
                    "{}: The lengths of the inputs to {operation} must match: {} != {}.",
                    Self::NAME,
                    input_counts[0].1,
                    input_counts[1].1,
                );

                eyre::ensure!(
                    output_counts[0].0 == input_counts[0].0,
                    "{}: The type of the output of {operation} must match the types of the inputs: {} != {}.",
                    Self::NAME,
                    output_counts[0].0,
                    input_counts[0].0,
                );

                eyre::ensure!(
                    output_counts[0].1 == input_counts[0].1,
                    "{}: The length of the output of {operation} must match the lengths of the inputs: {} != {}.",
                    Self::NAME,
                    output_counts[0].1,
                    input_counts[0].1,
                );

                let t = output_counts[0].0;
                let TypeSpecification::Field(_) = type_store.get(&t)? else {
                    eyre::bail!("{}: {operation} expects only field-typed inputs and outputs, but the type with index {} is plugin-defined.", Self::NAME, t);
                };

                let s = output_counts[0].1;

                let mut gates = vec![];
                for i in 0..s {
                    gates.push(match operation {
                        "add" => GateM::Add(t, i, s + i, 2 * s + i),
                        "mul" => GateM::Mul(t, i, s + i, 2 * s + i),
                        _ => panic!("The universe is broken."),
                    });
                }

                Ok(GatesBody::new(gates))
            }
            "addc" | "mulc" => {
                eyre::ensure!(
                    params.len() == 1,
                    "{}: {operation} expects 1 parameter (the constant), but {} were given.",
                    Self::NAME,
                    params.len(),
                );

                eyre::ensure!(
                    output_counts.len() == 1,
                    "{}: {operation} outputs 1 wire range, but this declaration specifies {}.",
                    Self::NAME,
                    output_counts.len(),
                );

                eyre::ensure!(
                    input_counts.len() == 1,
                    "{}: {operation} takes 1 wire range as input, but this declaration specifies {}.",
                    Self::NAME,
                    input_counts.len(),
                );

                eyre::ensure!(
                    output_counts[0].0 == input_counts[0].0,
                    "{}: The type of the output of {operation} must match the type of the input: {} != {}.",
                    Self::NAME,
                    output_counts[0].0,
                    input_counts[0].0,
                );

                eyre::ensure!(
                    output_counts[0].1 == input_counts[0].1,
                    "{}: The length of the output of {operation} must match the length of the input: {} != {}.",
                    Self::NAME,
                    output_counts[0].1,
                    input_counts[0].1,
                );

                let t = output_counts[0].0;
                let TypeSpecification::Field(_) = type_store.get(&t)? else {
                    eyre::bail!("{}: {operation} expects only field-typed inputs and outputs, but the type with index {} is plugin-defined.", Self::NAME, t);
                };

                let s = output_counts[0].1;

                // TODO: Uncomment this:
                //
                // let PluginTypeArg::Number(c) = params[0] else {
                //     eyre::bail!("{}: The constant parameter must be numeric, not a string.", Self::NAME);
                // };
                // let c = c.to_le_bytes().to_vec();
                //
                // once MR !236 is merged.

                let mut gates = vec![];
                for i in 0..s {
                    gates.push(match operation {
                        "addc" => {
                            GateM::AddConstant(t, i, s + i, todo!("Replace with `c`."))
                        }
                        "mulc" => {
                            GateM::MulConstant(t, i, s + i, todo!("Replace with `c`."))
                        }
                        _ => panic!("The universe is broken."),
                    });
                }

                Ok(GatesBody::new(gates))
            }
            "add_scalar" | "mul_scalar" => todo!(),
            "sum" | "product" => todo!(),
            "dotproduct" => todo!(),
            _ => eyre::bail!("{}: Unknown operation: {operation}", Self::NAME,),
        }
    }
}
