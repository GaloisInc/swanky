use crate::circuit_ir::{GateM, GatesBody, TypeId, TypeSpecification, TypeStore, WireCount};

use super::Plugin;

pub(crate) struct VectorsV1;

impl Plugin for VectorsV1 {
    const NAME: &'static str = "vectors_v1";

    fn gates_body(
        operation: &str,
        params: &[String],
        count: u64,
        output_counts: &[(TypeId, WireCount)],
        input_counts: &[(TypeId, WireCount)],
        type_store: &TypeStore,
    ) -> eyre::Result<GatesBody> {
        eyre::ensure!(
            output_counts.len() == 1,
            "{}: {operation} outputs 1 wire range, but this declaration specifies {}.",
            Self::NAME,
            output_counts.len(),
        );

        let t = output_counts[0].0;
        let TypeSpecification::Field(_) = type_store.get(&t)? else {
            eyre::bail!("{}: {operation} expects only field-typed inputs and outputs, but the type with index {} is plugin-defined.", Self::NAME, t);
        };

        match operation {
            "add" | "mul" => {
                eyre::ensure!(
                    params.len() == 0,
                    "{}: {operation} expects 0 parameters, but {} were given.",
                    Self::NAME,
                    params.len(),
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
                        "addc" => GateM::AddConstant(t, i, s + i, todo!("Replace with `c`.")),
                        "mulc" => GateM::MulConstant(t, i, s + i, todo!("Replace with `c`.")),
                        _ => panic!("The universe is broken."),
                    });
                }

                Ok(GatesBody::new(gates))
            }
            "add_scalar" | "mul_scalar" => {
                eyre::ensure!(
                    params.len() == 0,
                    "{}: {operation} expects 0 parameters, but {} were given.",
                    Self::NAME,
                    params.len(),
                );

                eyre::ensure!(
                    input_counts.len() == 2,
                    "{}: {operation} takes 2 wire ranges as input, but this declaration specifies {}.",
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
                    output_counts[0].0 == input_counts[0].0,
                    "{}: The type of the output of {operation} must match the types of the inputs: {} != {}.",
                    Self::NAME,
                    output_counts[0].0,
                    input_counts[0].0,
                );

                eyre::ensure!(
                    output_counts[0].1 == input_counts[0].1,
                    "{}: The length of the output of {operation} must match the length of the vector input: {} != {}",
                    Self::NAME,
                    output_counts[0].1,
                    input_counts[0].1,
                );

                eyre::ensure!(
                    input_counts[1].1 == 1,
                    "{}: The scalar input to {operation} must be given on a single wire.",
                    Self::NAME,
                );

                let s = output_counts[0].1;

                let mut gates = vec![];
                for i in 0..s {
                    gates.push(match operation {
                        "add_scalar" => GateM::Add(t, i, s + i, count - 1),
                        "mul_scalar" => GateM::Mul(t, i, s + i, count - 1),
                        _ => panic!("The universe is broken."),
                    });
                }

                Ok(GatesBody::new(gates))
            }
            "sum" | "product" => {
                eyre::ensure!(
                    params.len() == 0,
                    "{}; {operation} expects 0 parameters, but {} were given.",
                    Self::NAME,
                    params.len(),
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
                    output_counts[0].1 == 1,
                    "{}: The length of the output of {operation} must be 1, but this declaration specifies {}.",
                    Self::NAME,
                    output_counts[0].1,
                );

                let s = input_counts[0].1;

                let mut gates = vec![];
                match s {
                    0 => gates.push(match operation {
                        "sum" => GateM::Constant(t, 0, Box::new(vec![0])),
                        "product" => GateM::Constant(t, 0, Box::new(vec![1])),
                        _ => panic!("The universe is broken."),
                    }),
                    1 => gates.push(GateM::Copy(t, 0, 1)),
                    2 => gates.push(match operation {
                        "sum" => GateM::Add(t, 0, 1, 2),
                        "product" => GateM::Mul(t, 0, 1, 2),
                        _ => panic!("The universe is broken."),
                    }),
                    _ => {
                        let mut res = count;

                        gates.push(match operation {
                            "sum" => GateM::Add(t, res, 1, 2),
                            "product" => GateM::Mul(t, res, 1, 2),
                            _ => panic!("The universe is broken."),
                        });

                        for i in 3..=s {
                            gates.push(match operation {
                                "sum" => GateM::Add(t, res + 1, res, i),
                                "product" => GateM::Mul(t, res + 1, res, i),
                                _ => panic!("The universe is broken."),
                            });

                            res += 1;
                        }

                        gates.push(GateM::Copy(t, 0, res));
                    }
                };

                Ok(GatesBody::new(gates))
            }
            "dotproduct" => {
                eyre::ensure!(
                    params.len() == 0,
                    "{}: {operation} expects 0 parameters, but {} were given.",
                    Self::NAME,
                    params.len(),
                );

                eyre::ensure!(
                    input_counts.len() == 2,
                    "{}: {operation} takes 2 wire ranges as input, but this declarations specifies {}.",
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
                    output_counts[0].1 == 1,
                    "{}: The length of the output of {operation} must be 1, but this declaration specifies {}.",
                    Self::NAME,
                    output_counts[0].1,
                );

                let s = input_counts[0].1;

                let mut gates = vec![];
                match s {
                    0 => gates.push(GateM::Constant(t, 0, Box::new(vec![0]))),
                    1 => gates.push(GateM::Mul(t, 0, 1, 2)),
                    2 => gates.append(&mut vec![
                        GateM::Mul(t, count, 1, s + 1),
                        GateM::Mul(t, count + 1, 2, s + 2),
                        GateM::Add(t, 0, count, count + 1),
                    ]),
                    _ => {
                        for i in 1..=s {
                            gates.push(GateM::Mul(t, count + i - 1, i, s + i));
                        }

                        let mut res = count + s;
                        gates.push(GateM::Add(t, res, count, count + 1));

                        let first_sum = res;
                        for i in (count + 2)..first_sum {
                            gates.push(GateM::Add(t, res + 1, res, i));

                            res += 1;
                        }

                        gates.push(GateM::Copy(t, 0, res));
                    }
                };

                Ok(GatesBody::new(gates))
            }
            _ => eyre::bail!("{}: Unknown operation: {operation}", Self::NAME,),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::VectorsV1;
    use crate::{
        backend_multifield::tests::test_circuit,
        circuit_ir::{FunStore, FuncDecl, GateM, TypeStore},
        plugins::Plugin,
    };

    #[test]
    fn test_vector_add() {}

    #[test]
    fn test_vector_mul() {}

    #[test]
    fn test_vector_addc() {}

    #[test]
    fn test_vector_mulc() {}

    #[test]
    fn test_vector_add_scalar() {}

    #[test]
    fn test_vector_mul_scalar() {}

    #[test]
    fn test_vector_sum() {}

    #[test]
    fn test_vector_product() {}

    #[test]
    fn test_vector_dotproduct() {}
}
