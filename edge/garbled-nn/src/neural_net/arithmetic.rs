use crate::{
    Accuracy, ActivationFunction, NeuralNet,
    layer::Layer,
    neural_net::FancyNeuralNet,
    util::{from_mod_q_crt, to_mod_q, to_mod_q_crt},
};
use fancy_circuits::util::factor;
use fancy_circuits::{
    CrtBundle, CrtGadgets,
    arithmetic::{Addition, Constant, ConstantMultiplication, Max, ReLU, Sgn},
};
use fancy_traits::{Circuit, FancyArithmetic, FancyBinary, FancyConstant, FancyProj, HasModulus};
use ndarray::Array3;
use swanky_channel::Channel;
use swanky_error::{ErrorKind, Result, WrapErr};

/// [`NeuralNet`] evaluator for arithmetic circuit representations of the neural
/// network.
pub(crate) struct ArithmeticNeuralNet<'a, F> {
    backend: &'a mut F,
    moduli: &'a [u128],
    secret_weights_owned: bool,
}

impl<'a, F: FancyConstant + FancyBinary + FancyArithmetic + FancyProj + CrtGadgets>
    ArithmeticNeuralNet<'a, F>
{
    /// Create a new `ArithmeticNeuralNet` for the provided backend and using
    /// the specified moduli for each layer of the neural net.
    ///
    /// The `secret_weights_owned` argument denotes whether this evaluator
    /// "owns" the secret weights or not. Generally, the owner is the garbled
    /// circuit garbler, and the non-owner is the garbled circuit evaluator.
    pub(crate) fn new(backend: &'a mut F, moduli: &'a [u128], secret_weights_owned: bool) -> Self {
        Self {
            backend,
            moduli,
            secret_weights_owned,
        }
    }

    /// Encode an input so it can be evaluated by an arithmetic [`NeuralNet`].
    pub(crate) fn encode_input(
        &mut self,
        input: &Array3<i64>,
        channel: &mut Channel,
    ) -> Result<Vec<CrtBundle<F::Item>>> {
        input
            .iter()
            .map(|&x| {
                self.backend
                    .crt_encode(to_mod_q(x, self.moduli[0]), self.moduli[0], channel)
            })
            .collect()
    }

    /// Receive an input so it can be evaluated by an arithmetic [`NeuralNet`].
    pub(crate) fn receive_input(
        &mut self,
        input: &Array3<i64>,
        channel: &mut Channel,
    ) -> Result<Vec<CrtBundle<F::Item>>> {
        input
            .iter()
            .map(|_| self.backend.crt_receive(self.moduli[0], channel))
            .collect()
    }

    /// Decode an arithmetic output of a [`NeuralNet`] evaluation.
    pub(crate) fn decode_output(
        &mut self,
        output: &[CrtBundle<F::Item>],
        channel: &mut Channel,
    ) -> Result<Option<Vec<i64>>> {
        let mut result = Vec::with_capacity(output.len());
        for out in output.iter() {
            let vals = out
                .wires()
                .iter()
                .map(|v| self.backend.output(v, channel))
                .collect::<Result<Vec<_>>>()?;
            let vals = vals.into_iter().collect::<Option<Vec<_>>>();
            let val = vals.map(|vals| from_mod_q_crt(&vals, *self.moduli.last().unwrap()));
            result.push(val);
        }
        // We need to do the conversion from `Vec<Option>` to `Option<Vec>`
        // _after_ we construct the vector in its entirety, because otherwise
        // it'll short-circuit the execution, causing the garbler to exit out on
        // the first `None`.
        Ok(result.into_iter().collect::<Option<_>>())
    }

    /// Evaluate [`NeuralNet`] as an arithmetic circuit.
    ///
    /// # Panics
    /// Panics if `moduli.len()` is not equal to `self.nlayers() + 1`, or if
    /// `circuit_inputs` does not match the dimensions of the input layer.
    pub(crate) fn eval(
        &mut self,
        nn: &NeuralNet,
        circuit_inputs: &[CrtBundle<F::Item>],
        secret_weights: bool,
        accuracy: &Accuracy,
        channel: &mut Channel,
    ) -> Result<Vec<CrtBundle<F::Item>>> {
        assert_eq!(
            self.moduli.len(),
            nn.layers.len() + 1,
            "moduli for each layer and output required"
        );

        // Map the user-provided inputs to the input layer dimensions.
        let mut acc = Array3::from_shape_vec(nn.layers[0].input_dims(), circuit_inputs.to_vec())
            .wrap_err(
                ErrorKind::InitializationError,
                "Failed to initialize input layer",
            )?;
        // Evaluate the neural net layer-by-layer.
        for (i, layer) in nn.layers.iter().enumerate() {
            let mut backend = ArithmeticLayer::new(
                self.backend,
                self.moduli[i],
                self.moduli[i + 1],
                self.secret_weights_owned,
                accuracy.clone(),
            );
            acc = layer.eval(&mut backend, acc, secret_weights, channel)?;
        }
        Ok(acc.into_raw_vec_and_offset().0)
    }
}

/// A neural network layer represented as an arithmetic circuit.
struct ArithmeticLayer<'a, F> {
    backend: &'a mut F,
    input_modulus: u128,
    output_modulus: u128,
    secret_weights_owned: bool,
    accuracy: Accuracy,
}

impl<'a, F> ArithmeticLayer<'a, F> {
    /// Create a new `ArithmeticLayer`, specifying the input and output moduli
    /// of this layer.
    ///
    /// The `secret_weights_owned` argument denotes whether this evaluator
    /// "owns" the secret weights or not. Generally, the owner is the garbled
    /// circuit garbler, and the non-owner is the garbled circuit evaluator.
    ///
    /// The `accuracy` argument specifies the accuracy of various internal
    /// operations. See [`Accuracy`] for more details.
    fn new(
        backend: &'a mut F,
        input_modulus: u128,
        output_modulus: u128,
        secret_weights_owned: bool,
        accuracy: Accuracy,
    ) -> Self {
        Self {
            backend,
            input_modulus,
            output_modulus,
            secret_weights_owned,
            accuracy,
        }
    }
}

impl<'a, F: FancyConstant + FancyBinary + FancyArithmetic + FancyProj + CrtGadgets> FancyNeuralNet
    for ArithmeticLayer<'a, F>
{
    type Item = CrtBundle<F::Item>;

    fn nn_encode(&mut self, value: i64, channel: &mut Channel) -> Result<Self::Item> {
        Constant::new(to_mod_q(value, self.input_modulus), self.input_modulus).execute(
            self.backend,
            (),
            channel,
        )
    }

    fn nn_secret(&mut self, value: Option<i64>, channel: &mut Channel) -> Result<Self::Item> {
        if self.secret_weights_owned {
            self.backend.crt_encode(
                to_mod_q(value.unwrap(), self.input_modulus),
                self.input_modulus,
                channel,
            )
        } else {
            self.backend.crt_receive(self.input_modulus, channel)
        }
    }

    fn nn_add(
        &mut self,
        x: &Self::Item,
        y: &Self::Item,
        channel: &mut Channel,
    ) -> Result<Self::Item> {
        Addition::new().execute(self.backend, (x, y), channel)
    }

    fn nn_cmul(
        &mut self,
        x: &Self::Item,
        constant: i64,
        channel: &mut Channel,
    ) -> Result<Self::Item> {
        ConstantMultiplication::new().execute(
            self.backend,
            (x, to_mod_q(constant, self.input_modulus)),
            channel,
        )
    }

    fn nn_proj(
        &mut self,
        x: &Self::Item,
        tt: Option<i64>,
        channel: &mut Channel,
    ) -> Result<Self::Item> {
        if let Some(w) = tt {
            // convert the weight to crt mod q
            let ws = to_mod_q_crt(w, self.input_modulus);
            Ok(CrtBundle::new(
                x.wires()
                    .iter()
                    .zip(ws.iter())
                    .map(|(wire, weight)| {
                        let q = wire.modulus();
                        let tab = (0..q).map(|x| x * weight % q).collect::<Vec<_>>();
                        // project each input x to x*w
                        self.backend.proj(wire, q, Some(tab), channel)
                    })
                    .collect::<Result<Vec<_>>>()?,
            ))
        } else {
            Ok(CrtBundle::new(
                x.wires()
                    .iter()
                    .map(|wire| {
                        // project the input, without knowing the weight
                        self.backend.proj(wire, wire.modulus(), None, channel)
                    })
                    .collect::<Result<Vec<_>>>()?,
            ))
        }
    }

    fn nn_max(&mut self, xs: &[Self::Item], channel: &mut Channel) -> Result<Self::Item> {
        Max::new().execute(self.backend, (xs, &self.accuracy.max), channel)
    }

    fn nn_activation(
        &mut self,
        f: &crate::ActivationFunction,
        x: &Self::Item,
        channel: &mut Channel,
    ) -> Result<Self::Item> {
        let ps = factor(self.output_modulus);
        match f {
            ActivationFunction::Sign => {
                Sgn::new().execute(self.backend, (x, &self.accuracy.sign, Some(&ps)), channel)
            }
            ActivationFunction::Relu => {
                ReLU::new().execute(self.backend, (x, &self.accuracy.relu, Some(&ps)), channel)
            }
            ActivationFunction::Identity => Ok(x.clone()),
        }
    }

    fn nn_zero(&mut self, channel: &mut Channel) -> Result<Self::Item> {
        Constant::new(0, self.input_modulus).execute(self.backend, (), channel)
    }
}
