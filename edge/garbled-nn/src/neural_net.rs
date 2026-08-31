use crate::{
    layer::{
        Accuracy, ActivationFunction, Layer, Layers, activation::LayerActivation,
        convolutional::LayerConvolutional, dense::LayerDense, flatten::LayerFlatten,
        max_pooling_2d::LayerMaxPooling2D,
    },
    neural_net::{arithmetic::ArithmeticNeuralNet, binary::BinaryNeuralNet},
    util,
};
use fancy_analyzer::CircuitAnalyzer;
use fancy_circuits::{BinaryBundle, BinaryGadgets, CrtGadgets};
use fancy_garbling::{
    AllWire, BinaryWireLabel, WireMod2,
    classic::{GarbledChannel, GarbledCircuit},
    util::output_tweak,
};
use fancy_traits::{FancyArithmetic, FancyBinary, FancyProj, HasModulus};
use ndarray::Array3;
use rand::{CryptoRng, Rng};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use serde_json::{self, Map, Value};
use std::{
    fs::File,
    path::Path,
    time::{Duration, Instant},
};
use swanky_block::Block;
use swanky_channel::Channel;
use swanky_error::{ErrorKind, Result, WrapErr, swanky_error};
use swanky_ot_alsz_kos::alsz;
use swanky_rng::SwankyRng;
use swanky_twopac::semihonest::{Evaluator, Garbler};

pub(crate) trait NeuralNetExecutor<F: FancyNeuralNet> {
    fn execute(
        &self,
        backend: &mut F,
        inputs: Array3<F::Item>,
        secret_weights: bool,
        channel: &mut Channel,
    ) -> Result<Array3<F::Item>>;
}

/// A [`Fancy`] trait for evaluating neural networks.
///
/// This contains methods necessary for neural network evaluation.
pub trait FancyNeuralNet {
    type Item: Clone;

    fn nn_encode(&mut self, value: i64, channel: &mut Channel) -> Result<Self::Item>;
    fn nn_secret(&mut self, value: Option<i64>, channel: &mut Channel) -> Result<Self::Item>;
    fn nn_add(
        &mut self,
        x: &Self::Item,
        y: &Self::Item,
        channel: &mut Channel,
    ) -> Result<Self::Item>;
    fn nn_cmul(
        &mut self,
        x: &Self::Item,
        constant: i64,
        channel: &mut Channel,
    ) -> Result<Self::Item>;
    fn nn_proj(
        &mut self,
        x: &Self::Item,
        tt: Option<i64>,
        channel: &mut Channel,
    ) -> Result<Self::Item>;
    fn nn_max(&mut self, xs: &[Self::Item], channel: &mut Channel) -> Result<Self::Item>;
    fn nn_activation(
        &mut self,
        f: &ActivationFunction,
        x: &Self::Item,
        channel: &mut Channel,
    ) -> Result<Self::Item>;
    fn nn_zero(&mut self, channel: &mut Channel) -> Result<Self::Item>;
}

pub(crate) mod arithmetic;
pub(crate) mod binary;
pub(crate) mod bitwidth;
pub(crate) mod plaintext;

/// Input encoder for a garbled neural network.
///
/// This is created by the garbler, and allows the evaluator to encode its
/// (plaintext) input into the appropriate input wirelabels associated with the
/// garbled neural network.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct InputEncoder<W> {
    inputs: Vec<BinaryBundle<W>>,
    delta: W,
}

impl<W: BinaryWireLabel> InputEncoder<W> {
    fn new(inputs: Vec<BinaryBundle<W>>, delta: W) -> Self {
        Self { inputs, delta }
    }

    /// Encode an input into its associated wirelabels.
    ///
    /// # Panics
    /// This panics if `input.len() ≠ self.inputs.len()`.
    pub fn encode_inputs(&self, input: &Array3<i64>, bitwidth: usize) -> Vec<BinaryBundle<W>> {
        assert_eq!(input.len(), self.inputs.len());
        self.inputs
            .iter()
            .zip(input)
            .map(|(zeros, &x)| {
                let bits = util::i64_to_twos_complement(x, bitwidth);
                BinaryBundle::new(
                    zeros
                        .wires()
                        .iter()
                        .enumerate()
                        .map(|(i, zero)| *zero + self.delta * (1 & (bits >> i) as u16))
                        .collect::<Vec<_>>(),
                )
            })
            .collect()
    }
}

/// Output map for a garbled neural network.
///
/// This is created by the garbler, and allows the evaluator to map its output
/// wirelabels to their associated (plaintext) outputs.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct OutputMap {
    // The first entry is the zero wirelabel, and the second entry is the one
    // wirelabel for that bundle.
    outputs: Vec<Vec<[Block; 2]>>,
}

impl OutputMap {
    fn new<W: BinaryWireLabel>(bundles: &[BinaryBundle<W>], delta: W) -> Self {
        let mut outputs = Vec::with_capacity(bundles.len());
        for (i, zeros) in bundles.iter().enumerate() {
            let wires = zeros
                .wires()
                .iter()
                .map(|zero| {
                    [
                        zero.hash(output_tweak(i, 0)),
                        (*zero + delta).hash(output_tweak(i, 1)),
                    ]
                })
                .collect::<Vec<_>>();
            outputs.push(wires);
        }
        Self { outputs }
    }

    /// Decode a garbled neural network output.
    pub fn to_outputs<W: BinaryWireLabel>(&self, bundles: &[BinaryBundle<W>]) -> Result<Vec<i64>> {
        let mut outputs = Vec::with_capacity(bundles.len());
        for (i, bundle) in bundles.iter().enumerate() {
            let mut bits = Vec::with_capacity(bundle.size());
            for (j, wire) in bundle.wires().iter().enumerate() {
                let mut decoded = None;
                for k in 0..2 {
                    let hashed = wire.hash(output_tweak(i, k));
                    if hashed == self.outputs[i][j][k as usize] {
                        decoded = Some(k);
                        break;
                    }
                }
                if let Some(bit) = decoded {
                    bits.push(bit);
                } else {
                    swanky_error::bail!(
                        ErrorKind::OtherError,
                        "Decoding failed for wire {j} in bundle {i}"
                    );
                }
            }
            outputs.push(util::i64_from_bits(&bits));
        }
        Ok(outputs)
    }
}

/// A neural network that can be garbled.
pub struct NeuralNet {
    layers: Vec<Layers>,
}

impl std::fmt::Debug for NeuralNet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "neural net info:")?;
        writeln!(f, "  input dimensions: {:?}", self.layers[0].input_dims())?;
        for layer in self.layers.iter() {
            writeln!(f, "  {:?}", layer)?;
            writeln!(f, "    inp={:?}", layer.input_dims())?;
            writeln!(f, "    out={:?}", layer.output_dims())?;
        }
        Ok(())
    }
}

impl NeuralNet {
    /// Converts a directory into a [`NeuralNet`].
    ///
    /// The directory must have properly formatted `model.json` and `weights.json`
    /// files, otherwise an error is thrown.
    ///
    /// # Errors
    /// This returns an error if the directory does not contain a `model.json` file
    /// and a `weights.json` file.
    pub fn from_dir(dir: &Path) -> Result<Self> {
        let model_path = dir.join(Path::new("model.json"));
        swanky_error::ensure!(
            model_path.is_file(),
            ErrorKind::FilesystemError,
            "`model.json` does not exist in the given diretory"
        );

        let weights_path = dir.join(Path::new("weights.json"));
        swanky_error::ensure!(
            weights_path.is_file(),
            ErrorKind::FilesystemError,
            "`weights.json` does not exist in the given diretory"
        );

        NeuralNet::from_json(&model_path, &weights_path)
    }

    /// The number of inputs to the first layer of the neural network.
    pub fn ninputs(&self) -> usize {
        self.layers[0].input_size()
    }

    /// The number of layers in the neural network.
    pub fn nlayers(&self) -> usize {
        self.layers.len()
    }

    /// The max number of bits necessary for a value on any wire for each layer.
    pub fn max_bitwidth(&self, inputs: &[Array3<i64>]) -> Result<Vec<usize>> {
        let mut max_nbits: Vec<usize> = vec![0; self.layers.len()];

        for (i, input) in inputs.iter().enumerate() {
            // TODO: Remove this `println`, use some logging infrastructure instead?
            println!("Current bitwidth ({}): {max_nbits:?}", i + 1);

            let new_max_nbits = bitwidth::eval(self, input)?;
            for (a, b) in max_nbits.iter_mut().zip(new_max_nbits) {
                if b > *a {
                    *a = b;
                }
            }
        }

        Ok(max_nbits)
    }

    /// Read a [`NeuralNet`] from model and weights files containing data in
    /// tensorflow JSON output.
    pub fn from_json(model: &Path, weights: &Path) -> Result<Self> {
        // Extract the layers from `model`.
        let file = File::open(model).wrap_err_with(ErrorKind::FilesystemError, || {
            format!("Failed to open file '{model:?}'")
        })?;
        let root: Value = serde_json::from_reader(file)
            .wrap_err_with(ErrorKind::OtherError, || {
                format!("Failed to open file '{model:?}' as JSON")
            })?;
        let root = root.as_object().ok_or_else(|| {
            swanky_error!(
                ErrorKind::OtherError,
                "Root value in {model:?} must be an object",
            )
        })?;

        let layers_json = if root
            .get("config")
            .ok_or_else(|| {
                swanky_error!(
                    ErrorKind::OtherError,
                    "Root object in {model:?} must contain 'config' key",
                )
            })?
            .is_array()
        {
            &root["config"]
        } else {
            let config = root["config"].as_object().ok_or_else(|| {
                swanky_error!(
                    ErrorKind::OtherError,
                    "Config value must be either an array or an object",
                )
            })?;
            config.get("layers").ok_or_else(|| {
                swanky_error!(
                    ErrorKind::OtherError,
                    "Config object must contain 'layers' key",
                )
            })?
        };

        // Extract the weights and biases from `weights`.
        let file = File::open(weights).wrap_err_with(ErrorKind::FilesystemError, || {
            format!("Failed to open file '{model:?}'")
        })?;
        let root: Value = serde_json::from_reader(file)
            .wrap_err_with(ErrorKind::OtherError, || {
                format!("Failed to open file '{model:?}' as JSON")
            })?;
        let mut weights_and_biases_iter = root
            .as_array()
            .ok_or_else(|| {
                swanky_error!(
                    ErrorKind::OtherError,
                    "Root value in {weights:?} must be an array",
                )
            })?
            .as_chunks::<2>()
            .0
            .iter();

        let mut layers = Vec::<Layers>::new();
        for layer in layers_json
            .as_array()
            .ok_or_else(|| swanky_error!(ErrorKind::OtherError, "Layers value must be an array"))?
            .iter()
            .map(|c| {
                c.as_object().ok_or_else(|| {
                    swanky_error!(
                        ErrorKind::OtherError,
                        "Layers array value must be an object",
                    )
                })
            })
        {
            let layer = layer?;
            let cfg = layer
                .get("config")
                .ok_or_else(|| {
                    swanky_error!(
                        ErrorKind::OtherError,
                        "Layer object must contain 'config' key",
                    )
                })?
                .as_object()
                .ok_or_else(|| {
                    swanky_error!(ErrorKind::OtherError, "Config value must be an object")
                })?;

            // Extract whether to use padding from the config object.
            let is_padding = |cfg: &Map<String, Value>| -> Result<bool> {
                let padding = cfg
                    .get("padding")
                    .ok_or_else(|| {
                        swanky_error!(
                            ErrorKind::OtherError,
                            "Config object must contain 'padding' key",
                        )
                    })?
                    .as_str()
                    .ok_or_else(|| {
                        swanky_error!(ErrorKind::OtherError, "Padding value must be a string")
                    })?;
                Ok(padding == "same")
            };

            // Extract the biases from the biases object.
            let biases = |biases_json: &Value| -> Result<Vec<Option<i64>>> {
                let mut biases = Vec::new();
                for bias in biases_json
                    .as_array()
                    .ok_or_else(|| {
                        swanky_error!(ErrorKind::OtherError, "Biases value must be an array")
                    })?
                    .iter()
                {
                    let bias = bias.as_i64().ok_or_else(|| {
                        swanky_error!(ErrorKind::OtherError, "Bias value must be an integer")
                    })?;
                    biases.push(Some(bias));
                }
                Ok(biases)
            };

            // Extract the `ActivationFunction` from the config object.
            let activation = |cfg: &Map<String, Value>| -> Result<ActivationFunction> {
                ActivationFunction::try_from(
                    cfg.get("activation")
                        .ok_or_else(|| {
                            swanky_error!(
                                ErrorKind::OtherError,
                                "Config object must contain 'activation' key",
                            )
                        })?
                        .as_str()
                        .ok_or_else(|| {
                            swanky_error!(
                                ErrorKind::OtherError,
                                "Activation value must be a string",
                            )
                        })?,
                )
            };

            // Extract the stride from the config object.
            let stride = |cfg: &Map<String, Value>| -> Result<(usize, usize)> {
                let stride = cfg
                    .get("strides")
                    .ok_or_else(|| {
                        swanky_error!(
                            ErrorKind::OtherError,
                            "Config object must contain 'strides' key",
                        )
                    })?
                    .as_array()
                    .ok_or_else(|| {
                        swanky_error!(ErrorKind::OtherError, "Strides value must be an array")
                    })?
                    .iter()
                    .map(|v| {
                        v.as_u64().ok_or_else(|| {
                            swanky_error!(
                                ErrorKind::OtherError,
                                "Strides array value must be an integer",
                            )
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                swanky_error::ensure!(
                    stride.len() >= 2,
                    ErrorKind::OtherError,
                    "Strides array must have at least two elements"
                );
                Ok((stride[0] as usize, stride[1] as usize))
            };

            let input_shape = if let Some(v) = cfg.get("batch_input_shape") {
                let mut shape = v
                    .as_array()
                    .ok_or_else(|| {
                        swanky_error!(ErrorKind::OtherError, "Batch input shape must be an array")
                    })?
                    .clone();
                if shape[0].is_null() {
                    shape.remove(0);
                }
                let height = shape[0].as_u64().ok_or_else(|| {
                    swanky_error!(ErrorKind::OtherError, "Height must be an unsigned integer")
                })? as usize;
                let width = if shape.len() > 1 {
                    shape[1].as_u64().ok_or_else(|| {
                        swanky_error!(ErrorKind::OtherError, "Width must be an unsigned integer")
                    })? as usize
                } else {
                    1
                };
                let depth = if shape.len() > 2 {
                    shape[2].as_u64().ok_or_else(|| {
                        swanky_error!(ErrorKind::OtherError, "Depth must be an unsigned integer")
                    })? as usize
                } else {
                    1
                };
                (height, width, depth)
            } else {
                layers
                    .last()
                    .ok_or_else(|| {
                        swanky_error!(
                            ErrorKind::OtherError,
                            "No last layer to extract input shape",
                        )
                    })?
                    .output_dims()
            };

            match layer
                .get("class_name")
                .ok_or_else(|| {
                    swanky_error!(
                        ErrorKind::OtherError,
                        "Layer object must contain 'class_name' key",
                    )
                })?
                .as_str()
                .ok_or_else(|| {
                    swanky_error!(ErrorKind::OtherError, "Layer class name must be a string")
                })? {
                "Dense" => {
                    let weights_and_biases = weights_and_biases_iter.next().ok_or_else(|| {
                        swanky_error!(ErrorKind::OtherError, "Not enough weights and biases")
                    })?;
                    let num_neurons = cfg
                        .get("units")
                        .ok_or_else(|| {
                            swanky_error!(
                                ErrorKind::OtherError,
                                "Config object must contain 'units' key",
                            )
                        })?
                        .as_u64()
                        .ok_or_else(|| {
                            swanky_error!(
                                ErrorKind::OtherError,
                                "Units value must be an unsigned integer",
                            )
                        })? as usize;
                    let mut weights = vec![Array3::from_elem(input_shape, Some(0)); num_neurons];

                    // Keras outputs the weights in the transposition of what we need.
                    let weights_data = weights_and_biases[0].as_array().ok_or_else(|| {
                        swanky_error!(ErrorKind::OtherError, "Weights value must be an array")
                    })?;
                    swanky_error::ensure!(
                        weights_data.len() == input_shape.0,
                        ErrorKind::OtherError,
                        "Weights length must equal input shape"
                    );

                    for (inp_num, data) in weights_data.iter().enumerate() {
                        for (neuron_num, val) in data
                            .as_array()
                            .ok_or_else(|| {
                                swanky_error!(
                                    ErrorKind::OtherError,
                                    "Weights value must be an array",
                                )
                            })?
                            .iter()
                            .map(|v| {
                                v.as_i64().ok_or_else(|| {
                                    swanky_error!(
                                        ErrorKind::OtherError,
                                        "Weight value must be an integer",
                                    )
                                })
                            })
                            .enumerate()
                        {
                            weights[neuron_num][(inp_num, 0, 0)] = Some(val?);
                        }
                    }

                    let biases = biases(&weights_and_biases[1])?;

                    let activation = activation(cfg)?;

                    layers.push(Layers::Dense(LayerDense {
                        weights,
                        biases,
                        activation,
                    }));
                }
                "Dropout" => continue,
                "Conv2D" => {
                    let pad = is_padding(cfg)?;

                    let weights_and_biases = weights_and_biases_iter.next().ok_or_else(|| {
                        swanky_error!(ErrorKind::OtherError, "Not enough weights and biases")
                    })?;

                    let kernel_size = cfg
                        .get("kernel_size")
                        .ok_or_else(|| {
                            swanky_error!(
                                ErrorKind::OtherError,
                                "Config object must contain 'kernel_size' key",
                            )
                        })?
                        .as_array()
                        .ok_or_else(|| {
                            swanky_error!(
                                ErrorKind::OtherError,
                                "Kernel size value must be an array",
                            )
                        })?
                        .iter()
                        .map(|v| {
                            v.as_u64().ok_or_else(|| {
                                swanky_error!(
                                    ErrorKind::OtherError,
                                    "Kernel size array value must be an unsigned integer",
                                )
                            })
                        })
                        .collect::<Result<Vec<_>>>()?;
                    swanky_error::ensure!(
                        kernel_size.len() >= 2,
                        ErrorKind::OtherError,
                        "Kernel size array must have at least two elements"
                    );
                    let kernel_shape = (
                        kernel_size[0] as usize,
                        kernel_size[1] as usize,
                        input_shape.2,
                    );

                    let stride = stride(cfg)?;

                    let weights = weights_and_biases[0]
                        .as_array()
                        .ok_or_else(|| {
                            swanky_error!(ErrorKind::OtherError, "Weights value must be an array")
                        })?
                        .iter()
                        .map(|x| {
                            x.as_array()
                                .ok_or_else(|| {
                                    swanky_error!(
                                        ErrorKind::OtherError,
                                        "Weights x-coordinate must be an array",
                                    )
                                })?
                                .iter()
                                .map(|y| {
                                    y.as_array()
                                        .ok_or_else(|| {
                                            swanky_error!(
                                                ErrorKind::OtherError,
                                                "Weights y-coordinate must be an array",
                                            )
                                        })?
                                        .iter()
                                        .map(|z| {
                                            z.as_array()
                                                .ok_or_else(|| {
                                                    swanky_error!(
                                                        ErrorKind::OtherError,
                                                        "Weights z-coordinate must be an array",
                                                    )
                                                })?
                                                .iter()
                                                .map(|v| {
                                                    v.as_i64().ok_or_else(|| {
                                                        swanky_error!(
                                                            ErrorKind::OtherError,
                                                            "Weight value must be an integer",
                                                        )
                                                    })
                                                })
                                                .collect::<Result<Vec<_>>>()
                                        })
                                        .collect::<Result<Vec<_>>>()
                                })
                                .collect::<Result<Vec<_>>>()
                        })
                        .collect::<Result<Vec<_>>>()?;

                    let nfilters = cfg
                        .get("filters")
                        .ok_or_else(|| {
                            swanky_error!(
                                ErrorKind::OtherError,
                                "Config object must contain 'filters' key",
                            )
                        })?
                        .as_u64()
                        .ok_or_else(|| {
                            swanky_error!(
                                ErrorKind::OtherError,
                                "Filters value must be an unsigned integer",
                            )
                        })? as usize;
                    let mut filters = vec![Array3::from_elem(kernel_shape, Some(0)); nfilters];
                    swanky_error::ensure!(
                        weights.len() == kernel_shape.0,
                        ErrorKind::OtherError,
                        "Weights length must equal kernel shape"
                    );

                    for (x, weights) in weights.into_iter().enumerate() {
                        swanky_error::ensure!(
                            weights.len() == kernel_shape.1,
                            ErrorKind::OtherError,
                            "Weights x-coordinate length must equal kernel shape"
                        );

                        for (y, weights) in weights.into_iter().enumerate() {
                            swanky_error::ensure!(
                                weights.len() == kernel_shape.2,
                                ErrorKind::OtherError,
                                "Weights y-coordinate length must equal kernel shape"
                            );

                            for (z, weights) in weights.into_iter().enumerate() {
                                swanky_error::ensure!(
                                    weights.len() == nfilters,
                                    ErrorKind::OtherError,
                                    "Weights z-coordinate length must equal the number of filters"
                                );

                                for (filter_num, val) in weights.into_iter().enumerate() {
                                    filters[filter_num][(x, y, z)] = Some(val);
                                }
                            }
                        }
                    }

                    let biases = biases(&weights_and_biases[1])?;
                    swanky_error::ensure!(
                        biases.len() == nfilters,
                        ErrorKind::OtherError,
                        "Biases length must equal the number of filters"
                    );

                    let activation = activation(cfg)?;

                    layers.push(Layers::Convolutional(LayerConvolutional {
                        filters,
                        biases,
                        input_shape,
                        kernel_shape,
                        stride,
                        activation,
                        pad,
                    }));
                }

                "MaxPooling2D" => {
                    let pad = is_padding(cfg)?;
                    let stride = stride(cfg)?;
                    let size = cfg["pool_size"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|v| v.as_i64().unwrap() as usize)
                        .collect::<Vec<_>>();
                    let size = (size[0], size[1]);

                    layers.push(Layers::MaxPooling2D(LayerMaxPooling2D {
                        input_shape,
                        stride,
                        size,
                        pad,
                    }));
                }
                "Flatten" => {
                    let (height, width, depth) = input_shape;

                    layers.push(Layers::Flatten(LayerFlatten {
                        input_shape,
                        output_shape: (height * width * depth, 1, 1),
                    }));
                }
                "Activation" => {
                    let activation = activation(cfg)?;

                    layers.push(Layers::Activation(LayerActivation {
                        activation,
                        shape: input_shape,
                    }));
                }
                name => {
                    swanky_error::bail!(ErrorKind::OtherError, "Invalid layer class name: {name}");
                }
            }
        }

        Ok(NeuralNet { layers })
    }

    /// Evaluate [`NeuralNet`] between a boolean [`Garbler`] and [`Evaluator`].
    ///
    /// # Panics
    /// This panics if `input.len() ≠ self.ninputs()`.
    pub fn eval_roundtrip_binary(
        &self,
        input: &Array3<i64>,
        bitwidths: &[usize],
        secret_weights: bool,
    ) -> Result<Vec<i64>> {
        assert_eq!(input.len(), self.ninputs());
        let (_, outputs) = swanky_channel::local::local_channel_pair(
            |channel| {
                let mut garbler: Garbler<_, alsz::Sender, WireMod2> =
                    Garbler::new(channel, SwankyRng::new())?;
                let mut nn = BinaryNeuralNet::new(&mut garbler, bitwidths, true);
                let inputs = nn.encode_input(input, channel)?;
                let outputs = nn.eval(self, &inputs, secret_weights, channel)?;
                let outputs = nn.decode_output(&outputs, channel)?;
                // The garbler receives no outputs.
                debug_assert_eq!(outputs, None);
                Ok(())
            },
            |channel| {
                let mut evaluator: Evaluator<SwankyRng, alsz::Receiver, WireMod2> =
                    Evaluator::new(channel, SwankyRng::new())?;
                let mut nn = BinaryNeuralNet::new(&mut evaluator, bitwidths, false);
                let inputs = nn.receive_input(input, channel)?;
                let outputs = nn.eval(self, &inputs, secret_weights, channel)?;
                let outputs = nn.decode_output(&outputs, channel)?;
                // The evaluator receives the outputs, so the `unwrap` should
                // never fail here.
                debug_assert!(outputs.is_some());
                Ok(outputs.unwrap())
            },
        )?;
        Ok(outputs)
    }

    /// Evaluate [`NeuralNet`] between an arithmetic [`Garbler`] and [`Evaluator`].
    ///
    /// # Panics
    /// This panics if `input.len() ≠ self.ninputs()`.
    pub fn eval_roundtrip_arith(
        &self,
        input: &Array3<i64>,
        moduli: &[u128],
        secret_weights: bool,
        accuracy: &Accuracy,
    ) -> Result<Vec<i64>> {
        assert_eq!(input.len(), self.ninputs());
        let (_, outputs) = swanky_channel::local::local_channel_pair(
            |channel| {
                let mut gb: Garbler<_, alsz::Sender, AllWire> =
                    Garbler::new(channel, SwankyRng::new())?;
                let mut nn = ArithmeticNeuralNet::new(&mut gb, moduli, true);
                let inps = nn.encode_input(input, channel)?;
                let outputs = nn.eval(self, &inps, secret_weights, accuracy, channel)?;
                let outputs = nn.decode_output(&outputs, channel)?;
                // The garbler receives no outputs.
                debug_assert_eq!(outputs, None);
                Ok(())
            },
            |channel| {
                let mut ev: Evaluator<SwankyRng, alsz::Receiver, AllWire> =
                    Evaluator::new(channel, SwankyRng::new())?;
                let mut nn = ArithmeticNeuralNet::new(&mut ev, moduli, true);
                let inps = nn.receive_input(input, channel)?;
                let outputs = nn.eval(self, &inps, secret_weights, accuracy, channel)?;
                let outputs = nn.decode_output(&outputs, channel)?;
                // The evaluator receives the outputs, so the `unwrap` should
                // never fail here.
                debug_assert!(outputs.is_some());
                Ok(outputs.unwrap())
            },
        )?;
        Ok(outputs)
    }

    /// Output a boolean garbling of [`NeuralNet`].
    pub fn gc_garble_boolean<W: BinaryWireLabel, RNG: CryptoRng + Rng>(
        &self,
        bitwidths: &[usize],
        secret_weights: bool,
        rng: RNG,
    ) -> Result<(InputEncoder<W>, GarbledCircuit, OutputMap)> {
        let mut channel = GarbledChannel::new_writer(None);
        let (inputs, outputs, delta) = Channel::with(&mut channel, |channel| {
            let mut garbler = fancy_garbling::Garbler::<_, W>::new(rng, channel)?;

            // Construct the zero wires for the input.
            let inputs = (0..self.ninputs())
                .map(|_| {
                    let zeros = (0..bitwidths[0])
                        .map(|_| garbler.encode_zero(2))
                        .collect::<Vec<_>>();
                    BinaryBundle::new(zeros)
                })
                .collect::<Vec<_>>();

            let mut nn = BinaryNeuralNet::new(&mut garbler, bitwidths, true);
            let outputs = nn.eval(self, &inputs, secret_weights, channel)?;

            let delta = garbler.delta(2);
            Ok((inputs, outputs, delta))
        })?;
        let encoder = InputEncoder::new(inputs, delta);
        let gc = GarbledCircuit::new(channel.finish_writing());
        let output_map = OutputMap::new(&outputs, delta);
        Ok((encoder, gc, output_map))
    }

    /// Evaluate a boolean garbling of [`NeuralNet`].
    ///
    /// The inputs are provided as (bundles of) wirelabels, and the output is a
    /// vector of (bundles of) wirelabels corresponding to the output.
    pub fn gc_eval_boolean<W: BinaryWireLabel>(
        &self,
        inputs: &[BinaryBundle<W>],
        gc: &GarbledCircuit,
        bitwidth: &[usize],
        secret_weights: bool,
    ) -> Result<Vec<BinaryBundle<W>>> {
        // Evaluate the garbled circuit on the input wirelabels.
        Channel::with(GarbledChannel::from(gc), |channel| {
            let mut evaluator = fancy_garbling::Evaluator::<W>::new(channel)?;
            let mut nn = BinaryNeuralNet::new(&mut evaluator, bitwidth, false);
            nn.eval(self, inputs, secret_weights, channel)
        })
    }

    // TODO: The `*_accuracy_test` methods have _a lot_ of commonalities. Can we
    // combine them in some way?

    /// Evaluate the [`NeuralNet`] over all the provided boolean inputs and
    /// track the accuracy of the evaluations.
    pub fn boolean_accuracy_test<W, F>(
        &self,
        f: &mut F,
        images: &[Array3<i64>],
        labels: &[Vec<i64>],
        bitwidth: &[usize],
        secret_weights: bool,
        channel: &mut Channel,
    ) -> Result<()>
    where
        W: Clone + HasModulus,
        F: FancyBinary + BinaryGadgets,
    {
        let mut errors = 0;

        let total_time = Instant::now();

        for (img_num, img) in images.iter().enumerate() {
            println!(
                "(avg {:.2?}) [{} errors ({:.2}%)] ",
                if img_num > 0 {
                    total_time.elapsed() / img_num as u32
                } else {
                    Duration::ZERO
                },
                errors,
                100.0 * (1.0 - errors as f32 / img_num as f32)
            );
            let mut nn = BinaryNeuralNet::new(f, bitwidth, true);
            let inp = nn.encode_input(img, channel)?;
            let outs = nn.eval(self, &inp, secret_weights, channel)?;
            let res = nn.decode_output(&outs, channel)?.unwrap();

            if util::index_of_max(&res) != util::index_of_max(&labels[img_num]) {
                errors += 1;
            }
        }

        println!(
            "errors: {}/{}. accuracy: {:.2}%",
            errors,
            images.len(),
            100.0 * (1.0 - errors as f32 / images.len() as f32)
        );
        Ok(())
    }

    /// Evaluate the [`NeuralNet`] over all the provided arithmetic inputs and
    /// track the accuracy of the evaluations.
    #[allow(clippy::too_many_arguments)]
    pub fn arith_accuracy_test<W, F>(
        &self,
        f: &mut F,
        images: &[Array3<i64>],
        labels: &[Vec<i64>],
        bitwidth: &[usize],
        secret_weights: bool,
        accuracy: &Accuracy,
        channel: &mut Channel,
    ) -> Result<()>
    where
        W: Clone + HasModulus,
        F: FancyBinary + FancyArithmetic + FancyProj + CrtGadgets,
    {
        let moduli = util::bitwidths_to_moduli(bitwidth);

        let mut errors = 0;
        let total_time = Instant::now();

        for (img_num, img) in images.iter().enumerate() {
            println!(
                "(avg {:?}) [{} errors ({:.2}%)] ",
                if img_num > 0 {
                    total_time.elapsed() / img_num as u32
                } else {
                    Duration::ZERO
                },
                errors,
                100.0 * (1.0 - errors as f32 / img_num as f32)
            );
            let mut nn = ArithmeticNeuralNet::new(f, &moduli, true);
            let inp = nn.encode_input(img, channel)?;
            let outs = nn.eval(self, &inp, secret_weights, accuracy, channel)?;
            let res = nn.decode_output(&outs, channel)?.unwrap();

            if util::index_of_max(&res) != util::index_of_max(&labels[img_num]) {
                errors += 1;
            }
        }

        println!(
            "errors: {}/{}. accuracy: {:.2}%",
            errors,
            images.len(),
            100.0 * (1.0 - errors as f32 / images.len() as f32)
        );
        Ok(())
    }

    /// Evaluate the [`NeuralNet`] in plaintext.
    pub fn plaintext_accuracy_test(
        &self,
        inputs: &[Array3<i64>],
        labels: &[Vec<i64>],
    ) -> Result<()> {
        let mut errors = 0;
        let total_time = Instant::now();

        for (img_num, (img, label)) in inputs.iter().zip(labels.iter()).enumerate() {
            println!(
                "(avg {:.2?}) [{} errors ({:.2}%)] ",
                if img_num > 0 {
                    total_time.elapsed() / img_num as u32
                } else {
                    Duration::ZERO
                },
                errors,
                100.0 * (1.0 - errors as f32 / img_num as f32)
            );
            let res = plaintext::eval(self, img)?.into_iter().collect::<Vec<_>>();

            if util::index_of_max(&res) != util::index_of_max(label) {
                errors += 1;
            }
        }

        println!(
            "errors: {}/{}. accuracy: {}%\n",
            errors,
            inputs.len(),
            100.0 * (1.0 - errors as f32 / inputs.len() as f32)
        );

        Ok(())
    }

    /// Run [`CircuitAnalyzer`] in binary mode.
    pub fn analyze_binary(&self, bitwidths: &[usize], secret_weights: bool) -> Result<()> {
        let mut analyzer = CircuitAnalyzer::new();

        Channel::with(std::io::empty(), |channel| {
            let inps = (0..self.ninputs())
                .map(|_| analyzer.bin_receive(bitwidths[0], channel))
                .collect::<Result<Vec<_>>>()?;

            let mut nn = BinaryNeuralNet::new(&mut analyzer, bitwidths, true);
            nn.eval(self, &inps, secret_weights, channel)
        })?;
        println!("{analyzer}");
        Ok(())
    }

    /// Run [`CircuitAnalyzer`] in arithmetic mode.
    pub fn analyze_arith(
        &self,
        moduli: &[u128],
        secret_weights: bool,
        accuracy: &Accuracy,
    ) -> Result<()> {
        let mut analyzer = CircuitAnalyzer::new();

        Channel::with(std::io::empty(), |channel| {
            let inps = (0..self.ninputs())
                .map(|_| analyzer.crt_receive(moduli[0], channel))
                .collect::<Result<Vec<_>>>()?;
            let mut nn = ArithmeticNeuralNet::new(&mut analyzer, moduli, true);
            nn.eval(self, &inps, secret_weights, accuracy, channel)
        })?;
        println!("{analyzer}");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(non_upper_case_globals)]
    #![allow(non_snake_case)]

    use crate::{Accuracy, NeuralNet, io::read_tests, neural_net::plaintext, util};
    use fancy_garbling::WireMod2;
    use ndarray::Array3;
    use std::path::Path;
    use swanky_rng::SwankyRng;

    static DINN_30_DIR: &str = "neural_nets/DINN_30";
    static DINN_30_Bitwidths: [usize; 3] = [9; 3];
    static DINN_100_DIR: &str = "neural_nets/DINN_100";
    static DINN_100_Bitwidths: [usize; 3] = [9; 3];
    static CryptoNets_DIR: &str = "neural_nets/CryptoNets";
    static CryptoNets_Bitwidths: [usize; 11] = [26; 11];
    static DeepSecure_DIR: &str = "neural_nets/DeepSecure";
    static DeepSecure_Bitwidths: [usize; 5] = [24; 5];
    static MiniONN_MNIST: &str = "neural_nets/MiniONN_MNIST";
    static MiniONN_MNIST_Bitwidths: [usize; 8] = [21; 8];

    fn get_nn_and_test(dir: &Path) -> (NeuralNet, Array3<i64>) {
        // Set the base path to `$CARGO_MANIFEST_DIR` for CI.
        let base = env!("CARGO_MANIFEST_DIR");
        let dir = Path::new(base).join(dir);
        let nn = NeuralNet::from_dir(&dir).unwrap();
        let tests = read_tests(&dir, Some(1)).unwrap();
        (nn, tests[0].clone())
    }

    fn binary_and_plaintext_match_for_dir(dir: &Path, bitwidths: &[usize]) {
        let (nn, test) = get_nn_and_test(dir);
        let plaintext_output = plaintext::eval(&nn, &test).unwrap();

        let gc_output = nn.eval_roundtrip_binary(&test, bitwidths, false).unwrap();
        for (a, b) in plaintext_output.iter().zip(gc_output.iter()) {
            assert_eq!(a, b);
        }
    }

    fn arithmetic_and_plaintext_match_for_dir(dir: &Path, moduli: &[u128]) {
        let (nn, test) = get_nn_and_test(dir);
        let accuracy = Accuracy {
            relu: "100%".to_string(),
            sign: "100%".to_string(),
            max: "100%".to_string(),
        };

        println!("{nn:?}");

        let plaintext_output = plaintext::eval(&nn, &test).unwrap();
        let gc_output = nn
            .eval_roundtrip_arith(&test, moduli, false, &accuracy)
            .unwrap();
        for (a, b) in plaintext_output.iter().zip(gc_output.iter()) {
            assert_eq!(a, b);
        }
    }

    fn garbling_works_for_model(dir: &str, bitwidths: &[usize]) {
        let (nn, test) = get_nn_and_test(Path::new(dir));
        let (encoder, gc, output_map) = nn
            .gc_garble_boolean::<WireMod2, _>(bitwidths, false, SwankyRng::new())
            .unwrap();
        // Extract the wirelabels associated with our input of interest.
        let inputs = encoder.encode_inputs(&test, bitwidths[0]);
        // Evaluate the garbled circuit.
        let outputs = nn
            .gc_eval_boolean::<WireMod2>(&inputs, &gc, bitwidths, false)
            .unwrap();
        // Map the output wirelabels to values.
        let output = output_map.to_outputs(&outputs).unwrap();

        let expected = plaintext::eval(&nn, &test).unwrap();
        for (a, b) in expected.iter().zip(output.iter()) {
            assert_eq!(a, b);
        }
    }

    #[test]
    fn garbling_works_for_DINN_30() {
        garbling_works_for_model(DINN_30_DIR, &DINN_30_Bitwidths);
    }

    #[test]
    #[ignore = "Slow"]
    fn garbling_works_for_DINN_100() {
        garbling_works_for_model(DINN_100_DIR, &DINN_100_Bitwidths)
    }

    #[test]
    fn binary_and_plaintext_match_for_DINN_30() {
        binary_and_plaintext_match_for_dir(Path::new(DINN_30_DIR), &DINN_30_Bitwidths);
    }

    #[test]
    fn arithmetic_and_plaintext_match_for_DINN_30() {
        let moduli = util::bitwidths_to_moduli(&DINN_30_Bitwidths);
        arithmetic_and_plaintext_match_for_dir(Path::new(DINN_30_DIR), &moduli);
    }

    #[test]
    #[ignore = "Slow"]
    fn binary_and_plaintext_match_for_DINN_100() {
        binary_and_plaintext_match_for_dir(Path::new(DINN_100_DIR), &DINN_100_Bitwidths);
    }

    #[test]
    #[ignore = "Slow"]
    fn arithmetic_and_plaintext_match_for_DINN_100() {
        let moduli = util::bitwidths_to_moduli(&DINN_100_Bitwidths);
        arithmetic_and_plaintext_match_for_dir(Path::new(DINN_100_DIR), &moduli);
    }

    #[test]
    #[ignore = "Slow"]
    fn binary_and_plaintext_match_for_CryptoNets() {
        binary_and_plaintext_match_for_dir(Path::new(CryptoNets_DIR), &CryptoNets_Bitwidths);
    }

    #[test]
    #[ignore = "Slow"]
    fn arithmetic_and_plaintext_match_for_CryptoNets() {
        let moduli = util::bitwidths_to_moduli(&CryptoNets_Bitwidths);
        arithmetic_and_plaintext_match_for_dir(Path::new(CryptoNets_DIR), &moduli);
    }

    #[test]
    #[ignore = "Slow"]
    fn binary_and_plaintext_match_for_DeepSecure() {
        binary_and_plaintext_match_for_dir(Path::new(DeepSecure_DIR), &DeepSecure_Bitwidths);
    }

    #[test]
    #[ignore = "Slow"]
    fn arithmetic_and_plaintext_match_for_DeepSecure() {
        let moduli = util::bitwidths_to_moduli(&DeepSecure_Bitwidths);
        arithmetic_and_plaintext_match_for_dir(Path::new(DeepSecure_DIR), &moduli);
    }

    // This one almost certainly will take too long.
    // #[test]
    // fn binary_and_plaintext_match_for_MiniONN_CIFAR() {
    //     binary_and_plaintext_match_for_dir(Path::new("neural_nets/MiniONN_CIFAR"), &[...]);
    // }

    #[test]
    #[ignore = "Slow"]
    fn binary_and_plaintext_match_for_MiniONN_MNIST() {
        binary_and_plaintext_match_for_dir(Path::new(MiniONN_MNIST), &MiniONN_MNIST_Bitwidths);
    }

    // This one fails, need to debug!
    // #[test]
    // fn binary_and_plaintext_match_for_SecureML() {
    //     binary_and_plaintext_match_for_dir(Path::new("neural_nets/SecureML"), &[22; 11]);
    // }
}
