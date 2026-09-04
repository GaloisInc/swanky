# Garbled neural networks using `fancy-garbling`

This crate contains an implementation of convolutional neural networks using
boolean garbled circuits.

The high-level idea is that we use JSON output of `tensorflow` models to build
neural network layers as a garbled circuit. The `Garbler` either hard codes the
weights and biases as public values or as secret garbler input wires, depending
on how the circuit is configured. Public weights are much, much cheaper to run.
Finally, the `Evaluator` receives the garbled circuit from the `Garbler` and
evaluates it using the test input - in our examples this is always an image.

The `neural_nets` directory contains the trained neural networks we used in the
paper. To run an experiment, point the binary rust program to the directory you
want and give it a command on what kind of test you would like to run.

Generally, the `Garbler` does not know how large to make the integers. Integers
must be large enough to avoid overflow. But the smaller they are, the better the
performance. Therefore, we have the `bitwidth` command to run on a particular
neural network. This will evaluate the neural network on all the test data and
return the maximum bitwidth necessary for each layer. You can then use this
information to customize the bitwidth for each layer when using other commands
(using the `-w` argument).

## Usage
We provide both a library exposing the underlying `NeuralNet` type for garbling
and evaluating neural networks, alongside an executable for running various
tests and benchmarking. See `cargo run --release -- help` for documentation on
the executable, and the standard `swanky` docs for documentation on the library.

### Example: Benchmark a neural network
```shell
> cargo run --release -- neural_nets/DINN_30 bench
```

## Acknowledgments
This library was originally written by Brent Carmer and available at
https://github.com/GaloisInc/garbled-neural-network-experiments. It has since
been moved into `swanky` by the `swanky` development team.
