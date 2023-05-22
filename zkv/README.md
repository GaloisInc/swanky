# `zkv`: Zero knowledge proofs for verilog files generated using `saw` / `abc`

`zkv` is a tool for generating zero knowledge proofs of Cryptol functions.
The `zkv` tool itself provides a command line interface for generating proofs that
a Bristol Fashion circuit on a secret input equals a public output.

## `zkv` explained through an example

The best way to play with `zkv` is through the `zkv` binary, runnable
as follows:
> cargo run --release

Let's create a proof that the prover knows an input such that the `sha256.txt`
Bristol Fashion circuit outputs some fixed string.

First, download the `sha256.txt` file by running:
> wget https://homes.esat.kuleuven.be/\~nsmart/MPC/sha256.txt

First, we want to know what that "fixed string" should be. `zkv` implements an
"evaluator" that can evaluate any Bristol Fashion circuit, outputting the
result. So let's run this evaluator on the all-zeros input:
> cargo run --release -- evaluator sha256.txt $(python -c "print('0' * 768)")

This'll output the string
`0110010111100111110100001111110100110011011001000111111001110101111100001011011011001000000110011000101100101110101001110110110111100111010100000100000001000011111101001011101100101010011100110001010111011100001110100100001000101000011010001010010100111110`.

Okay, now we want to build a proof that the prover knows an input (in this case
the all-zeros input) that equals the above string. We can do this as follows
> cargo run --release -- prover sha256.txt $(python -c "print('0' * 768)") 0110010111100111110100001111110100110011011001000111111001110101111100001011011011001000000110011000101100101110101001110110110111100111010100000100000001000011111101001011101100101010011100110001010111011100001110100100001000101000011010001010010100111110 proof

The first argument to `prover` is the Bristol Fashion circuit to read in (in
this case, `sha256.txt`), the second argument is the witness (in this case, the
all-zeros string), and the last argument denotes the location to store the
resulting proof.

The resulting file, `proof`, is our non-interactive zero-knowledge proof of the
statement: "I know an input for sha256 such that the output is `0110010...`".

Now, let's verify this proof.
> cargo run --release -- verifier sha256.txt proof 0110010111100111110100001111110100110011011001000111111001110101111100001011011011001000000110011000101100101110101001110110110111100111010100000100000001000011111101001011101100101010011100110001010111011100001110100100001000101000011010001010010100111110

The first argument is, again, the Bristol Fashion circuit to read in, the second
argument is the proof to use, and the third argument is the value we are
checking equality against.

When run, we get the expected result: `Verification succeeded!` Nice!

Now, let's try verifying the "wrong" equality string:
> cargo run --release -- verifier sha256.txt proof 0110010111100111110100001111110100110011011001000111111001110101111100001011011011001000000110011000101100101110101001110110110111100111010100000100000001000011111101001011101100101010011100110001010111011100001110100100001000101000011010001010010100111111

This is the same as the successful run, except the last bit has been changed
from `0` to `1`. We can see here that verification failed.

If you'd like more detail in any of these executions, you can use the
`--logging` flag to print logging information.

## Creating Bristol Fashion files from Cryptol functions

Here we describe the steps to convert a Cryptol source to a Bristol Fashion
circuit using `saw` and `abc`. The process uses `saw` to convert a Cryptol
function to "AIG" format, which is then fed into the `abc` tool to produce
verilog output. Finally, this verilog output is fed into a custom python script
to produce the final Bristol Fashion file. We describe these steps in more
detail below.

1. In `saw`, run the following:
```
import "CryptolFileToImport.cry"
write_aig "circuit.aig" {{ CryptolFunction }}
```
Here, `CryptolFileToImport.cry` is the Cryptol source file to use and
`CryptoFunction` is the function we'd like to covert to AIG format.
This produces an output AIG formatted file `circuit.aig`.

2. Using the `circuit.genlib` file, run the following:
```
abc -c "read_library circuit.genlib; read circuit.aig; amap -m; write_verilog circuit.v"
```
This produces an output verilog file `circuit.v`.

3. Finally, use the `vg2bf.py` tool to convert the Verilog file
to a Bristol Fashion file:
```
./vg2bf.py circuit.v circuit.bf
```
This produces an output Bristol Fashion file `circuit.bf`.

Note that number of input/output wires per value is not expressed in the Cryptol
file. These parameters may be expressed in the Verilog file by manually adding a
`localparam vg2bf_input_wpv = "<list>";` statement after the `inputs ...;`
statement and a `localparam vg2bf_output_wpv = "<list>";` statement after the
`outputs ...;` statement. The `<list>` contains comma-separated integers which
must sum to the total number of inputs or outputs.

### Concrete example

Here's a concrete instance using example code from `saw`.

In `saw`:
```
> import "./examples/zuc/zuc.cry"
> write_aig "./foo.aig" {{ mulpow }}
```

In a shell:
```
$ abc -c "read_library circuit.genlib; read foo.aig; amap -m; write_verilog foo.v"
$ ./vg2bf.py foo.v foo.bf
```
