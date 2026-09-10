/*! Demo using dietmc as a library
This shows how to run a simple circuit using the library API.

 prover:
 ```
 cargo run --example dietmc_lib -- --prover
```
 verifier:
 ```
 cargo run --example dietmc_lib
 ```
 */

use std::env;
use std::io::{BufReader, BufWriter};
use std::net::{TcpListener, TcpStream};

use diet_mac_and_cheese::EvaluatorCirc;
use diet_mac_and_cheese::LpnSize;
use diet_mac_and_cheese::circuit_ir::{CircInputs, FunStore, GateM, TypeStore};
use diet_mac_and_cheese::party::{Prover, Verifier};
use diet_mac_and_cheese::svole_trait::Svole;
use swanky_channel_legacy::Channel;
use swanky_error::{ErrorKind, Result, WrapErr, bail};
use swanky_field::{FiniteField, FiniteRing};
use swanky_field_binary::{F2, F40b};
use swanky_field_f61p::F61p;
use swanky_rng::SwankyRng;
use swanky_sieve_ir_parser::Number;

fn field_to_number<F: FiniteField>(v: F) -> Number {
    // NOTE: We assume that `to_bytes()` converts a field value into a sequence of bytes in lower-endian.
    let bytes = v.to_bytes();
    assert!(bytes.len() <= Number::BYTES, "number too big",);
    let mut bigint_bytes = [0; Number::BYTES];
    bigint_bytes[..bytes.len()].copy_from_slice(bytes.as_slice());

    Number::from_le_slice(&bigint_bytes)
}

fn start_connection_verifier(addr: &String) -> Result<TcpStream> {
    let listener = TcpListener::bind(addr.clone())
        .wrap_err_with(ErrorKind::NetworkError, || {
            format!("Failed to bind listener to {addr}.")
        })?;
    match listener.accept() {
        Ok((stream, _addr)) => {
            println!("accept connections on {addr:?}");
            Ok(stream)
        }
        _ => {
            bail!(ErrorKind::NetworkError, "Error binding addr: {:?}", addr);
        }
    }
}

fn start_connection_prover(addr: &String) -> Result<TcpStream> {
    loop {
        let c = TcpStream::connect(addr.clone());
        if let Ok(stream) = c {
            println!("connection accepted on {addr:?}");
            return Ok(stream);
        }
    }
}

fn main() -> Result<()> {
    let addr = "127.0.0.1:8000";

    // If `--prover` is passed at the cli then it runs as the prover, otherwise as a verifier
    let args: Vec<String> = env::args().collect();
    let is_prover = args.iter().any(|x| x == "--prover");

    // Some configuration flags
    let lpn_size = LpnSize::Medium;
    let no_batching = false; // let's batch the various checks

    let ty = 0;
    let minus_one = field_to_number(-F61p::ONE);

    // Set of gates checking that two witnesses multiplies to an instance value
    let gates = vec![
        GateM::Witness(ty, (0, 0)),
        GateM::Witness(ty, (1, 1)),
        GateM::Instance(ty, (2, 2)),
        GateM::Mul(ty, 3, 0, 1),
        GateM::MulConstant(ty, 4, 2, Box::new(minus_one)),
        GateM::Add(ty, 5, 3, 4),
        GateM::AssertZero(ty, 5),
    ];

    let three = F61p::ONE + F61p::ONE + F61p::ONE;
    let seven = three + three + F61p::ONE;
    let twentyone = three * seven;

    let mut circ_inputs = CircInputs::default();
    let fun_store = FunStore::default();

    if !is_prover {
        // Verifier

        println!("Create communication channel");
        let stream = start_connection_verifier(&addr.to_string())?;
        let reader = BufReader::new(stream.try_clone().wrap_err(
            ErrorKind::NetworkError,
            "Failed to clone TCP stream for reader.",
        )?);
        let writer = BufWriter::new(stream);
        let mut channel = Channel::new(reader, writer);

        println!("ingest instances/witnesses");
        circ_inputs.ingest_instance(0, field_to_number(twentyone));

        println!("Create an evaluator");
        let mut evaluator =
            EvaluatorCirc::<Verifier, _, Svole<_, F2, F40b>, Svole<_, F40b, F40b>>::new(
                &mut channel,
                SwankyRng::new(),
                CircInputs::default(),
                TypeStore::default(),
                lpn_size,
                no_batching,
            )?;

        println!("Load the F61p backend");
        evaluator.load_backend(
            &mut channel,
            SwankyRng::new(),
            std::any::TypeId::of::<F61p>(),
            ty as usize,
            lpn_size,
        )?;

        println!("Evaluate gates with inputs");
        evaluator.evaluate_gates_with_inputs(&gates, &fun_store, &mut circ_inputs)?;

        println!("Finalize evaluator");
        evaluator.finish()?;

        println!("VERIFIER DONE!");
    } else {
        // Prover

        println!("Create communication channel");
        let stream = start_connection_prover(&addr.to_string())?;
        let reader = BufReader::new(stream.try_clone().wrap_err(
            ErrorKind::NetworkError,
            "Failed to clone TCP stream for reader.",
        )?);
        let writer = BufWriter::new(stream);
        let mut channel = Channel::new(reader, writer);

        println!("ingest instances/witnesses");
        circ_inputs.ingest_witness(ty as usize, field_to_number(three));
        circ_inputs.ingest_witness(ty as usize, field_to_number(seven));
        circ_inputs.ingest_instance(ty as usize, field_to_number(twentyone));

        println!("Create an evaluator");
        let mut evaluator =
            EvaluatorCirc::<Prover, _, Svole<_, F2, F40b>, Svole<_, F40b, F40b>>::new(
                &mut channel,
                SwankyRng::new(),
                CircInputs::default(),
                TypeStore::default(),
                lpn_size,
                no_batching,
            )?;

        println!("Load the F61p backend");
        evaluator.load_backend(
            &mut channel,
            SwankyRng::new(),
            std::any::TypeId::of::<F61p>(),
            ty as usize,
            lpn_size,
        )?;

        println!("Evaluate gates with inputs");
        evaluator.evaluate_gates_with_inputs(&gates, &fun_store, &mut circ_inputs)?;

        println!("Finalize evaluator");
        evaluator.finish()?;

        println!("PROVER DONE!");
    }

    Ok(())
}
