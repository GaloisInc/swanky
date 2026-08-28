mod test {
    use fancy_circuits::{
        BinaryBundle,
        aes::AesNonExpanded,
        binary::BinaryAddition,
        hmac::HmacSha256,
        sha::{Sha256, Sha256CompressionFunction},
    };
    use fancy_traits::{
        Circuit as FancyCircuit, FancyBinary, FancyBinaryConstant, FancyZeroKnowledge,
    };
    use merlin::Transcript;
    use rand::rng;
    use schmivitz::{
        Proof,
        circuit::{Circuit, load_circuit_from_strings_prover},
        proof::{test_circuit, test_sieveir},
        vole::functionality::{VoleProver, VoleVerifier},
    };
    use std::{sync::Once, time::Instant};
    use swanky_channel::Channel;
    use swanky_error::Result;
    use swanky_field::FiniteRing;
    use swanky_field_binary::F2;
    use swanky_sieve_ir_codegen::compile_sieve_ir_str;

    static DO_LOGGING: bool = false;
    static INIT: Once = Once::new();

    fn init_logger() {
        INIT.call_once(|| {
            let _ =
                env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
                    .try_init();
        });
    }

    // Get a fresh transcript
    fn transcript() -> Transcript {
        Transcript::new(b"basic happy test transcript")
    }

    // Create a proof for the given circuit and input.
    fn create_proof(
        circuit_bytes: &'static str,
        private_input_bytes: &'static str,
    ) -> (Result<Proof<VoleProver, VoleVerifier>>, Circuit) {
        let circuit = load_circuit_from_strings_prover(circuit_bytes, private_input_bytes).unwrap();

        let rng = &mut rng();

        let t = std::time::Instant::now();
        let t1 = Proof::prove_with_circuit::<_>(&circuit, &mut transcript(), rng);
        log::info!("proof time: {:?}", t.elapsed());
        (t1, circuit)
    }

    #[test]
    fn prove_doesnt_explode() -> Result<()> {
        let mini_circuit_bytes = "version 2.0.0;
        circuit;
        @type field 2;
        @begin
          $0 <- @private(0);
          $1 <- @mul(0: $0, $0);
          $2 <- @add(0: $0, $0);
        @end ";
        let private_input_bytes = "version 2.0.0;
        private_input;
        @type field 2;
        @begin
            < 1 >;
        @end";

        let (proof, mini_circuit) = create_proof(mini_circuit_bytes, private_input_bytes);
        let verif = proof?.verify_with_circuit(&mini_circuit, &mut transcript());
        assert!(verif.is_ok());

        Ok(())
    }

    compile_sieve_ir_str!(
        DoesntExplode,
        "version 2.0.0;
        circuit;
        @type field 2;
        @begin
          $0 <- @private(0);
          $1 <- @mul(0: $0, $0);
          $2 <- @add(0: $0, $0);
        @end
    "
    );

    #[test]
    fn prove_sieveir_codegen() -> Result<()> {
        let mini_circuit_bytes = "version 2.0.0;
        circuit;
        @type field 2;
        @begin
          $0 <- @private(0);
          $1 <- @mul(0: $0, $0);
          $2 <- @add(0: $0, $0);
        @end ";
        let private_input_bytes = "version 2.0.0;
        private_input;
        @type field 2;
        @begin
            < 1 >;
        @end";

        let (proof, mini_circuit) = create_proof(mini_circuit_bytes, private_input_bytes);
        let proof = proof.unwrap();
        let verif = proof.verify_with_circuit(&mini_circuit, &mut transcript());
        assert!(verif.is_ok());

        // Verify the dynamic circuit with the compiled circuit.
        let verif = proof.verify(&DoesntExplode, &mut transcript());
        assert!(verif.is_ok());

        // Verify the compiled circuit with the dynamic circuit.
        let rng = &mut rng();
        let proof = Proof::<VoleProver, VoleVerifier>::prove(
            &DoesntExplode,
            &mini_circuit.private_inputs,
            None,
            &mut transcript(),
            rng,
        )
        .unwrap();
        let verif = proof.verify_with_circuit(&mini_circuit, &mut transcript());
        assert!(verif.is_ok());

        Ok(())
    }

    compile_sieve_ir_str!(
        AssertZero,
        "version 2.0.0;
        circuit;
        @type field 2;
        @begin
          $0 <- @private(0);
          $1 <- @add(0: $0, $0);
          @assert_zero(0: $0);
          @assert_zero(0: $1);
        @end
    "
    );

    #[test]
    fn prove_sieveir_assert_zero() -> Result<()> {
        let mini_circuit_bytes = "version 2.0.0;
        circuit;
        @type field 2;
        @begin
          $0 <- @private(0);
          $1 <- @add(0: $0, $0);
          @assert_zero(0: $0);
          @assert_zero(0: $1);
        @end ";
        let private_input_bytes = "version 2.0.0;
        private_input;
        @type field 2;
        @begin
            < 0 >;
        @end";

        let (proof, mini_circuit) = create_proof(mini_circuit_bytes, private_input_bytes);
        let proof = proof.unwrap();
        let verif = proof.verify_with_circuit(&mini_circuit, &mut transcript());
        assert!(verif.is_ok());

        // Verify the dynamic circuit with the compiled circuit.
        let verif = proof.verify(&AssertZero, &mut transcript());
        assert!(verif.is_ok());

        let rng = &mut rng();
        let proof = Proof::<VoleProver, VoleVerifier>::prove(
            &AssertZero,
            &mini_circuit.private_inputs,
            None,
            &mut transcript(),
            rng,
        )
        .unwrap();
        let verif = proof.verify_with_circuit(&mini_circuit, &mut transcript());
        assert!(verif.is_ok());

        Ok(())
    }

    struct TestAssertZero;

    impl<F: FancyBinary + FancyBinaryConstant + FancyZeroKnowledge> FancyCircuit<F> for TestAssertZero {
        type Input = ();
        type Output = Vec<F::Item>; // TODO: should be `()`

        fn execute(
            &self,
            backend: &mut F,
            _: Self::Input,
            channel: &mut Channel,
        ) -> Result<Self::Output> {
            let x = backend.receive(2, channel)?;
            backend.assert_zero(&x, channel)?;
            let y = backend.xor(&x, &x);
            backend.assert_zero(&y, channel)?;
            let one = backend.constant(F2::ONE);
            let y = backend.xor(&x, &one);
            let z = backend.xor(&y, &one);
            backend.assert_zero(&z, channel)?;
            Ok(vec![])
        }
    }

    #[test]
    fn prove_circuit_assert_zero() -> Result<()> {
        let private_input = [F2::ZERO; 1];
        test_circuit(&TestAssertZero, &private_input)
    }

    #[test]
    fn prove_sieveir_assert_zero_interleaved() -> Result<()> {
        let mini_circuit_bytes = "version 2.0.0;
        circuit;
        @type field 2;
        @begin
          $0 <- @private(0);
          $1 <- @add(0: $0, $0);
          @assert_zero(0: $0);
          $2 <- @private(0);
          $3 <- @mul(0: $1, $2);
          @assert_zero(0: $3);
        @end ";
        let private_input_bytes = "version 2.0.0;
        private_input;
        @type field 2;
        @begin
            < 0 >;
            < 1 >;
        @end";

        let (proof, mini_circuit) = create_proof(mini_circuit_bytes, private_input_bytes);
        let proof = proof.unwrap();
        let verif = proof.verify_with_circuit(&mini_circuit, &mut transcript());
        assert!(verif.is_ok());

        Ok(())
    }

    #[test]
    fn prove_sieveir_assert_zero_interleaved_fail() -> Result<()> {
        let mini_circuit_bytes = "version 2.0.0;
        circuit;
        @type field 2;
        @begin
          $0 <- @private(0);
          $1 <- @add(0: $0, $0);
          @assert_zero(0: $0);
          $2 <- @private(0);
          $3 <- @mul(0: $1, $2);
          @assert_zero(0: $3);
        @end ";
        let private_input_bytes = "version 2.0.0;
        private_input;
        @type field 2;
        @begin
            < 1 >;
            < 1 >;
        @end";

        let (proof, mini_circuit) = create_proof(mini_circuit_bytes, private_input_bytes);
        let proof = proof.unwrap();
        let verif = proof.verify_with_circuit(&mini_circuit, &mut transcript());
        assert!(verif.is_err());

        Ok(())
    }

    #[test]
    fn prove_addc_doesnt_explode() -> Result<()> {
        let mini_circuit_bytes = "version 2.0.0;
        circuit;
        @type field 2;
        @begin
          $0 <- @private(0);
          $1 <- @mul(0: $0, $0);
          $2 <- @add(0: $0, $0);
          $3 <- @addc(0: $0, < 1 >);
          $4 <- @private(0);
          $5 <- @mul(0: $3, $4);
          $6 <- @addc(0: $5, < 1 >);
        @end ";
        let private_input_bytes = "version 2.0.0;
        private_input;
        @type field 2;
        @begin
            < 1 >;
            < 1 >;
        @end ";

        let (proof, mini_circuit) = create_proof(mini_circuit_bytes, private_input_bytes);
        let verif = proof?.verify_with_circuit(&mini_circuit, &mut transcript());
        assert!(verif.is_ok());

        Ok(())
    }

    const SMALL_CIRCUIT: &str = "version 2.0.0;
    circuit;
    @type field 2;
    @begin
      $0 ... $4 <- @private(0);
      $5 <- @add(0: $0, $0);
      $6 <- @add(0: $0, $1);
      $7 <- @add(0: $0, $2);
      $8 <- @add(0: $0, $3);
      $9 <- @add(0: $0, $4);
      $10 <- @mul(0: $0, $5);
      $11 <- @mul(0: $0, $6);
      $12 <- @mul(0: $0, $7);
      $13 <- @mul(0: $0, $8);
      $14 <- @mul(0: $0, $9);
    @end ";

    #[test]
    fn prove_works_on_slightly_larger_circuit() -> Result<()> {
        let private_input_bytes = "version 2.0.0;
        private_input;
        @type field 2;
        @begin
            < 1 >;
            < 1 >;
            < 1 >;
            < 0 >;
            < 0 >;
        @end ";

        let (proof, small_circuit) = create_proof(SMALL_CIRCUIT, private_input_bytes);
        assert!(
            proof?
                .verify_with_circuit(&small_circuit, &mut transcript())
                .is_ok()
        );

        Ok(())
    }

    struct TestBinaryAddition<'a>(BinaryAddition<'a>, &'static str);

    impl<'a, F: FancyBinary + FancyZeroKnowledge> FancyCircuit<F> for TestBinaryAddition<'a> {
        type Input = ();
        type Output = Vec<F::Item>; // TODO: should be `()`

        fn execute(
            &self,
            backend: &mut F,
            _: Self::Input,
            channel: &mut Channel,
        ) -> Result<Self::Output> {
            let x = BinaryBundle::new(
                (0..8)
                    .map(|_| backend.receive(2, channel))
                    .collect::<Result<Vec<_>>>()?,
            );
            let y = BinaryBundle::new(
                (0..8)
                    .map(|_| backend.receive(2, channel))
                    .collect::<Result<Vec<_>>>()?,
            );
            let (z, carry) = self.0.execute(backend, (&x, &y), channel)?;
            for (wire, c) in z.wires().iter().zip(self.1.chars()) {
                match c {
                    '0' => backend.assert_zero(wire, channel)?,
                    '1' => {
                        let z = backend.negate(wire);
                        backend.assert_zero(&z, channel)?;
                    }
                    _ => panic!("Unexpected character in boolean string"),
                }
            }
            backend.assert_zero(&carry, channel)?;
            Ok(vec![])
        }
    }

    #[test]
    fn prove_binary_addition_circuit() -> Result<()> {
        let mut x = [F2::ZERO; 8];
        let mut y = [F2::ZERO; 8];
        // Test 1 + 1 = 2.
        x[0] = F2::ONE;
        y[0] = F2::ONE;
        test_circuit(
            &TestBinaryAddition(BinaryAddition::new(), "01000000"),
            &[x, y].concat(),
        )?;
        // Test 3 + 3 = 6.
        x[1] = F2::ONE;
        y[1] = F2::ONE;
        test_circuit(
            &TestBinaryAddition(BinaryAddition::new(), "01100000"),
            &[x, y].concat(),
        )
    }

    #[test]
    fn prove_aes256_sieveir() -> Result<()> {
        if DO_LOGGING {
            init_logger();
        }

        let circuit_bytes = include_str!("../circuits/aes_256_conv.sieve");
        let private_input_bytes = include_str!("../circuits/aes_256_conv_private.sieve");

        let t = std::time::Instant::now();
        let circuit = load_circuit_from_strings_prover(circuit_bytes, private_input_bytes).unwrap();
        log::info!("parsing: {:?}", t.elapsed());

        test_sieveir(&circuit)
    }

    struct TestAes(AesNonExpanded);

    impl<F: FancyBinary + FancyBinaryConstant + FancyZeroKnowledge> FancyCircuit<F> for TestAes {
        type Input = ();
        type Output = Vec<F::Item>; // TODO: should be `()`

        fn execute(
            &self,
            backend: &mut F,
            _: Self::Input,
            channel: &mut Channel,
        ) -> Result<Self::Output> {
            let key = (0..128)
                .map(|_| backend.receive(2, channel))
                .collect::<Result<Vec<_>>>()?
                .try_into()
                .unwrap();
            let block = (0..128)
                .map(|_| backend.receive(2, channel))
                .collect::<Result<Vec<_>>>()?
                .try_into()
                .unwrap();
            let output = self.0.execute(backend, (key, block), channel)?;
            let expected = "01100110111010010100101111010100111011111000101000101100001110111000100001001100111110100101100111001010001101000010101100101110";
            for (x, c) in output.iter().zip(expected.chars()) {
                match c {
                    '0' => backend.assert_zero(x, channel)?,
                    '1' => {
                        let y = backend.negate(x);
                        backend.assert_zero(&y, channel)?;
                    }
                    _ => panic!("Unexpected character in boolean string"),
                }
            }
            Ok(vec![])
        }
    }

    #[test]
    fn prove_aes_circuit() -> Result<()> {
        // if log-level `RUST_LOG` not already set, then set to info
        if DO_LOGGING {
            init_logger();
        }

        let circuit = TestAes(AesNonExpanded::new());

        let private_input = (0..256).map(|_| F2::ZERO).collect::<Vec<_>>();
        test_circuit(&circuit, &private_input)
    }

    #[test]
    fn prove_sha256_compression_fn_sieveir() -> Result<()> {
        // if log-level `RUST_LOG` not already set, then set to info
        if DO_LOGGING {
            init_logger();
        }
        let circuit_bytes = include_str!("../circuits/sha256_conv.sieve");
        let private_input_bytes = include_str!("../circuits/sha256_conv_private.sieve");

        let t = std::time::Instant::now();
        let circuit = load_circuit_from_strings_prover(circuit_bytes, private_input_bytes).unwrap();
        log::info!("parsing: {:?}", t.elapsed());

        test_sieveir(&circuit)
    }

    struct TestSha256CompressionFunction(Sha256CompressionFunction);

    impl<F: FancyBinary + FancyBinaryConstant + FancyZeroKnowledge> FancyCircuit<F>
        for TestSha256CompressionFunction
    {
        type Input = ();
        type Output = Vec<F::Item>; // TODO: should be `()`

        fn execute(
            &self,
            backend: &mut F,
            _: Self::Input,
            channel: &mut Channel,
        ) -> Result<Self::Output> {
            let block = (0..512)
                .map(|_| backend.receive(2, channel))
                .collect::<Result<Vec<_>>>()?
                .try_into()
                .unwrap();
            let chain = (0..256)
                .map(|_| backend.receive(2, channel))
                .collect::<Result<Vec<_>>>()?
                .try_into()
                .unwrap();
            let _ = self.0.execute(backend, (block, chain), channel)?;
            Ok(vec![])
        }
    }

    #[test]
    fn prove_sha256_compression_fn_circuit() -> Result<()> {
        // if log-level `RUST_LOG` not already set, then set to info
        if DO_LOGGING {
            init_logger();
        }

        let t = Instant::now();
        let circuit = TestSha256CompressionFunction(Sha256CompressionFunction::new());
        log::info!("parsing: {:?}", t.elapsed());

        let private_input = (0..768).map(|_| F2::ZERO).collect::<Vec<_>>();
        test_circuit(&circuit, &private_input)
    }

    struct TestSha256(Sha256);

    impl<F: FancyBinary + FancyBinaryConstant + FancyZeroKnowledge> FancyCircuit<F> for TestSha256 {
        type Input = ();
        type Output = Vec<F::Item>; // TODO: should be `()`

        fn execute(
            &self,
            backend: &mut F,
            _: Self::Input,
            channel: &mut Channel,
        ) -> Result<Self::Output> {
            let input = (0..512)
                .map(|_| backend.receive(2, channel))
                .collect::<Result<Vec<_>>>()?;
            let _ = self.0.execute(backend, input, channel)?;
            Ok(vec![])
        }
    }

    #[test]
    fn prove_sha256_circuit() -> Result<()> {
        // if log-level `RUST_LOG` not already set, then set to info
        if DO_LOGGING {
            init_logger();
        }

        let t = Instant::now();
        let circuit = TestSha256(Sha256::new());
        log::info!("parsing: {:?}", t.elapsed());

        let private_input = (0..512).map(|_| F2::ZERO).collect::<Vec<_>>();
        test_circuit(&circuit, &private_input)
    }

    struct TestHmac<'a>(HmacSha256<'a>);

    impl<'a, F: FancyBinary + FancyBinaryConstant + FancyZeroKnowledge> FancyCircuit<F>
        for TestHmac<'a>
    {
        type Input = ();
        type Output = Vec<F::Item>; // TODO: should be `()`

        fn execute(
            &self,
            backend: &mut F,
            _: Self::Input,
            channel: &mut Channel,
        ) -> Result<Self::Output> {
            let key = (0..512)
                .map(|_| backend.receive(2, channel))
                .collect::<Result<Vec<_>>>()?
                .try_into()
                .unwrap();
            let input = (0..32)
                .map(|_| backend.receive(2, channel))
                .collect::<Result<Vec<_>>>()?;
            let outputs = self.0.execute(backend, (&key, &input), channel)?;
            let expected = "0100001110110000110011101111100110010010011001011111100111100011010011000001000011101010100111010011010100000001100100100110110100100111101100111001111101010111110001101101011001110100010101100001110110001011101000100011011011100111101010000001100111111011";
            for (x, c) in outputs.iter().zip(expected.chars()) {
                match c {
                    '0' => backend.assert_zero(x, channel)?,
                    '1' => {
                        let y = backend.negate(x);
                        backend.assert_zero(&y, channel)?
                    }
                    _ => panic!("Unexpected character in boolean string"),
                };
            }
            Ok(vec![])
        }
    }

    #[test]
    fn prove_hmac_circuit() -> Result<()> {
        // if log-level `RUST_LOG` not already set, then set to info
        if DO_LOGGING {
            init_logger();
        }

        let t = Instant::now();
        let circuit = TestHmac(HmacSha256::new());
        log::info!("parsing: {:?}", t.elapsed());

        let key = (0..512).map(|_| F2::ZERO).collect::<Vec<_>>();
        let message = "01110100011001010111001101110100"
            .chars()
            .map(|c| match c {
                '0' => F2::ZERO,
                '1' => F2::ONE,
                _ => panic!("Unexpected character in boolean string"),
            })
            .collect();
        let private_input = [key, message].concat();

        test_circuit(&circuit, &private_input)
    }
}
