fn main() {
    swanky_flatbuffer_build::compile_flatbuffer(
        "src/sieveir_phase2/sieve_ir.fbs",
        "src/sieveir_phase2/sieve_ir_generated.rs",
    );
}
