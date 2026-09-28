fn main() {
    swanky_flatbuffer_build::compile_flatbuffer("src/sieve_ir.fbs", "src/sieve_ir_generated.rs");
}
