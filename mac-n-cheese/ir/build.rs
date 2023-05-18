fn main() {
    swanky_flatbuffer_build::compile_flatbuffer(
        "src/compilation_format.fbs",
        "src/compilation_format_generated.rs",
    );
}
