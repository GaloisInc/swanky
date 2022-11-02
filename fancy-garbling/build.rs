use std::io::Result;

fn main() -> Result<()> {
    // https://github.com/tokio-rs/prost#using-prost-in-a-no_std-crate
    // "Additionally, configure prost-build to output BTreeMaps instead of HashMaps for all Protobuf map fields in your build.rs:"
    let mut config = prost_build::Config::new();
    config.btree_map(&["."]);
    // https://docs.rs/prost-build/0.7.0/prost_build/struct.Config.html#examples-1
    // "Match all bytes fields. Expecially useful in `no_std` contexts."
    config.bytes(&["."]);

    config.compile_protos(
        // list of protos
        &["deps/protos/skcd/skcd.proto"],
        // includes
        &["deps/protos"],
    )?;

    Ok(())
}
