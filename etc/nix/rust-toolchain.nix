with import ./pkgs.nix { };
# We strip the whitespace from the rust-toolchain file.
let
  rust-toolchain-version = builtins.head (builtins.match "([^\r\n]+)[\r\n]*" (builtins.readFile ../../rust-toolchain));
  rust = rust-bin.fromRustupToolchain {
    channel = rust-toolchain-version;
    components = [
      "rustfmt"
      "llvm-tools-preview"
      "clippy"
    ];
  };
in
runCommand "rust-${rust-toolchain-version}" { } ''
  mkdir -p "$out/bin"
  for bin in "${rust}/bin/"*; do
      ln -s "$bin" "$out/bin/"
  done
''
