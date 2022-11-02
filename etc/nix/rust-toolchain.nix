with import ./pkgs.nix {};
# We strip the whitespace from the rust-toolchain file.
let rust-toolchain-version = builtins.head (builtins.match "([^\r\n]+)[\r\n]*" (builtins.readFile ../../rust-toolchain));
in
rust-bin.fromRustupToolchain {
  channel = rust-toolchain-version;
  components = [ "rustfmt" "llvm-tools-preview" ];
}
