with import ./pkgs.nix { };
let swankyLlvm = import ./llvm.nix;
in
(mkShell.override { stdenv = swankyLlvm.stdenv; }) {
  shellHook = ''
    export SSL_CERT_FILE="${cacert}/etc/ssl/certs/ca-bundle.crt"
    export NIX_SSL_CERT_FILE="${cacert}/etc/ssl/certs/ca-bundle.crt"
  '';
  buildInputs = [
    (import ./rust-toolchain.nix)
    cargo-nextest
    cargo-deny
    cargo-edit
    cargo-depgraph
    swankyLlvm.bintools
    git
    (python312.withPackages (py: [
      py.black
      py.cbor2
      py.isort
      py.jinja2
      py.rich
      py.rich-click
      py.toml
      py.mypy
      py.types-toml
      py.tree-sitter
      py.pytest
      py.xattr
    ]))
    cacert
    nix
    nixpkgs-fmt
    npins
    tree-sitter-grammars.tree-sitter-rust
  ] ++ (lib.lists.optional (!stdenv.isDarwin) mold-wrapped);
}
