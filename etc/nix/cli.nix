with import ./pkgs.nix { };
let isLinux = !builtins.isNull (builtins.match "^.*linux$" system);
in (mkShell.override { stdenv = llvmPackages_16.stdenv; }) {
  shellHook = ''
    export SSL_CERT_FILE="${cacert}/etc/ssl/certs/ca-bundle.crt"
    export NIX_SSL_CERT_FILE="${cacert}/etc/ssl/certs/ca-bundle.crt"
  '';
  buildInputs = [
    (import ./rust-toolchain.nix)
    cargo-nextest
    cargo-deny
    cargo-edit
    llvmPackages_16.bintools
    git
    (python311.withPackages (py: [
      py.black
      py.cbor2
      py.click
      py.isort
      py.jinja2
      py.rich
      py.rich-click
      py.toml
      py.mypy
      py.types-toml
      py.py-tree-sitter
      py.pytest
    ]))
    sccache
    cacert
    niv
    nix
    nixpkgs-fmt
    tree-sitter-grammars.tree-sitter-rust
  ];
}
