with import ./pkgs.nix {};
(mkShell.override { stdenv = llvmPackages_16.stdenv; }) {
  shellHook = ''
    export SSL_CERT_FILE="${cacert}/etc/ssl/certs/ca-bundle.crt"
    export NIX_SSL_CERT_FILE="${cacert}/etc/ssl/certs/ca-bundle.crt"
  '';
  buildInputs = [
    (import ./rust-toolchain.nix)
    cargo-nextest
    cargo-deny
    lld_16
    git
    (python311.withPackages (py: [
      py.black
      py.cbor2
      py.isort
      py.rich
      py.toml
      py.typer
    ]))
    sccache
    cacert
    nix
  ];
}
