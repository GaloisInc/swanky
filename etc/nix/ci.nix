with import ./pkgs.nix;
mkShell {
  shellHook = ''
    export SSL_CERT_FILE="${cacert}/etc/ssl/certs/ca-bundle.crt"
    export NIX_SSL_CERT_FILE="${cacert}/etc/ssl/certs/ca-bundle.crt"
  '';
  buildInputs = [
    (import ./rust-toolchain.nix)
    cargo-nextest
    cargo-deny
    
    git
    (python310.withPackages (py: [
      py.toml
      py.rich
      py.typer
      py.black
      py.isort
    ]))
    sccache
    cacert
    nix
  ];
}
