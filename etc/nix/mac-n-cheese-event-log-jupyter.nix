with import ./pkgs.nix {};
(mkShell.override { stdenv = llvmPackages_16.stdenv; }) {
  shellHook = ''
    export SSL_CERT_FILE="${cacert}/etc/ssl/certs/ca-bundle.crt"
    export NIX_SSL_CERT_FILE="${cacert}/etc/ssl/certs/ca-bundle.crt"
  '';
  buildInputs = [
    cacert
    git
    (import ./rust-toolchain.nix)
    (python3.withPackages (py: [
        py.jupyterlab
        py.numpy
        py.scipy
        py.pandas
        py.plotly
        py.cbor2
    ]))
  ];
}
