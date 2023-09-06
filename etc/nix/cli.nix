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
    ]))
    sccache
    cacert
    niv
    nix
    nixpkgs-fmt
  ];
}
