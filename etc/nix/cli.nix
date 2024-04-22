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
    cargo-depgraph
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
    (tree-sitter-grammars.tree-sitter-rust.overrideAttrs (drv: rec {
      name = "tree-sitter-rust-grammar-${version}";
      version = "0.21.0";

      src = pkgs.fetchFromGitHub {
        owner = "tree-sitter";
        repo = "tree-sitter-rust";
        rev = "v${version}";
        sha256 = "sha256-qf63WCizR8Xa1mUOc+yaKzCWHJZ/perxyxDuN5CQYS4=";
      };
    }))
  ];
}
