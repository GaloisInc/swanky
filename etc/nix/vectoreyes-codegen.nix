with import ./pkgs.nix {};
mkShell {
  buildInputs = [
    (import ./rust-toolchain.nix)
    (python310.withPackages (py: [py.jinja2]))
  ];
}
