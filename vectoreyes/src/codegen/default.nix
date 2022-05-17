with (import (import nix/sources.nix).nixpkgs) { };
mkShell {
  buildInputs = [
    rustfmt
    (python39.withPackages (py: with py; [jinja2 black isort]))
  ];
}
