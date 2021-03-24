with (import (builtins.fetchTarball {
  url = "https://github.com/NixOS/nixpkgs/archive/3f74138ce2e97615bb8d50164214ad65c1093867.tar.gz";
  sha256 = "18jf4k86h82wj7h3w11b8fj1wgwb6bwq53f771z1z1la2lwpzn3v";
})) {};
mkShell {
  buildInputs = [
    rustfmt
    (python39.withPackages (py: with py; [jinja2 black isort]))
  ];
}