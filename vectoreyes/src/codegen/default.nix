with (import (builtins.fetchTarball {
  url = "https://github.com/NixOS/nixpkgs/archive/386234e2a61e1e8acf94dfa3a3d3ca19a6776efb.tar.gz";
  sha256 = "1qhfham6vhy67xjdvsmhb3prvsg854wfw4l4avxnvclrcm3k2yg8";
})) {};
mkShell {
  buildInputs = [
    rustfmt
    (python39.withPackages (py: with py; [jinja2 black isort]))
  ];
}
