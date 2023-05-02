with import ./pkgs.nix { };
mkShell {
  buildInputs = [
    (terraform.withPlugins (plugins: [ plugins.aws plugins.tls ]))
    (python3.withPackages (py: [
      py.rich
      py.typer
      py.mypy
      py.isort
      py.black
    ]))
    openssl
    openssh
    zstd
    git
    rsync
    (writeShellScriptBin "aws" ''
      exec ${awscli2}/bin/aws "$@"
    '')
  ];
}
