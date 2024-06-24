{ target }:
with import ./pkgs.nix { };
let
  version = "1.2.3";
  swankyLlvm = import ./llvm.nix;
in
stdenv.mkDerivation {
  name = "musl-sysroot";
  src = fetchurl {
    url = "https://musl.libc.org/releases/musl-${version}.tar.gz";
    hash = "sha256-fVsLYGJSHkYn4JnkydyCSNMqMChelZt+7Kp4DPjP1KQ=";
  };
  configurePhase = ''
    export CC="${swankyLlvm.clang-unwrapped}/bin/clang"
    export CFLAGS="--target=${target}"
    ./configure "--prefix=$out" "--target=${target}"
  '';
  buildPhase = "true";
  installPhase = ''
    mkdir -p "$out"
    echo "${version}" > "$out/version.txt"
    make install-headers
  '';
}
