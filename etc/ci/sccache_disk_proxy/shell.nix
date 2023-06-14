with import ../../nix/pkgs.nix {};
let sccache_disk_proxy = buildGoModule {
  pname = "sccache_disk_proxy";
  version = "0.0.1";
  src = ./.;
  vendorSha256 = "sha256-paCJiOD5J5I3N2TLdXlYR/WD69UyGaYALWIdsIxQkCs=";
};
in mkShell {
  buildInputs = [
    (writeShellScriptBin "start_sccache" ''
      source ${./env.sh}
      tmp=$(mktemp -d)
      mkfifo "$tmp/ready"
      function cleanup() {
        ${sccache}/bin/sccache --stop-server
        kill %1
      }
      trap cleanup EXIT
      ${sccache_disk_proxy}/bin/sccache_disk_proxy --bind "$SCCACHE_ENDPOINT" --data "$SWANKY_CACHE_DIR/sccache" --ready "$tmp/ready" &
      # Wait for the server to start
      head -c 1 "$tmp/ready" > /dev/null
      rm "$tmp/ready"
      rmdir "$tmp"
      ${sccache}/bin/sccache --start-server
      echo 1 > "$SCCACHE_READY_PATH"
      read # wait for stdin to close
    '')
  ];
}
