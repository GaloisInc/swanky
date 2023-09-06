with import ../../nix/pkgs.nix { };
let
  sccache_disk_proxy = buildGoModule {
    pname = "sccache_disk_proxy";
    version = "0.0.1";
    src = ./.;
    vendorHash = null;
  };
in
mkShell {
  buildInputs = [
    (writeShellScriptBin "start_sccache" ''
      source ${./env.sh}
      tmp=$(mktemp -d)
      mkfifo "$tmp/ready"
      function cleanup() {
        ${sccache}/bin/sccache --stop-server || true
        kill %2 || true
        kill %1 || true
      }
      trap cleanup EXIT
      ${sccache_disk_proxy}/bin/sccache_disk_proxy --bind "$SCCACHE_ENDPOINT" --data "$SWANKY_CACHE_DIR/sccache" --ready "$tmp/ready" &
      # Wait for the server to start
      head -c 1 "$tmp/ready" > /dev/null
      rm "$tmp/ready"
      rmdir "$tmp"
      export SCCACHE_LOG=info
      SCCACHE_IDLE_TIMEOUT=0 SCCACHE_START_SERVER=1 SCCACHE_NO_DAEMON=1 ${sccache}/bin/sccache &
      read # wait for stdin to close
    '')
  ];
}
