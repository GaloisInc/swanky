with import ../nix/pkgs.nix;
let sccache_disk_proxy = buildGoModule {
  pname = "sccache_disk_proxy";
  version = "0.0.1";
  src = ./sccache_disk_proxy;
  vendorSha256 = "sha256-paCJiOD5J5I3N2TLdXlYR/WD69UyGaYALWIdsIxQkCs=";
};
mkShell {
  buildInputs = [
    (writeShellScriptBin "start_sccache" ''
      export SCCACHE_IDLE_TIMEOUT=0
      export SCCACHE_ENDPOINT="127.64.64.1:9000"
      export SCCACHE_BUCKET=swanky-sccache
      export SCCACHE_S3_USE_SSL=off
      export AWS_ACCESS_KEY_ID=galois
      export AWS_SECRET_ACCESS_KEY=galoissecret
      tmp=$(mktemp -d)
      function run_daemon() {
          ${sccache_disk_proxy}/bin/sccache_disk_proxy --bind "$SCCACHE_ENDPOINT" --data "$SWANKY_CACHE_DIR/sccache" --ready "$tmp/ready" &
      }

      mkfifo "$tmp/ready"
      run_daemon &
      # Wait for the server to start
      head -c 1 "$tmp/ready" > /dev/null
      rm "$tmp/ready"
      rmdir "$tmp"
      ${sccache}/bin/sccache --start-server
    '')
  ];
}
