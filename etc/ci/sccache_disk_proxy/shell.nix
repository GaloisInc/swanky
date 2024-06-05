with import ../../nix/pkgs.nix { };
mkShell {
  buildInputs = [
    (writeShellScriptBin "start_sccache" ''
      set -euxo pipefail
      source ${./env.sh}
      export SSL_CERT_FILE="${cacert}/etc/ssl/certs/ca-bundle.crt"
      export NIX_SSL_CERT_FILE="${cacert}/etc/ssl/certs/ca-bundle.crt"
      tmp=$(mktemp -d)
      function cleanup() {
        ${sccache}/bin/sccache --stop-server || true
        kill %2 || true
        kill %1 || true
        rm -rf "$tmp"
      }
      trap cleanup EXIT
      SWANKY_CACHE_DIR="$(realpath $SWANKY_CACHE_DIR)"
      cat > "$tmp/nginx.conf" << EOF
      worker_processes 4;
      daemon off;

      error_log stderr;
      error_log stderr info;

      pid /dev/null;

      events {
        worker_connections 1024;
      }

      http {
        default_type application/octet-stream;
        access_log /dev/stderr;
        sendfile on;
        keepalive_timeout 65;

        server {
          listen 127.64.64.1:9000;
          location / {
            root $SWANKY_CACHE_DIR;
            dav_methods PUT DELETE MKCOL COPY MOVE;
            dav_ext_methods PROPFIND OPTIONS;

            client_max_body_size 0;
            create_full_put_path on;
            client_body_temp_path $SWANKY_CACHE_DIR/tmp;
            autoindex on;
          }
        }
      }
      EOF
      mkdir -p "$SWANKY_CACHE_DIR/tmp"
      ${nginx}/bin/nginx -c "$tmp/nginx.conf" -e stderr &
      # Wait for the server to start
      while ! timeout 5 ${curl}/bin/curl --verbose http://127.64.64.1:9000/ > /dev/null; do
        sleep 1
      done
      export SCCACHE_LOG=error
      SCCACHE_IDLE_TIMEOUT=0 SCCACHE_START_SERVER=1 SCCACHE_NO_DAEMON=1 ${sccache}/bin/sccache &
      read # wait for stdin to close
    '')
  ];
}
