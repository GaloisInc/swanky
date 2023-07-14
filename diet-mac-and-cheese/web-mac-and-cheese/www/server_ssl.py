#!/usr/bin/env python3
# python3 update of https://gist.github.com/dergachev/7028596
# Create a basic certificate using openssl:
#     openssl req -new -x509 -keyout key.pem -out cert.pem -days 365 -nodes
# Or to set CN, SAN and/or create a cert signed by your own root CA: https://thegreycorner.com/pentesting_stuff/writeups/selfsignedcert.html

import argparse
import http
import ssl
from http import server


class MyHTTPRequestHandler(server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_my_headers()

        server.SimpleHTTPRequestHandler.end_headers(self)

    def send_my_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cross-Origin-Embedder-Policy", "require-corp")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")


parser = argparse.ArgumentParser(description="Web server with SSL")
parser.add_argument(
    "--key", dest="keyfile", help="pem key file", default="../verifier/key.pem"
)
parser.add_argument(
    "--cert", dest="certfile", help="pem cerl file", default="../verifier/cert.pem"
)
parser.add_argument(
    "--addr", dest="address", help="binding address", default="127.0.0.1"
)
parser.add_argument("--port", dest="port", help="port", type=int, default=8000)
args = parser.parse_args()


httpd = http.server.HTTPServer((args.address, args.port), MyHTTPRequestHandler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(keyfile=args.keyfile, certfile=args.certfile)
httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
httpd.serve_forever()
