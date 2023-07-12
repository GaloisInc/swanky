
# Run the project

```bash
# from web-mac-and-cheese in three different terminals:

# term 1
cd websocket
cargo run --release --example web_macandcheese_verifier -- --instance <PATH-TO-FILE> --relation <PATH-TO-FILE>


# term 2
cd wasm
wasm-pack build --target web --no-typescript
cp pkg/web_mac_and_cheese_wasm_bg.wasm ../www/pkg/.
# in addition to copying the wasm file, it might be necessary to copy the js interface file when the interface changes
# or when the wasm toolchain is upgraded. Look at the diff, remove the `export` modifer in front
#  of `function test_web_macandcheese`, delete the unnecessary `async` part
cp pkg/web_mac_and_cheese_wasm.js ../www/copied_from_prover_wasm.js

# term 3
cd www
python3 server.py

# Browser
# open http://localhost:8000
# open the same files provided to the verifier
```

To start executing the demo, open in **Firefox** `http://localhost:8000`


# Architecture

The three main components are found in:
* `websocket/` library for the websocket channel. It contains the example `web_macandcheese_verifier`
* `wasm/` library for interface with the websocket channel in javascript. It also has an example `web_macandcheese_prover` that takes as input some `instance/witness/relation` and start executing the protocol. The network layer is provided as some foreign function implemented on the javacript side, in `www/`
* `www/` serves the user web page and contains the web app.


## Architecture

![Web Mac and Cheese](doc/Web\ Mac\ and\ Cheese.png)



# Notes and Tips

## Running wasm

After running:
```
wasm-pack build --target web --no-typescript
```
You get `/web_mac_and_cheese_wasm_bg.js` and `web_mac_and_cheese_wasm_bg.wasm`. The file `web_mac_and_cheese_wasm_bg.js` provides some interface/glue
code for the interaction between Javascript and WASM and is supposed to be loaded from Javascript.
Unfortunately, it contains some `export` statements that appears to be incompatible with the way it is
loaded from the Web-worker `worker_macandcheese.js`. For this reason, we have to manually extract and slightly
modify some of `/web_mac_and_cheese_wasm_bg.js` into `copied_from_prover_wams.js`, and this has to be done everytime the
interface changes (and maybe also when wasm-pack is updated):

* from `let wasm` to `function passArray8ToWasm0{...}` included
* `export function test_web_macandcheese{...}` without the `export` at the beginning
* from `const cachedTextEncoder = ...` to `get_imports(){...}`

There are different ways to setup and run wasm from javascript. Based on experiments and because of the
constraint that it runs into a webworker, we found how to load successfully the wasm code in two steps:

* 1. In `main.js`:
```
WebAssembly.compileStreaming(fetch('http://localhost:8000/pkg/prover_wasm_bg.wasm'))
  .then(mod =>
    worker_macandcheese.postMessage(mod)
  );
  ```
* 2. In `worker_macandcheese.js`:
```
const imports = getImports();
WebAssembly.instantiate(mod, imports)
  .then(function (instance) {
    wasm = instance.exports;
    // Recently have to init the memory here, because code is now in
    // `initSync` of prover_wasm.js that we do not use
    cachedUint8Memory0 = new Uint8Array(wasm.memory.buffer);
    cachedInt32Memory0 = new Int32Array(wasm.memory.buffer);

    let r;
    r = test_web_macandcheese(instance_bytes_rcv, relation_bytes_rcv, witness_bytes_rcv);
  });
```

References:
* https://developer.mozilla.org/en-US/docs/WebAssembly
* https://developer.mozilla.org/en-US/docs/WebAssembly/Rust_to_wasm


## Rust server-prover with websocket

Reference:
* https://docs.rs/websocket/latest/websocket/server/struct.WsServer.html


## Setting up for SharedArrayBuffer
Important, set following in http server header response (https://developer.chrome.com/blog/enabling-shared-array-buffer/)
```
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Opener-Policy: same-origin
```
Maybe also:
```
Access-Control-Allow-Origin": *
```

First, I thought I needed TLS to allow the `crossOriginIsolated`, but actually that's not needed.

Reference:
* https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/SharedArrayBuffer
* SharedMemory and workers: https://github.com/tc39/proposal-ecmascript-sharedmem/blob/main/TUTORIAL.md
* https://developer.chrome.com/blog/enabling-shared-array-buffer/
