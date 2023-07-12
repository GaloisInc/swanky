'use strict';

importScripts('/shared_arrays.js');
// importScripts('/pkg/web_mac_and_cheese_prover.js'); cant do that because of the `export`,
// so instead we have to coppy manually
importScripts('/copied_from_prover_wasm.js');
// importScripts('/pkg/web_mac_and_cheese_wasm.js');

var arrs;

function sleep(milliseconds) {
  let start = new Date().getTime();
  for (let i = 0; i < 100e7; i++) {
    if ((new Date().getTime() - start) > milliseconds) {
      break;
    }
  }
};

function alert(x) {
  console.log(x);
};

function print_console(x) {
  console.log("VALUE: " + x);
}

function js_read_byte() {
  return read_byte_from_read_shared_arrays(arrs);
}

function js_write_byte(b) {
  return write_byte_to_write_shared_arrays(arrs, b);
}

function js_write_bytes(bytes) {
  return write_bytes_to_write_shared_arrays(arrs, bytes);
}


function js_flush() {
  // console.log("flush: from wasm");
  self.postMessage({ flush: true });
}


var count = 0;

var instance_bytes_rcv;
var witness_bytes_rcv;
var relation_bytes_rcv;


self.onmessage = (msg) => {
  if (count == 0) {
    console.log("client worker received share memory");
    arrs = msg.data.arrays;
    validate_shared_arrays(arrs);
  } else if (msg.data.command == "instance") {
    let instance_bytes = msg.data.content;
    console.log("BEFORE put in Uint8Array");
    console.log(instance_bytes);
    console.log(instance_bytes.length);
    console.log(typeof instance_bytes);
    instance_bytes_rcv = new Uint8Array(instance_bytes);
    console.log(instance_bytes_rcv);
  } else if (msg.data.command == "witness") {
    let witness_bytes = msg.data.content;
    console.log(witness_bytes);
    witness_bytes_rcv = new Uint8Array(witness_bytes);
    console.log(witness_bytes_rcv.length);
  } else if (msg.data.command == "relation") {
    let relation_bytes = msg.data.content;
    console.log(relation_bytes);
    relation_bytes_rcv = new Uint8Array(relation_bytes);
    console.log(relation_bytes_rcv.length);
  } else if (msg.data.command == "exec") {
    console.log('module received from main thread');
    let mod = msg.data.content;
    console.log("MODULE");
    console.log(mod);

    // It is a little weird that we have to redo the imports!!! Oh well
    const imports = __wbg_get_imports();
    WebAssembly.instantiate(mod, imports)
      .then(function (instance) {
        console.log("EXPORTS")
        console.log(instance.exports);
        wasm = instance.exports;

        let r;

        // SVOLE
        // r = wasm.test_svole();
        // console.log("!!!!!SVOLE COMPLETED!!!!: " + r);

        r = test_web_macandcheese(instance_bytes_rcv, relation_bytes_rcv, witness_bytes_rcv);
        console.log("!!!!! Mac'n'Cheese zk verif COMPLETE!!!!: " + r);
        self.postMessage({ verif_status: r });
      });
  }
  count++;
};

