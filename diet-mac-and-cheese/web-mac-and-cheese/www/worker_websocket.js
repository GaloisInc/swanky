'use strict';

importScripts('/shared_arrays.js');


var arrs;
var progress;

function update_progress_bar(nb_bytes) {
  const count = Atomics.load(progress, 0);
  Atomics.store(progress, 0, count + nb_bytes);
}

/*
function sleep(milliseconds) {
  var start = new Date().getTime();
  for (var i = 0; i < 100e7; i++) {
    if ((new Date().getTime() - start) > milliseconds) {
      break;
    }
  }
};
*/

// now starting a websocket
var wsocket;
function create_websocket(websocket_url) {
  wsocket = new WebSocket(websocket_url);
  wsocket.binaryType = "arraybuffer";

  wsocket.onopen = function (event) {
    wsocket.send("init");
  };

  wsocket.onmessage = function (event) {
    // var msg = JSON.parse(event.data);
    // sleep(300);

    if (event.data instanceof ArrayBuffer) {
      // binary frame
      const view = new Uint8Array(event.data);
      const nb_bytes = store_to_read_shared_arrays(arrs, view);

      update_progress_bar(nb_bytes);
    } else {
      // text frame
      console.log("text frame");
      console.log(event.data);
    }
  }
}


function send_on_websocket() {
  let r = load_from_write_shared_arrays(arrs, progress);
  if (r.empty == false) {
    wsocket.send(r.arr_view);
  }

  update_progress_bar(r.nb_bytes);
}

self.onmessage = (msg) => {
  if ("flush" in msg.data) {
    // console.log("flush: worker_websocket");
    send_on_websocket();
  } else if ("arrays" in msg.data) {
    console.log("worker_websocket: receive arrays");
    // Receives the SharedArrayBuffers and store them in global variables
    arrs = msg.data.arrays;
    validate_shared_arrays(arrs);

    progress = msg.data.progress;
    create_websocket(msg.data.websocket_url);
  }
};