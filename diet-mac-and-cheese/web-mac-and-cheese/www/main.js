'use strict';

var read_buffer;
var rb_first;
var rb_last;

var write_buffer;
var wb_first;
var wb_last;

var write_lock;

var progress

if (crossOriginIsolated) {
  console.log("YES crossOriginIsolated");
  read_buffer = new SharedArrayBuffer(Uint8Array.BYTES_PER_ELEMENT * 10000000);
  rb_first = new SharedArrayBuffer(Uint32Array.BYTES_PER_ELEMENT);
  rb_last = new SharedArrayBuffer(Uint32Array.BYTES_PER_ELEMENT);

  write_buffer = new SharedArrayBuffer(Uint8Array.BYTES_PER_ELEMENT * 10000000);
  wb_first = new SharedArrayBuffer(Uint32Array.BYTES_PER_ELEMENT);
  wb_last = new SharedArrayBuffer(Uint32Array.BYTES_PER_ELEMENT);
  write_lock = new SharedArrayBuffer(Uint32Array.BYTES_PER_ELEMENT);

  progress = new SharedArrayBuffer(Uint32Array.BYTES_PER_ELEMENT);
} else {
  console.log("NO crossOriginIsolated");
  meme = new ArrayBuffer(Uint8Array.BYTES_PER_ELEMENT * 10000000);
}

function create_views() {
  let d = {};
  d.read_buffer = new Uint8Array(read_buffer);
  d.rb_first = new Uint32Array(rb_first);
  d.rb_last = new Uint32Array(rb_last);
  d.write_buffer = new Uint8Array(write_buffer);
  d.wb_first = new Uint32Array(wb_first);
  d.wb_last = new Uint32Array(wb_last);
  d.write_lock = new Uint32Array(write_lock);
  return d;
}

var views_websocket = create_views();
var views_macandcheese = create_views();

Atomics.store(views_websocket.rb_first, 0);
Atomics.store(views_websocket.rb_last, 0);

Atomics.store(views_websocket.wb_first, 0);
Atomics.store(views_websocket.wb_last, 0);
Atomics.store(views_websocket.write_lock, 0);

var progress_view = new Uint32Array(progress);
Atomics.store(progress_view, 0);

function make_websocket_url(isNginx) {
  let l = window.location;
  let protocol = (l.protocol === "https:") ? "wss://" : "ws://";
  let port = isNginx ? "8000" : "8080";
  let endpoint = isNginx ? "/ws_macncheese" : "";

  return protocol + l.hostname + ":" + port + endpoint;
}

const worker_websocket = new Worker('/worker_websocket.js', { name: "my_websocket_worker" });
worker_websocket.postMessage(
  {
    arrays: views_websocket,
    progress: progress_view,
    websocket_url: make_websocket_url(false),
  });


const worker_macandcheese = new Worker('/worker_macandcheese.js', { name: "macandcheese_worker" });

worker_macandcheese.postMessage({ arrays: views_macandcheese });

worker_macandcheese.onmessage = (msg) => {
  if ("flush" in msg.data) {
    //console.log("flush: main");
    worker_websocket.postMessage({ flush: true });
  } else if ("verif_status" in msg.data) {
    console.log("RESULT of M+C is " + msg.data.verif_status);
    if (msg.data.verif_status) {
      document.querySelector("#zk-exec-button").innerHTML = "ZK Verif " + "&#10004";
      console.log(document.querySelector("#zk-exec-button"));
      document.querySelector("#zk-exec-button").classList.remove("btn-primary");
      document.querySelector("#zk-exec-button").classList.add("btn-success");
    } else {
      document.querySelector("#zk-exec-button").innerHTML = "ZK Verif " + "&#10060";
      console.log(document.querySelector("#zk-exec-button"));
      document.querySelector("#zk-exec-button").classList.remove("btn-primary");
      document.querySelector("#zk-exec-button").classList.add("btn-danger");
    }
  }
}



/***********************************************/
/****     Loading SIEVE IR files      **********/
/***********************************************/


// Reference https://usefulangle.com/post/297/javascript-get-file-binary-data
document.querySelector("#instance-button").addEventListener('click', function () {
  // no file selected to read
  if (document.querySelector("#file-instance").value == '') {
    console.log('No file selected');
    return;
  }

  let file = document.querySelector("#file-instance").files[0];

  let reader = new FileReader();
  reader.onload = function (e) {
    // binary data
    console.log("******* INSTANCE READ ******");
    console.log(e.target.result);
    let circ_elem = {};
    circ_elem.command = "instance";
    circ_elem.content = e.target.result;
    worker_macandcheese.postMessage(circ_elem);
  };
  reader.onerror = function (e) {
    // error occurred
    console.log('Error : ' + e.type);
  };
  reader.readAsArrayBuffer(file);

  document.querySelector("#instance-button").classList.remove("btn-secondary");
  document.querySelector("#instance-button").classList.add("btn-success");
});

document.querySelector("#relation-button").addEventListener('click', function () {
  // no file selected to read
  if (document.querySelector("#file-relation").value == '') {
    console.log('No file selected');
    return;
  }

  let file = document.querySelector("#file-relation").files[0];

  let reader = new FileReader();
  reader.onload = function (e) {
    // binary data
    console.log("******* RELATION READ ******");
    console.log(e.target.result);
    let circ_elem = {};
    circ_elem.command = "relation";
    circ_elem.content = e.target.result;
    worker_macandcheese.postMessage(circ_elem);
  };
  reader.onerror = function (e) {
    // error occurred
    console.log('Error : ' + e.type);
  };
  reader.readAsArrayBuffer(file);

  document.querySelector("#relation-button").classList.remove("btn-secondary");
  document.querySelector("#relation-button").classList.add("btn-success");
});

document.querySelector("#witness-button").addEventListener('click', function () {
  // no file selected to read
  if (document.querySelector("#file-witness").value == '') {
    console.log('No file selected');
    return;
  }

  let file = document.querySelector("#file-witness").files[0];

  let reader = new FileReader();
  reader.onload = function (e) {
    // binary data
    console.log("******* WITNESS READ ******");
    console.log(e.target.result);
    let circ_elem = {};
    circ_elem.command = "witness";
    circ_elem.content = e.target.result;
    worker_macandcheese.postMessage(circ_elem);
  };
  reader.onerror = function (e) {
    // error occurred
    console.log('Error : ' + e.type);
  };
  reader.readAsArrayBuffer(file);

  document.querySelector("#witness-button").classList.remove("btn-secondary");
  document.querySelector("#witness-button").classList.add("btn-success");
});

/***********************************************/
/**** Loading wasm and sending to worker *******/
/***********************************************/

var wasm_mod_loaded;

function load_mod(mod) {
  wasm_mod_loaded = mod;
}

WebAssembly.compileStreaming(fetch('/pkg/web_mac_and_cheese_wasm_bg.wasm'))
  .then(mod =>
    load_mod(mod)
  );


document.querySelector("#zk-exec-button").addEventListener('click', function () {
  let cont = {};
  cont.command = "exec";
  cont.content = wasm_mod_loaded;
  document.querySelector("#zk-exec-button").innerHTML =
    `ZK Verif <div class="spinner-border" role="status"> <span class="sr-only" > Loading...</span ></div > `;
  worker_macandcheese.postMessage(cont);
});


/***********************************************/
/************** Progress Bar *******************/
/***********************************************/


var write_task = setInterval(make_progress_bar, 1000);

//var total = 12795118; # SVOLE
//var total = 1071293; // f2 circuit
const total = 27428072; // f61p circuit

function make_progress_bar() {
  // count = count + 1; //Number(document.getElementById('count').innerHTML); //set this on page load in a hidden field after an ajax call
  // var total = document.getElementById('total').innerHTML; //set this on initial page load
  const count = Atomics.load(progress_view, 0);
  console.log("progress bar: " + count);
  const pcg = Math.floor(count / total * 100);
  document.getElementsByClassName('progress-bar').item(0).setAttribute('aria-valuenow', pcg);
  document.getElementsByClassName('progress-bar').item(0).setAttribute('style', 'width:' + Number(pcg) + '%');
  document.getElementsByClassName('progress-bar').item(0).innerHTML = Number(pcg) + '%';
}