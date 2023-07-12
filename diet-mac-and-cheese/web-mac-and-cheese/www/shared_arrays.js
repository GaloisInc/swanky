'use strict';

// This module defines the interface to the shared arrays used
// to implement a channel of communication between the rust/wasm code
// and the websocket.

const RELEASED_LOCK = 0;
const ACQUIRED_LOCK_LOAD = 17;
const ACQUIRED_LOCK_WRITE = 42;


// The keys of the object containing the arrays.
const shared_arrays_keys = [
  'read_buffer',
  'rb_first',
  'rb_last',

  'write_buffer',
  'wb_first',
  'wb_last',
  'write_lock',
];

function validate_shared_arrays(arrs) {
  shared_arrays_keys.forEach(key => {
    if (!(key in arrs)) {
      throw new Error(`${key} does not exist in the JSON object.`);
    }
  });
}

// how many bytes allocated in the buffer
// NOTE, maybe last is not the best name, it is really the one after last
function how_many(first, last, size) {
  if (first <= last) {
    return last - first;
  } else {
    return size - first + last;
  }
}


function store_to_read_shared_arrays(arrs, data_view) {
  const len = data_view.byteLength;

  // TODO: Put a lock around all that
  const size = arrs.read_buffer.byteLength;
  const first = Atomics.load(arrs.rb_first, 0);
  const last = Atomics.load(arrs.rb_last, 0);
  const nb = how_many(first, last, size);

  if (nb + len > (size - 1)) {
    console.log({
      error: "not enough shared memory on receiving from websocket",
      val: [nb + 1, size]
    });
    sleep(300);
    return;
  }

  let curr_last = last;
  for (let i = 0; i < len; i++) {
    //console.log("byte: " + data_view[i]);
    Atomics.store(arrs.read_buffer, curr_last, data_view[i]);
    curr_last = (curr_last + 1) % size;
  }
  Atomics.store(arrs.rb_last, 0, curr_last);

  return len;
}

function read_byte_from_read_shared_arrays(arrs) {
  let waiting_for_read = true;
  let v;

  // this is blocking
  while (waiting_for_read) {
    // console.log("WAIT ");
    // TODO: lock?
    const size = arrs.read_buffer.byteLength;
    const first = Atomics.load(arrs.rb_first, 0);
    const last = Atomics.load(arrs.rb_last, 0);
    const nb = how_many(first, last, size);

    if (nb > 0) {
      v = Atomics.load(arrs.read_buffer, first);
      Atomics.store(arrs.rb_first, 0, (first + 1) % size);
      waiting_for_read = false;
      //console.log("SERVER: " + v + " at pos " + first);
    }
  }
  return v;
}

// an array used for sending over the websocket,
// it contains data from the shared arrays before sending
var global_arr = new ArrayBuffer(10000000);

function load_from_write_shared_arrays(arrs) {
  let write_done = false;
  let arr_view;
  let empty = true;
  let nb_bytes;

  while (!write_done) {
    // Acquire lock
    if (Atomics.compareExchange(arrs.write_lock, 0, RELEASED_LOCK, ACQUIRED_LOCK_LOAD) == RELEASED_LOCK) {
      //console.log("websocket: Acquire lock");
      const size = arrs.write_buffer.byteLength;
      const first = Atomics.load(arrs.wb_first, 0);
      const last = Atomics.load(arrs.wb_last, 0);
      const nb = how_many(first, last, size);

      write_done = true;
      nb_bytes = nb;

      // Early Free lock
      Atomics.store(arrs.write_lock, 0, RELEASED_LOCK);

      if (nb > 0) {
        empty = false;
        // copy the shared memory and send it on the websocket via a global array
        arr_view = new Uint8Array(global_arr, 0, nb);
        for (let i = 0; i < nb; i++) {
          arr_view[i] = Atomics.load(arrs.write_buffer, (first + i) % size);
        }
        // Advance the first index by how many was sent
        const new_first = (first + nb) % size;
        Atomics.store(arrs.wb_first, 0, new_first);
        //console.log("free spots:" + (size - how_many(new_first, last, size)));
      }

      // Free lock
      // Atomics.store(arrs.write_lock, 0, RELEASED_LOCK);

      console.log("SEND WEBSOCKET: " + nb);
    }
  }
  return { arr_view: arr_view, empty: empty, nb_bytes: nb_bytes };
}

function write_byte_to_write_shared_arrays(arrs, b) {
  let waiting_for_write = true;

  while (waiting_for_write) {
    // Acquire lock
    if (Atomics.compareExchange(arrs.write_lock, 0, RELEASED_LOCK, ACQUIRED_LOCK_WRITE) == RELEASED_LOCK) { // Acquire lock
      const size = arrs.write_buffer.byteLength;
      const first = Atomics.load(arrs.wb_first, 0);
      const last = Atomics.load(arrs.wb_last, 0);
      const nb = how_many(first, last, size);

      // Early Free lock
      Atomics.store(arrs.write_lock, 0, RELEASED_LOCK);

      const enough_space = nb + 1 <= (size - 1);
      if (enough_space) {
        Atomics.store(arrs.write_buffer, last, b);
        let new_last = (last + 1) % size;
        Atomics.store(arrs.wb_last, 0, new_last);
        waiting_for_write = false;
      }

      // Free lock
      // Atomics.store(arrs.write_lock, 0, RELEASED_LOCK);

      if (!enough_space) {
        console.log({ error: "write_byte: waiting for available shared memory. Might have to increase SharedBuffer size", val: [nb + 1, size] });
        sleep(10);
      }
    } else {
      console.log({ error: "write_byte: wait for write_lock release" });
      sleep(10);
    }
  }
}

// Same as `write_byte_to_write_shared_arrays` except that it writes many bytes.
function write_bytes_to_write_shared_arrays(arrs, bytes) {
  let waiting_for_write = true;

  while (waiting_for_write) {
    // Acquire lock
    if (Atomics.compareExchange(arrs.write_lock, 0, RELEASED_LOCK, ACQUIRED_LOCK_WRITE) == RELEASED_LOCK) { // Acquire lock
      const size = arrs.write_buffer.byteLength;
      const first = Atomics.load(arrs.wb_first, 0);
      const last = Atomics.load(arrs.wb_last, 0);
      const nb = how_many(first, last, size);

      // Early Free lock
      // NOTE: it does not seem to run any faster with an early release
      // Atomics.store(arrs.write_lock, 0, RELEASED_LOCK);

      const enough_space = nb + bytes.byteLength <= (size - 1);
      if (enough_space) {
        let new_last = last;
        for (let i = 0; i < bytes.byteLength; i++) {
          Atomics.store(arrs.write_buffer, new_last, bytes[i]);
          new_last = (new_last + 1) % size;
        }
        Atomics.store(arrs.wb_last, 0, new_last);
        waiting_for_write = false;
      }

      // Free lock
      Atomics.store(arrs.write_lock, 0, RELEASED_LOCK);

      if (!enough_space) {
        console.log({ error: "write_byte: waiting for available shared memory", val: [nb + 1, size] });
        sleep(10);
      }
    } else {
      console.log({ error: "write_byte: wait for write_lock release" });
      sleep(10);
    }
  }
}
