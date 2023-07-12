# The `scuttlebutt` multi-party computation utilities toolkit
Or: "Where rust MPC libraries come to drink"

The `scuttlebutt` library provides a bunch of core primitives for building
multi-party computation (MPC) related protocols, such as garbled circuits or
oblivious transfer. In particular, `scuttlebutt` provides the following:

* `AbstractChannel`, which provides a trait for a read/write communication
  channel. The library also includes several implementations of said trait:
  `Channel` for your basic channel needs, `TrackChannel` for additionally
  recording the number of bytes read/written to the channel, and `SyncChannel`
  for a channel that supports the `Send` and `Sync` traits.
* `Aes128` and `Aes256`, which provide AES encryption capabilities using AES-NI.
* `AesHash`, which provides correlation-robust hash functions based on
  fixed-key AES (cf. <https://eprint.iacr.org/2019/074>).
* `AesRng`, which provides a random number generator based on fixed-key AES.
* `Block`, which wraps a 128-bit value and provides methods operating on that value.
* `Block512`, which wraps a 512-bit value and provides methods operating on that value.
* A `cointoss` module, which implements a simple random-oracle-based coin-tossing protocol.
* A `commitment` module, which provides a `Commitment` trait and an
  implementation `ShaCommitment` using SHA-256.
* A `utils` module, which contains useful utility functions.
* Marker traits `SemiHonest` and `Malicious` for enforcing security properties
  on specific implementations.