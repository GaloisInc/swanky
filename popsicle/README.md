# `popsicle`: A rust library for private set intersection

`popsicle` is a rust library that provides implementations for private
set intersection (PSI) protocols.

`popsicle` currently implements the following PSI protocols:

* The [Pinkas-Schneider-Zohner](https://eprint.iacr.org/2016/930) semi-honest two-party PSI protocol based on the
  oblivious PRF of [Kolesnikov-Kumaresan-Rosulek-Trieu](https://eprint.iacr.org/2016/799).
* The [Pinkas-Schneider-Tkachenko-Yanai](https://eprint.iacr.org/2019/241) semi-honest two-party PSI protocol based
  on the oblivious programmable PRF of [Kolesnikov-Matania-Pinkas-Rosulek-Trieu](https://eprint.iacr.org/2017/799).
* The [Kolesnikov-Matania-Pinkas-Rosulek-Trieu](https://eprint.iacr.org/2017/799) semi-honest multi-party PSI
  protocol.