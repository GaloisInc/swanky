use scuttlebutt::{Aes128, Block};

pub struct PseudorandomCode {
    cipher1: Aes128,
    cipher2: Aes128,
    cipher3: Aes128,
    cipher4: Aes128,
}

impl PseudorandomCode {
    pub fn new(k1: Block, k2: Block, k3: Block, k4: Block) -> Self {
        let cipher1 = Aes128::new(k1);
        let cipher2 = Aes128::new(k2);
        let cipher3 = Aes128::new(k3);
        let cipher4 = Aes128::new(k4);
        Self {
            cipher1,
            cipher2,
            cipher3,
            cipher4,
        }
    }

    pub fn encode(&self, m: Block, out: &mut [Block; 4]) {
        out[0] = self.cipher1.encrypt(m);
        out[1] = self.cipher2.encrypt(m);
        out[2] = self.cipher3.encrypt(m);
        out[3] = self.cipher4.encrypt(m);
    }
}

#[cfg(all(feature = "nightly", test))]
mod benchmarks {
    extern crate test;
    use super::*;
    use test::Bencher;

    #[bench]
    fn bench_new(b: &mut Bencher) {
        let k1 = rand::random::<Block>();
        let k2 = rand::random::<Block>();
        let k3 = rand::random::<Block>();
        let k4 = rand::random::<Block>();
        b.iter(|| PseudorandomCode::new(k1, k2, k3, k4));
    }

    #[bench]
    fn bench_encode(b: &mut Bencher) {
        let k1 = rand::random::<Block>();
        let k2 = rand::random::<Block>();
        let k3 = rand::random::<Block>();
        let k4 = rand::random::<Block>();
        let prc = PseudorandomCode::new(k1, k2, k3, k4);
        let m = rand::random::<Block>();
        let mut out = [Block::default(); 4];
        b.iter(|| prc.encode(m, &mut out));
    }
}
