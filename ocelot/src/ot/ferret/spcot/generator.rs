use scuttlebutt::{Block, F128};

pub struct BiasedGen {
    x: F128,
    s: F128,
}

impl BiasedGen {
    pub fn new(seed: Block) -> BiasedGen {
        BiasedGen {
            x: seed.into(),
            s: seed.into(),
        }
    }

    pub fn next(&mut self) -> F128 {
        let out = self.s;
        self.s = self.s * self.x;
        out
    }
}
