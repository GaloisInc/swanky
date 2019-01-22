use bitvec::BitVec;

pub fn u128_to_bitvec(v: u128) -> BitVec {
    let b = u128::to_ne_bytes(v);
    BitVec::from(b.to_vec())
}

pub fn bitvec_to_u128(bv: &BitVec) -> u128 {
    let mut bytes = [0u8; 16];
    let v = bitvec_to_vec(bv);
    for (i, b) in v.iter().enumerate() {
        bytes[i] = *b;
    }
    u128::from_ne_bytes(bytes)
}

pub fn bitvec_to_vec(bytes: &BitVec) -> Vec<u8> {
    let v = bytes.clone().into_iter().collect::<Vec<bool>>();
    let v = v
        .into_boxed_slice()
        .chunks(8)
        .map(|bits| {
            let b = bits.into_iter().enumerate().fold(0u8, |acc, (i, b)| {
                let acc = acc ^ (u8::from(*b) << (7 - i));
                acc
            });
            b
        })
        .collect::<Vec<u8>>();
    v
}
