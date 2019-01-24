use bitvec::BitVec;

pub fn u128_to_bitvec(v: u128) -> BitVec {
    let b = u128::to_ne_bytes(v);
    BitVec::from(b.to_vec())
}

pub fn bitvec_to_u128(bv: BitVec) -> u128 {
    let mut bytes = [0u8; 16];
    let v: Vec<u8> = bv.into();
    for (i, b) in v.iter().enumerate() {
        bytes[i] = *b;
    }
    u128::from_ne_bytes(bytes)
}
