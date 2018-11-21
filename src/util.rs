pub fn u128_to_bytes(x: u128) -> [u8;16] {
    unsafe {
        std::mem::transmute(x)
    }
}

pub fn bytes_to_u128(bytes: [u8;16]) -> u128 {
    unsafe {
        std::mem::transmute(bytes)
    }
}
