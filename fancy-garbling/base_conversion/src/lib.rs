#![allow(clippy::all)]
#![deny(clippy::all)]

pub fn lookup_digits_mod_at_position(x: u8, q: u16, pos: usize) -> &'static [u16] {
    unsafe {
        let tab = c_get_table(q, pos);
        let len = c_num_digits(q, pos);
        std::slice::from_raw_parts(tab.add(len * (x as usize)), len)
    }
}

pub fn lookup_defined_for_mod(q: u16) -> bool {
    unsafe { c_num_digits(q, 0) > 0 }
}

extern "C" {
    fn c_get_table(q: u16, pos: usize) -> *const u16;
    fn c_num_digits(q: u16, pos: usize) -> usize;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lookup() {
        if lookup_defined_for_mod(3) {
            assert_eq!(lookup_digits_mod_at_position(0, 3, 0), &[0, 0, 0, 0, 0, 0]);
            assert_eq!(
                lookup_digits_mod_at_position(2, 3, 6).to_vec(),
                vec![
                    2, 0, 1, 1, 2, 0, 1, 1, 2, 2, 0, 2, 1, 1, 0, 0, 2, 0, 1, 1, 1, 0, 2, 0, 1, 1,
                    2, 1, 0, 2, 2, 0, 0, 0, 0, 0
                ]
            );
        }
    }
}
