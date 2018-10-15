pub fn lookup_digits_mod(x: u16, q: u8) -> &'static [u8] {
    unsafe {
        let tab = c_get_table(q);
        let len = c_num_digits(q);
        std::slice::from_raw_parts(tab.offset((len*(x as usize)) as isize), len)
    }
}

pub fn lookup_defined_for_mod(q: u8) -> bool {
    unsafe {
        c_num_digits(q) > 0
    }
}

extern {
    fn c_get_table(q: u8, ) -> *const u8;
    fn c_num_digits(q: u8) -> usize;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lookup() {
        if lookup_defined_for_mod(3) {
            assert_eq!(lookup_digits_mod(0,3), &[ 0,0,0,0,0,0,0,0,0,0,0 ]);
        }
    }
}
