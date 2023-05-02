use rand::{rngs::StdRng, Rng, SeedableRng};

use super::Allocation;

#[test]
fn simple_tests() {
    let mut alloc = Allocation::<String>::new_owned(15);
    assert!(alloc.get_mut(14).is_none());
    assert!(alloc.insert(14, "14".to_string()));
    assert_eq!(alloc.get_mut(14).cloned(), Some("14".to_string()));
}

#[test]
fn empty_test() {
    // This test doesn't assert anything, but miri will check to make sure that it's legit.
    Allocation::<String>::new_owned(0);
    Allocation::<u8>::new_owned(0);
    Allocation::<u64>::new_owned(0);
}

#[test]
fn simple_128_string_test() {
    Allocation::<String>::new_owned(128);
}

#[test]
fn test_borrow() {
    let mut root = Allocation::<String>::new_owned(16);
    for i in [4, 9, 13] {
        root.insert(i, i.to_string());
    }
    {
        let [mut a, b, mut c, d, e, f, g] = unsafe {
            let a = Allocation::new_borrow(&root, 0, 8, super::BorrowKind::Mutable);
            let b = Allocation::new_borrow(&root, 8, 2, super::BorrowKind::Immutable);
            let c = Allocation::new_borrow(&root, 10, 1, super::BorrowKind::Mutable);
            let d = Allocation::new_borrow(&root, 12, 4, super::BorrowKind::Immutable);
            let e = Allocation::new_borrow(&root, 8, 2, super::BorrowKind::Immutable);
            let f = Allocation::new_borrow(&root, 9, 1, super::BorrowKind::Immutable);
            let g = Allocation::new_borrow(&root, 11, 3, super::BorrowKind::Immutable);
            [a, b, c, d, e, f, g]
        };
        assert!(a.is_mutable());
        assert!(c.is_mutable());
        assert!(!b.is_mutable());
        assert!(!d.is_mutable());
        assert!(!e.is_mutable());
        assert!(!f.is_mutable());
        assert!(!g.is_mutable());
        let four = a.get_mut(4).unwrap();
        assert_eq!(four.as_str(), "4");
        assert!(a.insert(6, "6".to_string()));
        assert!(!a.insert(4, "four".to_string()));
        assert_eq!(c.get_mut(0), None);
        assert!(c.insert(0, "10".to_string()));
        assert_eq!(b.get(1).unwrap().as_str(), "9");
        assert_eq!(e.get(1).unwrap().as_str(), "9");
        assert_eq!(f.get(0).unwrap().as_str(), "9");
        assert!(b.get(0).is_none());
        assert!(e.get(0).is_none());
        assert_eq!(g.get(2).unwrap().as_str(), "13");
        assert_eq!(d.get(1).unwrap().as_str(), "13");
    }
    for i in 0..16 {
        let expected = match i {
            4 => Some("four"),
            6 => Some("6"),
            9 => Some("9"),
            10 => Some("10"),
            13 => Some("13"),
            _ => None,
        }
        .map(|x| x.to_string());
        assert_eq!(expected.as_ref(), root.get(i));
    }
}

mod random_tests {
    use super::*;
    fn check<T: std::fmt::Debug + Eq>(alloc: &mut Allocation<T>, canonical: &Vec<Option<T>>) {
        assert_eq!(alloc.len(), canonical.len());
        for (i, expected) in canonical.iter().enumerate() {
            assert_eq!(alloc.get_mut(i).as_deref(), expected.as_ref());
        }
    }
    fn rnd_test<T: std::fmt::Debug + Eq + Clone, Gen>(seed: u32, len: usize, gen: Gen)
    where
        for<'a> Gen: Fn(&'a mut StdRng) -> T,
    {
        let mut rng = StdRng::seed_from_u64((u64::from(seed) << 32) | (len as u64));
        let mut canonical: Vec<Option<T>> = vec![None; len];
        let mut alloc = Allocation::<T>::new_owned(len);
        check(&mut alloc, &canonical);
        for _ in 0..len * 2 {
            let idx = rng.gen_range(0..len);
            let value = gen(&mut rng);
            assert_eq!(alloc.insert(idx, value.clone()), canonical[idx].is_none());
            canonical[idx] = Some(value);
            check(&mut alloc, &canonical);
        }
    }
    // We want to test String (which implements Drop), u8 (since it doesn't implement Drop and it's
    // only 1-byte aligned), and unit (since it's a zero-sized type).
    fn test_string(trial: u32, len: usize) {
        let alphabet: Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
            .chars()
            .collect();
        rnd_test::<String, _>(0xc001000 + trial, len, move |x| {
            let strlen = x.gen_range(0_usize..=128_usize);
            let mut out = String::with_capacity(strlen);
            for _ in 0..strlen {
                out.push(alphabet[x.gen_range(0..alphabet.len())]);
            }
            out
        });
    }
    fn test_u8(trial: u32, len: usize) {
        rnd_test::<u8, _>(0xcafe000 + trial, len, |x| x.gen());
    }
    fn test_unit(trial: u32, len: usize) {
        rnd_test::<(), _>(0x7777000 + trial, len, |_| ());
    }
    // We have many different tests since miri uses a lot of memory. By using many tests, we can
    // use cargo-nextest along with miri to reduce the memory usage.
    /*
    for l in [1, 2, 3, 63, 64, 65, 125, 126, 127, 128, 129]:
        for ty in ["string", "u8", "unit"]:
            for trial in range(4):
                print(f"#[test] fn test_{ty}_len{l}_trial{trial}() {{ test_{ty}({trial}, {l}); }}")
    */
    #[test]
    fn test_string_len1_trial0() {
        test_string(0, 1);
    }
    #[test]
    fn test_string_len1_trial1() {
        test_string(1, 1);
    }
    #[test]
    fn test_string_len1_trial2() {
        test_string(2, 1);
    }
    #[test]
    fn test_string_len1_trial3() {
        test_string(3, 1);
    }
    #[test]
    fn test_u8_len1_trial0() {
        test_u8(0, 1);
    }
    #[test]
    fn test_u8_len1_trial1() {
        test_u8(1, 1);
    }
    #[test]
    fn test_u8_len1_trial2() {
        test_u8(2, 1);
    }
    #[test]
    fn test_u8_len1_trial3() {
        test_u8(3, 1);
    }
    #[test]
    fn test_unit_len1_trial0() {
        test_unit(0, 1);
    }
    #[test]
    fn test_unit_len1_trial1() {
        test_unit(1, 1);
    }
    #[test]
    fn test_unit_len1_trial2() {
        test_unit(2, 1);
    }
    #[test]
    fn test_unit_len1_trial3() {
        test_unit(3, 1);
    }
    #[test]
    fn test_string_len2_trial0() {
        test_string(0, 2);
    }
    #[test]
    fn test_string_len2_trial1() {
        test_string(1, 2);
    }
    #[test]
    fn test_string_len2_trial2() {
        test_string(2, 2);
    }
    #[test]
    fn test_string_len2_trial3() {
        test_string(3, 2);
    }
    #[test]
    fn test_u8_len2_trial0() {
        test_u8(0, 2);
    }
    #[test]
    fn test_u8_len2_trial1() {
        test_u8(1, 2);
    }
    #[test]
    fn test_u8_len2_trial2() {
        test_u8(2, 2);
    }
    #[test]
    fn test_u8_len2_trial3() {
        test_u8(3, 2);
    }
    #[test]
    fn test_unit_len2_trial0() {
        test_unit(0, 2);
    }
    #[test]
    fn test_unit_len2_trial1() {
        test_unit(1, 2);
    }
    #[test]
    fn test_unit_len2_trial2() {
        test_unit(2, 2);
    }
    #[test]
    fn test_unit_len2_trial3() {
        test_unit(3, 2);
    }
    #[test]
    fn test_string_len3_trial0() {
        test_string(0, 3);
    }
    #[test]
    fn test_string_len3_trial1() {
        test_string(1, 3);
    }
    #[test]
    fn test_string_len3_trial2() {
        test_string(2, 3);
    }
    #[test]
    fn test_string_len3_trial3() {
        test_string(3, 3);
    }
    #[test]
    fn test_u8_len3_trial0() {
        test_u8(0, 3);
    }
    #[test]
    fn test_u8_len3_trial1() {
        test_u8(1, 3);
    }
    #[test]
    fn test_u8_len3_trial2() {
        test_u8(2, 3);
    }
    #[test]
    fn test_u8_len3_trial3() {
        test_u8(3, 3);
    }
    #[test]
    fn test_unit_len3_trial0() {
        test_unit(0, 3);
    }
    #[test]
    fn test_unit_len3_trial1() {
        test_unit(1, 3);
    }
    #[test]
    fn test_unit_len3_trial2() {
        test_unit(2, 3);
    }
    #[test]
    fn test_unit_len3_trial3() {
        test_unit(3, 3);
    }
    #[test]
    fn test_string_len63_trial0() {
        test_string(0, 63);
    }
    #[test]
    fn test_string_len63_trial1() {
        test_string(1, 63);
    }
    #[test]
    fn test_string_len63_trial2() {
        test_string(2, 63);
    }
    #[test]
    fn test_string_len63_trial3() {
        test_string(3, 63);
    }
    #[test]
    fn test_u8_len63_trial0() {
        test_u8(0, 63);
    }
    #[test]
    fn test_u8_len63_trial1() {
        test_u8(1, 63);
    }
    #[test]
    fn test_u8_len63_trial2() {
        test_u8(2, 63);
    }
    #[test]
    fn test_u8_len63_trial3() {
        test_u8(3, 63);
    }
    #[test]
    fn test_unit_len63_trial0() {
        test_unit(0, 63);
    }
    #[test]
    fn test_unit_len63_trial1() {
        test_unit(1, 63);
    }
    #[test]
    fn test_unit_len63_trial2() {
        test_unit(2, 63);
    }
    #[test]
    fn test_unit_len63_trial3() {
        test_unit(3, 63);
    }
    #[test]
    fn test_string_len64_trial0() {
        test_string(0, 64);
    }
    #[test]
    fn test_string_len64_trial1() {
        test_string(1, 64);
    }
    #[test]
    fn test_string_len64_trial2() {
        test_string(2, 64);
    }
    #[test]
    fn test_string_len64_trial3() {
        test_string(3, 64);
    }
    #[test]
    fn test_u8_len64_trial0() {
        test_u8(0, 64);
    }
    #[test]
    fn test_u8_len64_trial1() {
        test_u8(1, 64);
    }
    #[test]
    fn test_u8_len64_trial2() {
        test_u8(2, 64);
    }
    #[test]
    fn test_u8_len64_trial3() {
        test_u8(3, 64);
    }
    #[test]
    fn test_unit_len64_trial0() {
        test_unit(0, 64);
    }
    #[test]
    fn test_unit_len64_trial1() {
        test_unit(1, 64);
    }
    #[test]
    fn test_unit_len64_trial2() {
        test_unit(2, 64);
    }
    #[test]
    fn test_unit_len64_trial3() {
        test_unit(3, 64);
    }
    #[test]
    fn test_string_len65_trial0() {
        test_string(0, 65);
    }
    #[test]
    fn test_string_len65_trial1() {
        test_string(1, 65);
    }
    #[test]
    fn test_string_len65_trial2() {
        test_string(2, 65);
    }
    #[test]
    fn test_string_len65_trial3() {
        test_string(3, 65);
    }
    #[test]
    fn test_u8_len65_trial0() {
        test_u8(0, 65);
    }
    #[test]
    fn test_u8_len65_trial1() {
        test_u8(1, 65);
    }
    #[test]
    fn test_u8_len65_trial2() {
        test_u8(2, 65);
    }
    #[test]
    fn test_u8_len65_trial3() {
        test_u8(3, 65);
    }
    #[test]
    fn test_unit_len65_trial0() {
        test_unit(0, 65);
    }
    #[test]
    fn test_unit_len65_trial1() {
        test_unit(1, 65);
    }
    #[test]
    fn test_unit_len65_trial2() {
        test_unit(2, 65);
    }
    #[test]
    fn test_unit_len65_trial3() {
        test_unit(3, 65);
    }
    #[test]
    fn test_string_len125_trial0() {
        test_string(0, 125);
    }
    #[test]
    fn test_string_len125_trial1() {
        test_string(1, 125);
    }
    #[test]
    fn test_string_len125_trial2() {
        test_string(2, 125);
    }
    #[test]
    fn test_string_len125_trial3() {
        test_string(3, 125);
    }
    #[test]
    fn test_u8_len125_trial0() {
        test_u8(0, 125);
    }
    #[test]
    fn test_u8_len125_trial1() {
        test_u8(1, 125);
    }
    #[test]
    fn test_u8_len125_trial2() {
        test_u8(2, 125);
    }
    #[test]
    fn test_u8_len125_trial3() {
        test_u8(3, 125);
    }
    #[test]
    fn test_unit_len125_trial0() {
        test_unit(0, 125);
    }
    #[test]
    fn test_unit_len125_trial1() {
        test_unit(1, 125);
    }
    #[test]
    fn test_unit_len125_trial2() {
        test_unit(2, 125);
    }
    #[test]
    fn test_unit_len125_trial3() {
        test_unit(3, 125);
    }
    #[test]
    fn test_string_len126_trial0() {
        test_string(0, 126);
    }
    #[test]
    fn test_string_len126_trial1() {
        test_string(1, 126);
    }
    #[test]
    fn test_string_len126_trial2() {
        test_string(2, 126);
    }
    #[test]
    fn test_string_len126_trial3() {
        test_string(3, 126);
    }
    #[test]
    fn test_u8_len126_trial0() {
        test_u8(0, 126);
    }
    #[test]
    fn test_u8_len126_trial1() {
        test_u8(1, 126);
    }
    #[test]
    fn test_u8_len126_trial2() {
        test_u8(2, 126);
    }
    #[test]
    fn test_u8_len126_trial3() {
        test_u8(3, 126);
    }
    #[test]
    fn test_unit_len126_trial0() {
        test_unit(0, 126);
    }
    #[test]
    fn test_unit_len126_trial1() {
        test_unit(1, 126);
    }
    #[test]
    fn test_unit_len126_trial2() {
        test_unit(2, 126);
    }
    #[test]
    fn test_unit_len126_trial3() {
        test_unit(3, 126);
    }
    #[test]
    fn test_string_len127_trial0() {
        test_string(0, 127);
    }
    #[test]
    fn test_string_len127_trial1() {
        test_string(1, 127);
    }
    #[test]
    fn test_string_len127_trial2() {
        test_string(2, 127);
    }
    #[test]
    fn test_string_len127_trial3() {
        test_string(3, 127);
    }
    #[test]
    fn test_u8_len127_trial0() {
        test_u8(0, 127);
    }
    #[test]
    fn test_u8_len127_trial1() {
        test_u8(1, 127);
    }
    #[test]
    fn test_u8_len127_trial2() {
        test_u8(2, 127);
    }
    #[test]
    fn test_u8_len127_trial3() {
        test_u8(3, 127);
    }
    #[test]
    fn test_unit_len127_trial0() {
        test_unit(0, 127);
    }
    #[test]
    fn test_unit_len127_trial1() {
        test_unit(1, 127);
    }
    #[test]
    fn test_unit_len127_trial2() {
        test_unit(2, 127);
    }
    #[test]
    fn test_unit_len127_trial3() {
        test_unit(3, 127);
    }
    #[test]
    fn test_string_len128_trial0() {
        test_string(0, 128);
    }
    #[test]
    fn test_string_len128_trial1() {
        test_string(1, 128);
    }
    #[test]
    fn test_string_len128_trial2() {
        test_string(2, 128);
    }
    #[test]
    fn test_string_len128_trial3() {
        test_string(3, 128);
    }
    #[test]
    fn test_u8_len128_trial0() {
        test_u8(0, 128);
    }
    #[test]
    fn test_u8_len128_trial1() {
        test_u8(1, 128);
    }
    #[test]
    fn test_u8_len128_trial2() {
        test_u8(2, 128);
    }
    #[test]
    fn test_u8_len128_trial3() {
        test_u8(3, 128);
    }
    #[test]
    fn test_unit_len128_trial0() {
        test_unit(0, 128);
    }
    #[test]
    fn test_unit_len128_trial1() {
        test_unit(1, 128);
    }
    #[test]
    fn test_unit_len128_trial2() {
        test_unit(2, 128);
    }
    #[test]
    fn test_unit_len128_trial3() {
        test_unit(3, 128);
    }
    #[test]
    fn test_string_len129_trial0() {
        test_string(0, 129);
    }
    #[test]
    fn test_string_len129_trial1() {
        test_string(1, 129);
    }
    #[test]
    fn test_string_len129_trial2() {
        test_string(2, 129);
    }
    #[test]
    fn test_string_len129_trial3() {
        test_string(3, 129);
    }
    #[test]
    fn test_u8_len129_trial0() {
        test_u8(0, 129);
    }
    #[test]
    fn test_u8_len129_trial1() {
        test_u8(1, 129);
    }
    #[test]
    fn test_u8_len129_trial2() {
        test_u8(2, 129);
    }
    #[test]
    fn test_u8_len129_trial3() {
        test_u8(3, 129);
    }
    #[test]
    fn test_unit_len129_trial0() {
        test_unit(0, 129);
    }
    #[test]
    fn test_unit_len129_trial1() {
        test_unit(1, 129);
    }
    #[test]
    fn test_unit_len129_trial2() {
        test_unit(2, 129);
    }
    #[test]
    fn test_unit_len129_trial3() {
        test_unit(3, 129);
    }
}
