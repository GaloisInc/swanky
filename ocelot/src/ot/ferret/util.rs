use rand::Rng;

#[inline]
pub fn unique_random_array<R: Rng, const N: usize>(rng: &mut R, max: usize) -> [usize; N] {
    let mut arr = [0usize; N];
    arr[0] = rng.gen::<usize>() % max;
    loop {
        let mut ok: bool = true;
        for i in 1..N {
            if arr[i] == arr[i - 1] {
                arr[i] = rng.gen::<usize>() % max;
                ok = false;
            }
        }
        arr.sort();
        if ok {
            break arr;
        }
    }
}

#[inline]
pub fn random_array<R: Rng, const N: usize>(rng: &mut R, max: usize) -> [usize; N] {
    let mut arr = [0usize; N];
    for e in arr.iter_mut() {
        *e = rng.gen::<usize>() % max;
    }
    arr
}
