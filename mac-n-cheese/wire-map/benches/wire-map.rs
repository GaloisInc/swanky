use std::{hint::black_box, time::Instant};

use mac_n_cheese_wire_map::WireMap;

fn main() {
    eprintln!("Reusing hot allocation");
    let mut wm = WireMap::<u64>::new();
    let len = 1024 * 1024 * 16;
    let bases = [
        12377537193953682426,
        11609590603972078201,
        9795369235465835325,
        18446018382927974683,
    ];
    let start = Instant::now();
    for base in bases {
        wm.alloc(base, len).unwrap();
    }
    let len = len;
    for i in 0..len {
        for base in bases {
            wm.insert(base + i, black_box(base + i));
        }
    }
    let time = start.elapsed();
    eprintln!(
        "insert/alloc takes {:?}",
        time / u32::try_from(bases.len() * len as usize).unwrap()
    );
    let start = Instant::now();
    for i in 0..len {
        for base in bases {
            let _ = black_box(wm.get_mut(base + i));
        }
    }
    let time = start.elapsed();
    eprintln!(
        "reading takes {:?}",
        time / u32::try_from(bases.len() * len as usize).unwrap()
    );
}
