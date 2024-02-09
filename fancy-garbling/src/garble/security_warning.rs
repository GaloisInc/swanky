use std::sync::atomic::AtomicBool;

pub(super) fn warn_proj() {
    static WARNING_PRINTED: AtomicBool = AtomicBool::new(false);
    if !WARNING_PRINTED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        eprintln!("SWANKY SECURITY WARNING:");
        eprintln!("This code uses the arithmetic proj garbled circuit gate. These have");
        eprintln!("a critical security issue. See the README for more info.");
    }
}
