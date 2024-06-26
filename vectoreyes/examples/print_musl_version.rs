//! If running with `musl` libc, then print out the version of musl. Otherwise do nothing.

#[cfg(target_env = "musl")]
extern "C" {
    static __libc_version: std::ffi::c_char;
}

fn main() {
    #[cfg(target_env = "musl")]
    {
        println!(
            "{}",
            unsafe { std::ffi::CStr::from_ptr(&__libc_version) }
                .to_str()
                .unwrap()
        );
    }
}
