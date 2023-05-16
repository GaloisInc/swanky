use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_VECTOREYES_TARGET_CPU_NATIVE").is_ok() {
        let output = Command::new(std::env::var("RUSTC").expect("RUSTC env var"))
            .arg("-C")
            .arg("target-cpu=help")
            .output()
            .expect("rustc finished successfully");
        assert!(output.status.success());
        let mut lines = output
            .stdout
            .split(|ch| *ch == b'\n')
            .map(|line| String::from_utf8_lossy(line).into_owned());
        // NOTE: rustc's output format isn't desinged to be parsed like this, but there isn't an
        // easy way to get the native target-cpu otherwise (since LLVM uses a pile of heuristics to
        // pick it).
        assert_eq!(
            lines.next().expect("first line").as_str(),
            "Available CPUs for this target:"
        );
        let native_line = lines.next().expect("the native line");
        assert!(native_line.trim_start().starts_with("native"));
        let last_whitespace = native_line.rfind(' ').expect("there is some whitespace");
        // The last two characters are ")."
        let target_cpu = &native_line[last_whitespace + 1..native_line.len() - 2];
        if !lines.any(|line| line.trim() == target_cpu) {
            panic!("target_cpu {:?} doesn't seem to be valid", target_cpu);
        }
        println!("cargo:rustc-cfg=vectoreyes_target_cpu={:?}", target_cpu);
    }
}
