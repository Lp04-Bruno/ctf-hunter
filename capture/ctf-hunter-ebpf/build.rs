use which::which;

fn main() {
    let bpf_linker = which("bpf-linker").expect("bpf-linker must be available");
    println!("cargo:rerun-if-changed={}", bpf_linker.display());
}
