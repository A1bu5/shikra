fn main() {
    // `shikra-obf` expands string literals at compile time using this seed;
    // the crate must rebuild whenever the builder rotates it.
    println!("cargo:rerun-if-env-changed=SHIKRA_OBF_SEED");
}
