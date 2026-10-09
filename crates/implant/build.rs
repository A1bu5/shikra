fn main() {
    // `option_env!("SHIKRA_EMBEDDED_CONFIG_JSON")` in the crate must be
    // re-evaluated whenever the builder changes the baked-in configuration.
    println!("cargo:rerun-if-env-changed=SHIKRA_EMBEDDED_CONFIG_JSON");
    println!("cargo:rerun-if-env-changed=SHIKRA_OBF_SEED");
    println!("cargo:rerun-if-env-changed=SHIKRA_STAGER_URL");
    println!("cargo:rerun-if-env-changed=SHIKRA_STAGER_KEY");
    println!("cargo:rerun-if-env-changed=SHIKRA_STAGER_ARGS");
}
