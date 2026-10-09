fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    std::env::set_var("PROTOC", protoc);

    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR")?);

    tonic_prost_build::configure()
        .file_descriptor_set_path(out_dir.join("shikra_descriptor.bin"))
        .build_client(true)
        .build_server(true)
        .compile_protos(
            &[
                "proto/shikra/v1/common.proto",
                "proto/shikra/v1/control.proto",
            ],
            &["proto"],
        )?;

    println!("cargo:rerun-if-changed=proto/shikra/v1/common.proto");
    println!("cargo:rerun-if-changed=proto/shikra/v1/control.proto");
    Ok(())
}
