fn main() -> Result<(), Box<dyn std::error::Error>> {
    // println!("cargo:rustc-link-search=native=./local/libsnark");
    // println!("cargo:rustc-link-lib=dylib=libsnark");
    tonic_build::configure()
        .protoc_arg("--experimental_allow_proto3_optional")
        .compile(&["src/proto/stage.proto"], &["src/proto"])?;
    Ok(())
}
