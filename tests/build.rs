fn main() {
    if cfg!(target_os = "linux") {
        match pkg_config::probe_library("libiscsi") {
            Ok(_) => {
                println!("cargo:rustc-cfg=has_libiscsi");
                println!("cargo:warning=libiscsi found, integration tests enabled");
            }
            Err(_) => {
                println!("cargo:warning=libiscsi not found, integration tests skipped");
            }
        }
    }
}
