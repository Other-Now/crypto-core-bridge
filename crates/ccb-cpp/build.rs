// Compiles the C++ core (cpp/src) together with the cxx shim and links the
// system OpenSSL. CCB_CXXFLAGS adds flags (CI uses it for sanitizers).
fn main() {
    let core = ["primitives.cpp", "software_store.cpp", "pkcs11_store.cpp"];
    let mut b = cxx_build::bridge("src/lib.rs");
    b.file("src/bridge.cpp")
        .include("../../cpp/include")
        .include("../../third_party/pkcs11")
        .std("c++20")
        .flag_if_supported("-Wno-unused-parameter");
    for f in core {
        b.file(format!("../../cpp/src/{f}"));
        println!("cargo:rerun-if-changed=../../cpp/src/{f}");
    }
    if let Ok(extra) = std::env::var("CCB_CXXFLAGS") {
        for f in extra.split_whitespace() {
            b.flag(f);
        }
    }
    println!("cargo:rerun-if-env-changed=CCB_CXXFLAGS");
    b.compile("ccb_cpp_core");
    println!("cargo:rustc-link-lib=crypto");
    println!("cargo:rustc-link-lib=dl");
    for f in ["src/bridge.cpp", "src/bridge.hpp", "../../cpp/include/ccb/core.hpp"] {
        println!("cargo:rerun-if-changed={f}");
    }
}
