//! Differential fuzzing: fuzzer bytes become an operation sequence replayed
//! against the Rust store and the C++ store (through cxx). Any difference in
//! status code or output aborts. This exercises every KeyStore entry point
//! of both implementations, and every cxx bridge function on the C++ side.
#![no_main]
use ccb_cpp::diff::{Engine, Src};
use ccb_cpp::CppKeyStore;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut r = ccb::software_store();
    let mut c = CppKeyStore::software();
    let mut e = Engine::new(r.as_mut(), &mut c);
    if let Err(d) = e.run(&mut Src::new(data)) {
        panic!("divergence: {d}");
    }
});
