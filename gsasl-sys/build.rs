#[cfg(feature = "build_bindgen")]
extern crate bindgen;

use std::env;
use std::path::PathBuf;

#[cfg(feature = "build_bindgen")]
fn main() {
    // Compilation preamble
    println!("cargo:rustc-link-lib=gsasl");
    println!("cargo:rerun-if-changed=wrapper.h");

    let bindings = bindgen::Builder::default()
        // Intermediary header including all parts of gsasl we need
        .header("wrapper.h")
        // Make sure cargo re-builds if necessary
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .rustified_non_exhaustive_enum("Gsasl_rc")
        .rustified_non_exhaustive_enum("Gsasl_property")
        .generate()
        .expect("Unable to generate bindgen bindings.");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Unable to write bindgen bindings.");
}

#[cfg(not(feature = "build_bindgen"))]
fn main() { }
