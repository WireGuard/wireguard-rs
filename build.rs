extern crate bindgen;

use bindgen::Builder;

use std::env;
use std::fs::File;
use std::io::Write;
use std::error::Error;
use std::path::PathBuf;

static HEADERS: &[&str] = &["net/if.h", "linux/if_tun.h", "sys/ioctl.h"];

fn main() {
    run().expect("Could not execute build script.");
}

fn run() -> Result<(), Box<Error>> {
    // Create a wrapper header file
    let out_path = PathBuf::from(env::var("OUT_DIR")?);
    let wrapper_path = out_path.join("wrapper.h");
    let mut wrapper = File::create(&wrapper_path)?;
    for header in HEADERS {
        writeln!(wrapper, "#include <{}>", header)?;
    }

    // Generate the bindungs
    let wrapper_path_str = wrapper_path.to_str().expect("Wrapper include path corrupt.");
    let bindings = Builder::default()
        .no_unstable_rust()
        .generate_comments(true)
        .hide_type("pthread_mutex_t")
        .header(wrapper_path_str)
        .generate()
        .expect("Unable to generate bindings");

    // Write the bindungs to the output directory
    bindings.write_to_file(out_path.join("bindings.rs"))?;
    Ok(())
}
