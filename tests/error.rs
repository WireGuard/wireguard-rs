extern crate wireguard;

use wireguard::WgError;
use std::error::Error;
use std::fmt::Write;
use std::io;

static TEST_STR: &'static str = "Some error message";

#[test]
fn success_convert_wg_from_io_error() {
    let io_error = io::Error::new(io::ErrorKind::NotFound, TEST_STR);
    let wg_error: WgError = io_error.into();
    assert_eq!(wg_error.description(), TEST_STR.to_string());
    assert_eq!(wg_error.kind(), io::ErrorKind::Other);
}

#[test]
fn success_convert_io_from_wg_error() {
    let wg_error = WgError::new(TEST_STR);
    let io_error: io::Error = wg_error.into();
    assert_eq!(io_error.description(), TEST_STR.to_string());
    assert_eq!(io_error.kind(), io::ErrorKind::Other);
}

#[test]
fn success_wg_error_display_debug() {
    let error = WgError::new(TEST_STR);
    let mut string = String::new();

    write!(string, "{}", error).unwrap();
    assert_eq!(string, TEST_STR);
    string.clear();

    write!(string, "{:?}", error).unwrap();
    assert_eq!(string, TEST_STR);
}
