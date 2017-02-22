extern crate wireguard;

use wireguard::Device;

use std::io::Write;
use std::fs::OpenOptions;

#[test]
fn success_dummy() {
    // Create a dummy device
    let name = "test_1";
    let dummy = Device::dummy(name).expect("Could not create dummy device");

    // Check the defaults
    assert!(dummy.is_dummy());
    assert_eq!(dummy.get_name(), name);
    assert_eq!(dummy.get_rw_count(), 0);
    println!("Dummy: {:?}", dummy);
}

#[test]
fn success_read_write() {
    // Create a dummy device and reset it
    let mut dummy = Device::dummy("test_2").expect("Could not create dummy device");
    dummy.get_fd().set_len(0).expect("Could not reset dummy file");

    // Check the defaults
    assert_eq!(dummy.get_rw_count(), 0);
    assert!(dummy.flush().is_ok());

    // Write to the dummy
    let test_data = b"test string";
    assert!(dummy.write(test_data).is_ok());
    assert_eq!(dummy.get_rw_count(), 1);
    assert!(dummy.flush().is_ok());

    // Write from outside to the dummy
    let mut file = OpenOptions::new().append(true).open(dummy.get_path()).expect("Could not open dummy device file");
    file.write(test_data).expect("Could not write to file via file descriptor");

    // Read from the dummy
    let mut buffer = vec![0; 100];
    assert_eq!(dummy.read(&mut buffer).expect("Could not read from dummy device"), test_data.len());
    assert_eq!(&buffer[..test_data.len()], test_data);
    assert_eq!(dummy.get_rw_count(), 2);
    assert!(dummy.flush().is_ok());
}
