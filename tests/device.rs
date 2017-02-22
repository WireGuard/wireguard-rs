extern crate wireguard;

use wireguard::Device;

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
fn success_dummy_write() {
    // Create a dummy device
    let mut dummy = Device::dummy("test_2").expect("Could not create dummy device");

    // Check the defaults
    assert_eq!(dummy.get_rw_count(), 0);
    assert!(dummy.flush().is_ok());

    // Write to the dummy
    let test_data = b"test string";
    assert!(dummy.write(test_data).is_ok());
    assert_eq!(dummy.get_rw_count(), 1);
    assert!(dummy.flush().is_ok());
}
