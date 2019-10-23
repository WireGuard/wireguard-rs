use super::wireguard::Wireguard;
use super::{bind, dummy, tun};

use std::thread;
use std::time::Duration;

fn init() {
    let _ = env_logger::builder().is_test(true).try_init();
}

/* Create and configure two matching pure instances of WireGuard
 *
 */
#[test]
fn test_pure_wireguard() {
    init();

    // create WG instances for fake TUN devices

    let (fake1, tun_reader1, tun_writer1, mtu1) = dummy::TunTest::create(1500, true);
    let wg1: Wireguard<dummy::TunTest, dummy::PairBind> =
        Wireguard::new(vec![tun_reader1], tun_writer1, mtu1);

    let (fake2, tun_reader2, tun_writer2, mtu2) = dummy::TunTest::create(1500, true);
    let wg2: Wireguard<dummy::TunTest, dummy::PairBind> =
        Wireguard::new(vec![tun_reader2], tun_writer2, mtu2);

    // create pair bind to connect the interfaces "over the internet"

    let ((bind_reader1, bind_writer1), (bind_reader2, bind_writer2)) = dummy::PairBind::pair();

    wg1.set_writer(bind_writer1);
    wg2.set_writer(bind_writer2);

    wg1.add_reader(bind_reader1);
    wg2.add_reader(bind_reader2);

    // generate (public, pivate) key pairs

    // configure cryptkey router

    // create IP packets

    thread::sleep(Duration::from_millis(500));
}
