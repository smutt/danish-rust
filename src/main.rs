extern crate pcap;
extern crate ctrlc;

use pcap::Device;

fn main() {
    println!("Start");

    ctrlc::set_handler(move || {
        euthanize();
    }).expect("Error setting Ctrl-C handler");

    let mut cap = Device::lookup().unwrap().open().unwrap();

    while let Ok(packet) = cap.next() {
        println!("received packet! {:?}", packet);
    }
    println!("Finish");
}

// Die gracefully
fn euthanize() {
    println!("Ctrl-C exiting");
    std::process::exit(0);
}
