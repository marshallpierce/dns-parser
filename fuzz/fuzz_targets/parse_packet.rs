#![no_main]

extern crate libfuzzer_sys;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // not panicking is the goal
    let _ = dns_parser::Packet::parse(data);
});
