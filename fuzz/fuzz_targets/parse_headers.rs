#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut headers = [httparse::EMPTY_HEADER; 16];
    httparse::parse_headers(data, &mut headers);
});
