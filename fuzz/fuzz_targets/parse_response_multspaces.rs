#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut resp = httparse::Response::new(&mut headers);
    let _ = httparse::ParserConfig::default()
        .allow_multiple_spaces_in_response_status_delimiters(true)
        .parse_response(&mut resp, data);
});
