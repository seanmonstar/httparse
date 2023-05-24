#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut resp = httparse::Request::new(&mut headers);
    let _ = httparse::ParserConfig::default()
        .allow_multiple_spaces_in_request_line_delimiters(true)
        .parse_request(&mut resp, data);
});
