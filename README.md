# httparse

[![Build Status](https://travis-ci.org/seanmonstar/httparse.svg?branch=master)](https://travis-ci.org/seanmonstar/httparse)

A push parser for the HTTP 1.x protocol. Avoids allocations. Fast.

## Usage

```rust
let mut headers = [httparse::EMPTY_HEADER; 16];
let mut req = httparse::Request::new(&mut headers);

let buf = b"GET /index.html HTTP/1.1\r\nHost";
assert!(try!(req.parse(buf)).is_partial());

// a partial request, so we try again once we have more data

let buf = b"GET /index.html HTTP/1.1\r\nHost: example.domain\r\n\r\n";
assert!(try!(req.parse(buf)).is_complete());
```

## License

MIT
