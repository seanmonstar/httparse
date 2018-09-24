#![doc(html_root_url = "https://docs.rs/httparse/1.3.2")]
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(test, deny(warnings))]
#![deny(missing_docs)]

//! # httparse
//!
//! A push library for parsing HTTP/1.x requests and responses.
//!
//! The focus is on speed and safety. Unsafe code is used to keep parsing fast,
//! but unsafety is contained in a submodule, with invariants enforced. The
//! parsing internals use an `Iterator` instead of direct indexing, while
//! skipping bounds checks.
//!
//! With Rust 1.27.0 or later, support for SIMD is enabled automatically.
//! If building an executable to be run on multiple platforms, and thus
//! not passing `target_feature` or `target_cpu` flags to the compiler,
//! runtime detection can still detect SSE4.2 or AVX2 support to provide
//! massive wins.
//!
//! If compiling for a specific target, remembering to include
//! `-C target_cpu=native` allows the detection to become compile time checks,
//! making it *even* faster.
#[cfg(feature = "std")]
extern crate std as core;

use core::{fmt, result, str, slice};

use iter::Bytes;

mod iter;
#[macro_use] mod macros;
mod simd;

#[inline]
fn shrink<T>(slice: &mut &mut [T], len: usize) {
    debug_assert!(slice.len() >= len);
    let ptr = slice.as_mut_ptr();
    *slice = unsafe { slice::from_raw_parts_mut(ptr, len) };
}

/// Determines if byte is a token char.
///
/// > ```notrust
/// > token          = 1*tchar
/// >
/// > tchar          = "!" / "#" / "$" / "%" / "&" / "'" / "*"
/// >                / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~"
/// >                / DIGIT / ALPHA
/// >                ; any VCHAR, except delimiters
/// > ```
#[inline]
fn is_token(b: u8) -> bool {
    b > 0x1F && b < 0x7F
}

// ASCII codes to accept URI string.
// i.e. A-Z a-z 0-9 !#$%&'*+-._();:@=,/?[]~^
// TODO: Make a stricter checking for URI string?
static URI_MAP: [bool; 256] = byte_map![
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
//  \0                            \n
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
//  commands
    0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
//  \w !  "  #  $  %  &  '  (  )  *  +  ,  -  .  /
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1,
//  0  1  2  3  4  5  6  7  8  9  :  ;  <  =  >  ?
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
//  @  A  B  C  D  E  F  G  H  I  J  K  L  M  N  O
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1,
//  P  Q  R  S  T  U  V  W  X  Y  Z  [  \  ]  ^  _
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
//  `  a  b  c  d  e  f  g  h  i  j  k  l  m  n  o
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0,
//  p  q  r  s  t  u  v  w  x  y  z  {  |  }  ~  del
//   ====== Extended ASCII (aka. obs-text) ======
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

#[inline]
fn is_uri_token(b: u8) -> bool {
    URI_MAP[b as usize]
}

static HEADER_NAME_MAP: [bool; 256] = byte_map![
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0,
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

#[inline]
fn is_header_name_token(b: u8) -> bool {
    HEADER_NAME_MAP[b as usize]
}

static HEADER_VALUE_MAP: [bool; 256] = byte_map![
    0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
];


#[inline]
fn is_header_value_token(b: u8) -> bool {
    HEADER_VALUE_MAP[b as usize]
}

/// An error in parsing.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// Invalid byte in header name.
    HeaderName,
    /// Invalid byte in header value.
    HeaderValue,
    /// Invalid byte in new line.
    NewLine,
    /// Invalid byte in Response status.
    Status,
    /// Invalid byte where token is required.
    Token,
    /// Parsed more headers than provided buffer can contain.
    TooManyHeaders,
    /// Invalid byte in HTTP version.
    Version,
}

impl Error {
    #[inline]
    fn description_str(&self) -> &'static str {
        match *self {
            Error::HeaderName => "invalid header name",
            Error::HeaderValue => "invalid header value",
            Error::NewLine => "invalid new line",
            Error::Status => "invalid response status",
            Error::Token => "invalid token",
            Error::TooManyHeaders => "too many headers",
            Error::Version => "invalid HTTP version",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.description_str())
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn description(&self) -> &str {
        self.description_str()
    }
}

/// An error in parsing a chunk size.
// Note: Move this into the error enum once v2.0 is released.
#[derive(Debug, PartialEq, Eq)]
pub struct InvalidChunkSize;

impl fmt::Display for InvalidChunkSize {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("invalid chunk size")
    }
}

/// A Result of any parsing action.
///
/// If the input is invalid, an `Error` will be returned. Note that incomplete
/// data is not considered invalid, and so will not return an error, but rather
/// a `Ok(Status::Partial)`.
pub type Result<T> = result::Result<Status<T>, Error>;

/// The result of a successful parse pass.
///
/// `Complete` is used when the buffer contained the complete value.
/// `Partial` is used when parsing did not reach the end of the expected value,
/// but no invalid data was found.
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum Status<T> {
    /// The completed result.
    Complete(T),
    /// A partial result.
    Partial
}

impl<T> Status<T> {
    /// Convenience method to check if status is complete.
    #[inline]
    pub fn is_complete(&self) -> bool {
        match *self {
            Status::Complete(..) => true,
            Status::Partial => false
        }
    }

    /// Convenience method to check if status is partial.
    #[inline]
    pub fn is_partial(&self) -> bool {
        match *self {
            Status::Complete(..) => false,
            Status::Partial => true
        }
    }

    /// Convenience method to unwrap a Complete value. Panics if the status is
    /// `Partial`.
    #[inline]
    pub fn unwrap(self) -> T {
        match self {
            Status::Complete(t) => t,
            Status::Partial => panic!("Tried to unwrap Status::Partial")
        }
    }
}

/// A parsed Request.
///
/// The optional values will be `None` if a parse was not complete, and did not
/// parse the associated property. This allows you to inspect the parts that
/// could be parsed, before reading more, in case you wish to exit early.
///
/// # Example
///
/// ```no_run
/// let buf = b"GET /404 HTTP/1.1\r\nHost:";
/// let mut headers = [httparse::EMPTY_HEADER; 16];
/// let mut req = httparse::Request::new(&mut headers);
/// let res = req.parse(buf).unwrap();
/// if res.is_partial() {
///     match req.path {
///         Some(ref path) => {
///             // check router for path.
///             // /404 doesn't exist? we could stop parsing
///         },
///         None => {
///             // must read more and parse again
///         }
///     }
/// }
/// ```
#[derive(Debug, PartialEq)]
pub struct Request<'headers, 'buf: 'headers> {
    /// The request method, such as `GET`.
    pub method: Option<&'buf str>,
    /// The request path, such as `/about-us`.
    pub path: Option<&'buf str>,
    /// The request version, such as `HTTP/1.1`.
    pub version: Option<u8>,
    /// The request headers.
    pub headers: &'headers mut [Header<'buf>]
}

impl<'h, 'b> Request<'h, 'b> {
    /// Creates a new Request, using a slice of headers you allocate.
    #[inline]
    pub fn new(headers: &'h mut [Header<'b>]) -> Request<'h, 'b> {
        Request {
            method: None,
            path: None,
            version: None,
            headers: headers,
        }
    }

    /// Try to parse a buffer of bytes into the Request.
    pub fn parse(&mut self, buf: &'b [u8]) -> Result<usize> {
        let orig_len = buf.len();
        let mut bytes = Bytes::new(buf);
        complete!(skip_empty_lines(&mut bytes));
        self.method = Some(complete!(parse_token(&mut bytes)));
        self.path = Some(complete!(parse_uri(&mut bytes)));
        self.version = Some(complete!(parse_version(&mut bytes)));
        newline!(bytes);

        let len = orig_len - bytes.len();
        let headers_len = complete!(parse_headers_iter(&mut self.headers, &mut bytes));

        Ok(Status::Complete(len + headers_len))
    }
}

#[inline]
fn skip_empty_lines(bytes: &mut Bytes) -> Result<()> {
    loop {
        let b = bytes.peek();
        match b {
            Some(b'\r') => {
                // there's `\r`, so it's safe to bump 1 pos
                unsafe { bytes.bump() };
                expect!(bytes.next() == b'\n' => Err(Error::NewLine));
            },
            Some(b'\n') => {
                // there's `\n`, so it's safe to bump 1 pos
                unsafe { bytes.bump(); }
            },
            Some(..) => {
                bytes.slice();
                return Ok(Status::Complete(()));
            },
            None => return Ok(Status::Partial)
        }
    }
}

/// A parsed Response.
///
/// See `Request` docs for explanation of optional values.
#[derive(Debug, PartialEq)]
pub struct Response<'headers, 'buf: 'headers> {
    /// The response version, such as `HTTP/1.1`.
    pub version: Option<u8>,
    /// The response code, such as `200`.
    pub code: Option<u16>,
    /// The response reason-phrase, such as `OK`.
    pub reason: Option<&'buf str>,
    /// The response headers.
    pub headers: &'headers mut [Header<'buf>]
}

impl<'h, 'b> Response<'h, 'b> {
    /// Creates a new `Response` using a slice of `Header`s you have allocated.
    #[inline]
    pub fn new(headers: &'h mut [Header<'b>]) -> Response<'h, 'b> {
        Response {
            version: None,
            code: None,
            reason: None,
            headers: headers,
        }
    }

    /// Try to parse a buffer of bytes into this `Response`.
    pub fn parse(&mut self, buf: &'b [u8]) -> Result<usize> {
        let orig_len = buf.len();
        let mut bytes = Bytes::new(buf);

        complete!(skip_empty_lines(&mut bytes));
        self.version = Some(complete!(parse_version(&mut bytes)));
        space!(bytes or Error::Version);
        self.code = Some(complete!(parse_code(&mut bytes)));

        // RFC7230 says there must be 'SP' and then reason-phrase, but admits
        // its only for legacy reasons. With the reason-phrase completely
        // optional (and preferred to be omitted) in HTTP2, we'll just
        // handle any response that doesn't include a reason-phrase, because
        // it's more lenient, and we don't care anyways.
        //
        // So, a SP means parse a reason-phrase.
        // A newline means go to headers.
        // Anything else we'll say is a malformed status.
        match next!(bytes) {
            b' ' => {
                bytes.slice();
                self.reason = Some(complete!(parse_reason(&mut bytes)));
            },
            b'\r' => {
                expect!(bytes.next() == b'\n' => Err(Error::Status));
                bytes.slice();
                self.reason = Some("");
            },
            b'\n' => self.reason = Some(""),
            _ => return Err(Error::Status),
        }


        let len = orig_len - bytes.len();
        let headers_len = complete!(parse_headers_iter(&mut self.headers, &mut bytes));
        Ok(Status::Complete(len + headers_len))
    }
}

/// Represents a parsed header.
#[derive(Copy, Clone, PartialEq, Debug)]
pub struct Header<'a> {
    /// The name portion of a header.
    ///
    /// A header name must be valid ASCII-US, so it's safe to store as a `&str`.
    pub name: &'a str,
    /// The value portion of a header.
    ///
    /// While headers **should** be ASCII-US, the specification allows for
    /// values that may not be, and so the value is stored as bytes.
    pub value: &'a [u8],
}

/// An empty header, useful for constructing a `Header` array to pass in for
/// parsing.
///
/// # Example
///
/// ```
/// let headers = [httparse::EMPTY_HEADER; 64];
/// ```
pub const EMPTY_HEADER: Header<'static> = Header { name: "", value: b"" };

#[inline]
fn parse_version(bytes: &mut Bytes) -> Result<u8> {
    if let Some(mut eight) = bytes.next_8() {
        expect!(eight._0() => b'H' |? Err(Error::Version));
        expect!(eight._1() => b'T' |? Err(Error::Version));
        expect!(eight._2() => b'T' |? Err(Error::Version));
        expect!(eight._3() => b'P' |? Err(Error::Version));
        expect!(eight._4() => b'/' |? Err(Error::Version));
        expect!(eight._5() => b'1' |? Err(Error::Version));
        expect!(eight._6() => b'.' |? Err(Error::Version));
        let v = match eight._7() {
            b'0' => 0,
            b'1' => 1,
            _ => return Err(Error::Version)
        };
        return Ok(Status::Complete(v))
    }

    // else (but not in `else` because of borrow checker)

    // If there aren't at least 8 bytes, we still want to detect early
    // if this is a valid version or not. If it is, we'll return Partial.
    expect!(bytes.next() == b'H' => Err(Error::Version));
    expect!(bytes.next() == b'T' => Err(Error::Version));
    expect!(bytes.next() == b'T' => Err(Error::Version));
    expect!(bytes.next() == b'P' => Err(Error::Version));
    expect!(bytes.next() == b'/' => Err(Error::Version));
    expect!(bytes.next() == b'1' => Err(Error::Version));
    expect!(bytes.next() == b'.' => Err(Error::Version));
    Ok(Status::Partial)
}

/// From [RFC 7230](https://tools.ietf.org/html/rfc7230):
///
/// > ```notrust
/// > reason-phrase  = *( HTAB / SP / VCHAR / obs-text )
/// > HTAB           = %x09        ; horizontal tab
/// > VCHAR          = %x21-7E     ; visible (printing) characters
/// > obs-text       = %x80-FF
/// > ```
///
/// > A.2.  Changes from RFC 2616
/// >
/// > Non-US-ASCII content in header fields and the reason phrase
/// > has been obsoleted and made opaque (the TEXT rule was removed).
///
/// Note that the following implementation deliberately rejects the obsoleted (non-US-ASCII) text range.
///
/// The fully compliant parser should probably just return the reason-phrase as an opaque &[u8] data
/// and leave interpretation to user or specialized helpers (akin to .display() in std::path::Path)
#[inline]
fn parse_reason<'a>(bytes: &mut Bytes<'a>) -> Result<&'a str> {
    loop {
        let b = next!(bytes);
        if b == b'\r' {
            expect!(bytes.next() == b'\n' => Err(Error::Status));
            return Ok(Status::Complete(unsafe {
                // all bytes up till `i` must have been HTAB / SP / VCHAR
                str::from_utf8_unchecked(bytes.slice_skip(2))
            }));
        } else if b == b'\n' {
            return Ok(Status::Complete(unsafe {
                // all bytes up till `i` must have been HTAB / SP / VCHAR
                str::from_utf8_unchecked(bytes.slice_skip(1))
            }));
        } else if !((b >= 0x20 && b <= 0x7E) || b == b'\t') {
            return Err(Error::Status);
        }
    }
}

#[inline]
fn parse_token<'a>(bytes: &mut Bytes<'a>) -> Result<&'a str> {
    loop {
        let b = next!(bytes);
        if b == b' ' {
            return Ok(Status::Complete(unsafe {
                // all bytes up till `i` must have been `is_token`.
                str::from_utf8_unchecked(bytes.slice_skip(1))
            }));
        } else if !is_token(b) {
            return Err(Error::Token);
        }
    }
}

#[inline]
fn parse_uri<'a>(bytes: &mut Bytes<'a>) -> Result<&'a str> {
    simd::match_uri_vectored(bytes);

    loop {
        let b = next!(bytes);
        if b == b' ' {
            return Ok(Status::Complete(unsafe {
                // all bytes up till `i` must have been `is_token`.
                str::from_utf8_unchecked(bytes.slice_skip(1))
            }));
        } else if !is_uri_token(b) {
            return Err(Error::Token);
        }
    }
}


#[inline]
fn parse_code(bytes: &mut Bytes) -> Result<u16> {
    let hundreds = expect!(bytes.next() == b'0'...b'9' => Err(Error::Status));
    let tens = expect!(bytes.next() == b'0'...b'9' => Err(Error::Status));
    let ones = expect!(bytes.next() == b'0'...b'9' => Err(Error::Status));

    Ok(Status::Complete((hundreds - b'0') as u16 * 100 +
        (tens - b'0') as u16 * 10 +
        (ones - b'0') as u16))
}

/// Parse a buffer of bytes as headers.
///
/// The return value, if complete and successful, includes the index of the
/// buffer that parsing stopped at, and a sliced reference to the parsed
/// headers. The length of the slice will be equal to the number of properly
/// parsed headers.
///
/// # Example
///
/// ```
/// let buf = b"Host: foo.bar\nAccept: */*\n\nblah blah";
/// let mut headers = [httparse::EMPTY_HEADER; 4];
/// assert_eq!(httparse::parse_headers(buf, &mut headers),
///            Ok(httparse::Status::Complete((27, &[
///                httparse::Header { name: "Host", value: b"foo.bar" },
///                httparse::Header { name: "Accept", value: b"*/*" }
///            ][..]))));
/// ```
pub fn parse_headers<'b: 'h, 'h>(src: &'b [u8], mut dst: &'h mut [Header<'b>])
    -> Result<(usize, &'h [Header<'b>])> {
    let mut iter = Bytes::new(src);
    let pos = complete!(parse_headers_iter(&mut dst, &mut iter));
    Ok(Status::Complete((pos, dst)))
}

/*
#[cfg(not(any(
    feature = "httparse_simd",
    target_arch = "x86",
    target_arch = "x86_64",
    target_feature = "sse4.2"
)))]
*/


#[inline]
fn parse_headers_iter<'a, 'b>(headers: &mut &mut [Header<'a>], bytes: &'b mut Bytes<'a>)
    -> Result<usize> {
    let mut num_headers: usize = 0;
    let mut count: usize = 0;
    let mut result = Err(Error::TooManyHeaders);

    {
        let mut iter = headers.iter_mut();

        'headers: loop {
            // a newline here means the head is over!
            let b = next!(bytes);
            if b == b'\r' {
                expect!(bytes.next() == b'\n' => Err(Error::NewLine));
                result = Ok(Status::Complete(count + bytes.pos()));
                break;
            } else if b == b'\n' {
                result = Ok(Status::Complete(count + bytes.pos()));
                break;
            } else if !is_header_name_token(b) {
                return Err(Error::HeaderName);
            }

            let header = match iter.next() {
                Some(header) => header,
                None => break 'headers
            };

            num_headers += 1;
            // parse header name until colon
            'name: loop {
                let b = next!(bytes);
                if b == b':' {
                    count += bytes.pos();
                    header.name = unsafe {
                        str::from_utf8_unchecked(bytes.slice_skip(1))
                    };
                    break 'name;
                } else if !is_header_name_token(b) {
                    return Err(Error::HeaderName);
                }
            }

            let mut b;

            'value: loop {

                // eat white space between colon and value
                'whitespace: loop {
                    b = next!(bytes);
                    if b == b' ' || b == b'\t' {
                        count += bytes.pos();
                        bytes.slice();
                        continue 'whitespace;
                    } else {
                        if !is_header_value_token(b) {
                            break 'value;
                        }
                        break 'whitespace;
                    }
                }

                // parse value till EOL

                simd::match_header_value_vectored(bytes);

                macro_rules! check {
                    ($bytes:ident, $i:ident) => ({
                        b = $bytes.$i();
                        if !is_header_value_token(b) {
                            break 'value;
                        }
                    });
                    ($bytes:ident) => ({
                        check!($bytes, _0);
                        check!($bytes, _1);
                        check!($bytes, _2);
                        check!($bytes, _3);
                        check!($bytes, _4);
                        check!($bytes, _5);
                        check!($bytes, _6);
                        check!($bytes, _7);
                    })
                }
                while let Some(mut bytes8) = bytes.next_8() {
                    check!(bytes8);
                }
                loop {
                    b = next!(bytes);
                    if !is_header_value_token(b) {
                        break 'value;
                    }
                }
            }

            //found_ctl
            if b == b'\r' {
                expect!(bytes.next() == b'\n' => Err(Error::HeaderValue));
                count += bytes.pos();
                // having just check that `\r\n` exists, it's safe to skip those 2 bytes
                unsafe {
                    header.value = bytes.slice_skip(2);
                }
            } else if b == b'\n' {
                count += bytes.pos();
                // having just check that `\r\n` exists, it's safe to skip 1 byte
                unsafe {
                    header.value = bytes.slice_skip(1);
                }
            } else {
                return Err(Error::HeaderValue);
            }
        }
    } // drop iter

    shrink(headers, num_headers);
    result
}

/// Parse a buffer of bytes as a chunk size.
///
/// The return value, if complete and successful, includes the index of the
/// buffer that parsing stopped at, and the size of the following chunk.
///
/// # Example
///
/// ```
/// let buf = b"4\r\nRust\r\n0\r\n\r\n";
/// assert_eq!(httparse::parse_chunk_size(buf),
///            Ok(httparse::Status::Complete((3, 4))));
/// ```
pub fn parse_chunk_size(buf: &[u8])
    -> result::Result<Status<(usize, u64)>, InvalidChunkSize> {
    const RADIX: u64 = 16;
    let mut bytes = Bytes::new(buf);
    let mut size = 0;
    let mut in_chunk_size = true;
    let mut in_ext = false;
    let mut count = 0;
    loop {
        let b = next!(bytes);
        match b {
            b'0' ... b'9' if in_chunk_size => {
                if count > 15 {
                    return Err(InvalidChunkSize);
                }
                count += 1;
                size *= RADIX;
                size += (b - b'0') as u64;
            },
            b'a' ... b'f' if in_chunk_size => {
                if count > 15 {
                    return Err(InvalidChunkSize);
                }
                count += 1;
                size *= RADIX;
                size += (b + 10 - b'a') as u64;
            }
            b'A' ... b'F' if in_chunk_size => {
                if count > 15 {
                    return Err(InvalidChunkSize);
                }
                count += 1;
                size *= RADIX;
                size += (b + 10 - b'A') as u64;
            }
            b'\r' => {
                match next!(bytes) {
                    b'\n' => break,
                    _ => return Err(InvalidChunkSize),
                }
            }
            // If we weren't in the extension yet, the ";" signals its start
            b';' if !in_ext => {
                in_ext = true;
                in_chunk_size = false;
            }
            // "Linear white space" is ignored between the chunk size and the
            // extension separator token (";") due to the "implied *LWS rule".
            b'\t' | b' ' if !in_ext & !in_chunk_size => {}
            // LWS can follow the chunk size, but no more digits can come
            b'\t' | b' ' if in_chunk_size => in_chunk_size = false,
            // We allow any arbitrary octet once we are in the extension, since
            // they all get ignored anyway. According to the HTTP spec, valid
            // extensions would have a more strict syntax:
            //     (token ["=" (token | quoted-string)])
            // but we gain nothing by rejecting an otherwise valid chunk size.
            _ if in_ext => {}
            // Finally, if we aren't in the extension and we're reading any
            // other octet, the chunk size line is invalid!
            _ => return Err(InvalidChunkSize),
        }
    }
    Ok(Status::Complete((bytes.pos(), size)))
}

#[cfg(test)]
mod tests {
    use super::{Request, Response, Status, EMPTY_HEADER, shrink, parse_chunk_size};

    const NUM_OF_HEADERS: usize = 4;

    #[test]
    fn test_shrink() {
        let mut arr = [EMPTY_HEADER; 16];
        {
            let slice = &mut &mut arr[..];
            assert_eq!(slice.len(), 16);
            shrink(slice, 4);
            assert_eq!(slice.len(), 4);
        }
        assert_eq!(arr.len(), 16);
    }

    macro_rules! req {
        ($name:ident, $buf:expr, |$arg:ident| $body:expr) => (
            req! {$name, $buf, Ok(Status::Complete($buf.len())), |$arg| $body }
        );
        ($name:ident, $buf:expr, $len:expr, |$arg:ident| $body:expr) => (
        #[test]
        fn $name() {
            let mut headers = [EMPTY_HEADER; NUM_OF_HEADERS];
            let mut req = Request::new(&mut headers[..]);
            let status = req.parse($buf.as_ref());
            assert_eq!(status, $len);
            closure(req);

            fn closure($arg: Request) {
                $body
            }
        }
        )
    }

    req! {
        test_request_simple,
        b"GET / HTTP/1.1\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 0);
        }
    }

    req! {
        test_request_simple_with_query_params,
        b"GET /thing?data=a HTTP/1.1\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/thing?data=a");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 0);
        }
    }

    req! {
        test_request_simple_with_whatwg_query_params,
        b"GET /thing?data=a^ HTTP/1.1\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/thing?data=a^");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 0);
        }
    }

    req! {
        test_request_headers,
        b"GET / HTTP/1.1\r\nHost: foo.com\r\nCookie: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 2);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"foo.com");
            assert_eq!(req.headers[1].name, "Cookie");
            assert_eq!(req.headers[1].value, b"");
        }
    }

    req! {
        // test the scalar parsing
        test_request_header_value_htab_short,
        b"GET / HTTP/1.1\r\nUser-Agent: some\tagent\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "User-Agent");
            assert_eq!(req.headers[0].value, b"some\tagent");
        }
    }

    req! {
        // test the sse42 parsing
        test_request_header_value_htab_med,
        b"GET / HTTP/1.1\r\nUser-Agent: 1234567890some\tagent\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "User-Agent");
            assert_eq!(req.headers[0].value, b"1234567890some\tagent");
        }
    }

    req! {
        // test the avx2 parsing
        test_request_header_value_htab_long,
        b"GET / HTTP/1.1\r\nUser-Agent: 1234567890some\t1234567890agent1234567890\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "User-Agent");
            assert_eq!(req.headers[0].value, &b"1234567890some\t1234567890agent1234567890"[..]);
        }
    }

    req! {
        test_request_headers_max,
        b"GET / HTTP/1.1\r\nA: A\r\nB: B\r\nC: C\r\nD: D\r\n\r\n",
        |req| {
            assert_eq!(req.headers.len(), NUM_OF_HEADERS);
        }
    }

    req! {
        test_request_multibyte,
        b"GET / HTTP/1.1\r\nHost: foo.com\r\nUser-Agent: \xe3\x81\xb2\xe3/1.0\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"foo.com");
            assert_eq!(req.headers[1].name, "User-Agent");
            assert_eq!(req.headers[1].value, b"\xe3\x81\xb2\xe3/1.0");
        }
    }


    req! {
        test_request_partial,
        b"GET / HTTP/1.1\r\n\r", Ok(Status::Partial),
        |_req| {}
    }

    req! {
        test_request_partial_version,
        b"GET / HTTP/1.", Ok(Status::Partial),
        |_req| {}
    }

    req! {
        test_request_newlines,
        b"GET / HTTP/1.1\nHost: foo.bar\n\n",
        |_r| {}
    }

    req! {
        test_request_empty_lines_prefix,
        b"\r\n\r\nGET / HTTP/1.1\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 0);
        }
    }

    req! {
        test_request_empty_lines_prefix_lf_only,
        b"\n\nGET / HTTP/1.1\n\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 0);
        }
    }

    req! {
        test_request_with_invalid_token_delimiter,
        b"GET\n/ HTTP/1.1\r\nHost: foo.bar\r\n\r\n",
        Err(::Error::Token),
        |_r| {}
    }


    req! {
        test_request_with_invalid_but_short_version,
        b"GET / HTTP/1!",
        Err(::Error::Version),
        |_r| {}
    }


    req! {
        urltest_1,
        b"GET /bar;par?b HTTP/1.1\r\nHost: foo\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/bar;par?b");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"foo");
        }
    }


    req! {
        urltest_2,
        b"GET /x HTTP/1.1\r\nHost: test\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/x");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"test");
        }
    }


    req! {
        urltest_3,
        b"GET /x HTTP/1.1\r\nHost: test\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/x");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"test");
        }
    }


    req! {
        urltest_4,
        b"GET /foo/foo.com HTTP/1.1\r\nHost: example.org\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foo/foo.com");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.org");
        }
    }


    req! {
        urltest_5,
        b"GET /foo/:foo.com HTTP/1.1\r\nHost: example.org\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foo/:foo.com");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.org");
        }
    }


    req! {
        urltest_6,
        b"GET /foo/foo.com HTTP/1.1\r\nHost: example.org\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foo/foo.com");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.org");
        }
    }


    req! {
        urltest_7,
        b"GET  foo.com HTTP/1.1\r\nHost: \r\n\r\n",
        Err(::Error::Version),
        |_r| {}
    }


    req! {
        urltest_8,
        b"GET /%20b%20?%20d%20 HTTP/1.1\r\nHost: f\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/%20b%20?%20d%20");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"f");
        }
    }


    req! {
        urltest_9,
        b"GET x x HTTP/1.1\r\nHost: \r\n\r\n",
        Err(::Error::Version),
        |_r| {}
    }


    req! {
        urltest_10,
        b"GET /c HTTP/1.1\r\nHost: f\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/c");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"f");
        }
    }


    req! {
        urltest_11,
        b"GET /c HTTP/1.1\r\nHost: f\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/c");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"f");
        }
    }


    req! {
        urltest_12,
        b"GET /c HTTP/1.1\r\nHost: f\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/c");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"f");
        }
    }


    req! {
        urltest_13,
        b"GET /c HTTP/1.1\r\nHost: f\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/c");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"f");
        }
    }


    req! {
        urltest_14,
        b"GET /c HTTP/1.1\r\nHost: f\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/c");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"f");
        }
    }


    req! {
        urltest_15,
        b"GET /foo/bar HTTP/1.1\r\nHost: example.org\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foo/bar");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.org");
        }
    }


    req! {
        urltest_16,
        b"GET /foo/bar HTTP/1.1\r\nHost: example.org\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foo/bar");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.org");
        }
    }


    req! {
        urltest_17,
        b"GET /foo/:foo.com/ HTTP/1.1\r\nHost: example.org\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foo/:foo.com/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.org");
        }
    }


    req! {
        urltest_18,
        b"GET /foo/:foo.com/ HTTP/1.1\r\nHost: example.org\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foo/:foo.com/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.org");
        }
    }


    req! {
        urltest_19,
        b"GET /foo/: HTTP/1.1\r\nHost: example.org\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foo/:");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.org");
        }
    }


    req! {
        urltest_20,
        b"GET /foo/:a HTTP/1.1\r\nHost: example.org\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foo/:a");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.org");
        }
    }


    req! {
        urltest_21,
        b"GET /foo/:/ HTTP/1.1\r\nHost: example.org\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foo/:/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.org");
        }
    }


    req! {
        urltest_22,
        b"GET /foo/:/ HTTP/1.1\r\nHost: example.org\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foo/:/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.org");
        }
    }


    req! {
        urltest_23,
        b"GET /foo/: HTTP/1.1\r\nHost: example.org\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foo/:");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.org");
        }
    }


    req! {
        urltest_24,
        b"GET /foo/bar HTTP/1.1\r\nHost: example.org\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foo/bar");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.org");
        }
    }


    req! {
        urltest_25,
        b"GET /foo/bar HTTP/1.1\r\nHost: example.org\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foo/bar");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.org");
        }
    }


    req! {
        urltest_26,
        b"GET /foo/bar HTTP/1.1\r\nHost: example.org\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foo/bar");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.org");
        }
    }


    req! {
        urltest_27,
        b"GET /foo/bar HTTP/1.1\r\nHost: example.org\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foo/bar");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.org");
        }
    }


    req! {
        urltest_28,
        b"GET /foo/bar HTTP/1.1\r\nHost: example.org\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foo/bar");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.org");
        }
    }


    req! {
        urltest_29,
        b"GET /foo/:23 HTTP/1.1\r\nHost: example.org\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foo/:23");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.org");
        }
    }


    req! {
        urltest_30,
        b"GET /:23 HTTP/1.1\r\nHost: example.org\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/:23");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.org");
        }
    }


    req! {
        urltest_31,
        b"GET /foo/:: HTTP/1.1\r\nHost: example.org\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foo/::");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.org");
        }
    }


    req! {
        urltest_32,
        b"GET /foo/::23 HTTP/1.1\r\nHost: example.org\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foo/::23");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.org");
        }
    }


    req! {
        urltest_33,
        b"GET /d HTTP/1.1\r\nHost: c\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/d");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"c");
        }
    }


    req! {
        urltest_34,
        b"GET /foo/:@c:29 HTTP/1.1\r\nHost: example.org\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foo/:@c:29");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.org");
        }
    }


    req! {
        urltest_35,
        b"GET //@ HTTP/1.1\r\nHost: foo.com\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "//@");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"foo.com");
        }
    }


    req! {
        urltest_36,
        b"GET /b:c/d@foo.com/ HTTP/1.1\r\nHost: a\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/b:c/d@foo.com/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"a");
        }
    }


    req! {
        urltest_37,
        b"GET /bar.com/ HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/bar.com/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_38,
        b"GET /////// HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "///////");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_39,
        b"GET ///////bar.com/ HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "///////bar.com/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_40,
        b"GET //:///// HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "//://///");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_41,
        b"GET /foo HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foo");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_42,
        b"GET /bar HTTP/1.1\r\nHost: foo\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/bar");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"foo");
        }
    }


    req! {
        urltest_43,
        b"GET /path;a??e HTTP/1.1\r\nHost: foo\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/path;a??e");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"foo");
        }
    }


    req! {
        urltest_44,
        b"GET /abcd?efgh?ijkl HTTP/1.1\r\nHost: foo\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/abcd?efgh?ijkl");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"foo");
        }
    }


    req! {
        urltest_45,
        b"GET /abcd HTTP/1.1\r\nHost: foo\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/abcd");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"foo");
        }
    }


    req! {
        urltest_46,
        b"GET /foo/[61:24:74]:98 HTTP/1.1\r\nHost: example.org\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foo/[61:24:74]:98");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.org");
        }
    }


    req! {
        urltest_47,
        b"GET /foo/[61:27]/:foo HTTP/1.1\r\nHost: example.org\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foo/[61:27]/:foo");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.org");
        }
    }


    req! {
        urltest_48,
        b"GET /example.com/ HTTP/1.1\r\nHost: example.org\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/example.com/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.org");
        }
    }


    req! {
        urltest_49,
        b"GET /example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/example.com/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_50,
        b"GET /example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/example.com/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_51,
        b"GET /example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/example.com/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_52,
        b"GET /example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/example.com/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_53,
        b"GET /example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/example.com/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_54,
        b"GET /example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/example.com/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_55,
        b"GET /foo/example.com/ HTTP/1.1\r\nHost: example.org\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foo/example.com/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.org");
        }
    }


    req! {
        urltest_56,
        b"GET example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "example.com/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_57,
        b"GET example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "example.com/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_58,
        b"GET example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "example.com/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_59,
        b"GET example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "example.com/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_60,
        b"GET example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "example.com/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_61,
        b"GET /a/b/c HTTP/1.1\r\nHost: example.org\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/a/b/c");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.org");
        }
    }


    req! {
        urltest_62,
        b"GET /a/%20/c HTTP/1.1\r\nHost: example.org\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/a/%20/c");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.org");
        }
    }


    req! {
        urltest_63,
        b"GET /a%2fc HTTP/1.1\r\nHost: example.org\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/a%2fc");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.org");
        }
    }


    req! {
        urltest_64,
        b"GET /a/%2f/c HTTP/1.1\r\nHost: example.org\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/a/%2f/c");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.org");
        }
    }


    req! {
        urltest_65,
        b"GET /foo/bar HTTP/1.1\r\nHost: example.org\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foo/bar");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.org");
        }
    }


    req! {
        urltest_66,
        b"GET text/html,test HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "text/html,test");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_67,
        b"GET 1234567890 HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "1234567890");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_68,
        b"GET /c:/foo/bar.html HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/c:/foo/bar.html");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_69,
        b"GET /c:////foo/bar.html HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/c:////foo/bar.html");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_70,
        b"GET /C:/foo/bar HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/C:/foo/bar");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_71,
        b"GET /C:/foo/bar HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/C:/foo/bar");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_72,
        b"GET /C:/foo/bar HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/C:/foo/bar");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_73,
        b"GET /file HTTP/1.1\r\nHost: server\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/file");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"server");
        }
    }


    req! {
        urltest_74,
        b"GET /file HTTP/1.1\r\nHost: server\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/file");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"server");
        }
    }


    req! {
        urltest_75,
        b"GET /file HTTP/1.1\r\nHost: server\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/file");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"server");
        }
    }


    req! {
        urltest_76,
        b"GET /foo/bar.txt HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foo/bar.txt");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_77,
        b"GET /home/me HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/home/me");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_78,
        b"GET /test HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/test");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_79,
        b"GET /test HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/test");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_80,
        b"GET /tmp/mock/test HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/tmp/mock/test");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_81,
        b"GET /tmp/mock/test HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/tmp/mock/test");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_82,
        b"GET /foo HTTP/1.1\r\nHost: example.com\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foo");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.com");
        }
    }


    req! {
        urltest_83,
        b"GET /.foo HTTP/1.1\r\nHost: example.com\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/.foo");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.com");
        }
    }


    req! {
        urltest_84,
        b"GET /foo/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foo/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.com");
        }
    }


    req! {
        urltest_85,
        b"GET /foo/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foo/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.com");
        }
    }


    req! {
        urltest_86,
        b"GET /foo/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foo/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.com");
        }
    }


    req! {
        urltest_87,
        b"GET /foo/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foo/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.com");
        }
    }


    req! {
        urltest_88,
        b"GET /foo/..bar HTTP/1.1\r\nHost: example.com\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foo/..bar");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.com");
        }
    }


    req! {
        urltest_89,
        b"GET /foo/ton HTTP/1.1\r\nHost: example.com\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foo/ton");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.com");
        }
    }


    req! {
        urltest_90,
        b"GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/a");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.com");
        }
    }


    req! {
        urltest_91,
        b"GET /ton HTTP/1.1\r\nHost: example.com\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/ton");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.com");
        }
    }


    req! {
        urltest_92,
        b"GET /foo/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foo/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.com");
        }
    }


    req! {
        urltest_93,
        b"GET /foo/%2e%2 HTTP/1.1\r\nHost: example.com\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foo/%2e%2");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.com");
        }
    }


    req! {
        urltest_94,
        b"GET /%2e.bar HTTP/1.1\r\nHost: example.com\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/%2e.bar");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.com");
        }
    }


    req! {
        urltest_95,
        b"GET // HTTP/1.1\r\nHost: example.com\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "//");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.com");
        }
    }


    req! {
        urltest_96,
        b"GET /foo/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foo/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.com");
        }
    }


    req! {
        urltest_97,
        b"GET /foo/bar/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foo/bar/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.com");
        }
    }


    req! {
        urltest_98,
        b"GET /foo HTTP/1.1\r\nHost: example.com\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foo");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.com");
        }
    }


    req! {
        urltest_99,
        b"GET /%20foo HTTP/1.1\r\nHost: example.com\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/%20foo");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.com");
        }
    }


    req! {
        urltest_100,
        b"GET /foo% HTTP/1.1\r\nHost: example.com\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foo%");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.com");
        }
    }


    req! {
        urltest_101,
        b"GET /foo%2 HTTP/1.1\r\nHost: example.com\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foo%2");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.com");
        }
    }


    req! {
        urltest_102,
        b"GET /foo%2zbar HTTP/1.1\r\nHost: example.com\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foo%2zbar");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.com");
        }
    }


    req! {
        urltest_103,
        b"GET /foo%2%C3%82%C2%A9zbar HTTP/1.1\r\nHost: example.com\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foo%2%C3%82%C2%A9zbar");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.com");
        }
    }


    req! {
        urltest_104,
        b"GET /foo%41%7a HTTP/1.1\r\nHost: example.com\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foo%41%7a");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.com");
        }
    }


    req! {
        urltest_105,
        b"GET /foo%C2%91%91 HTTP/1.1\r\nHost: example.com\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foo%C2%91%91");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.com");
        }
    }


    req! {
        urltest_106,
        b"GET /foo%00%51 HTTP/1.1\r\nHost: example.com\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foo%00%51");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.com");
        }
    }


    req! {
        urltest_107,
        b"GET /(%28:%3A%29) HTTP/1.1\r\nHost: example.com\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/(%28:%3A%29)");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.com");
        }
    }


    req! {
        urltest_108,
        b"GET /%3A%3a%3C%3c HTTP/1.1\r\nHost: example.com\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/%3A%3a%3C%3c");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.com");
        }
    }


    req! {
        urltest_109,
        b"GET /foobar HTTP/1.1\r\nHost: example.com\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foobar");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.com");
        }
    }


    req! {
        urltest_110,
        b"GET //foo//bar HTTP/1.1\r\nHost: example.com\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "//foo//bar");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.com");
        }
    }


    req! {
        urltest_111,
        b"GET /%7Ffp3%3Eju%3Dduvgw%3Dd HTTP/1.1\r\nHost: example.com\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/%7Ffp3%3Eju%3Dduvgw%3Dd");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.com");
        }
    }


    req! {
        urltest_112,
        b"GET /@asdf%40 HTTP/1.1\r\nHost: example.com\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/@asdf%40");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.com");
        }
    }


    req! {
        urltest_113,
        b"GET /%E4%BD%A0%E5%A5%BD%E4%BD%A0%E5%A5%BD HTTP/1.1\r\nHost: example.com\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/%E4%BD%A0%E5%A5%BD%E4%BD%A0%E5%A5%BD");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.com");
        }
    }


    req! {
        urltest_114,
        b"GET /%E2%80%A5/foo HTTP/1.1\r\nHost: example.com\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/%E2%80%A5/foo");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.com");
        }
    }


    req! {
        urltest_115,
        b"GET /%EF%BB%BF/foo HTTP/1.1\r\nHost: example.com\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/%EF%BB%BF/foo");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.com");
        }
    }


    req! {
        urltest_116,
        b"GET /%E2%80%AE/foo/%E2%80%AD/bar HTTP/1.1\r\nHost: example.com\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/%E2%80%AE/foo/%E2%80%AD/bar");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.com");
        }
    }


    req! {
        urltest_117,
        b"GET /foo?bar=baz HTTP/1.1\r\nHost: www.google.com\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foo?bar=baz");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"www.google.com");
        }
    }


    req! {
        urltest_118,
        b"GET /foo?bar=baz HTTP/1.1\r\nHost: www.google.com\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foo?bar=baz");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"www.google.com");
        }
    }


    req! {
        urltest_119,
        b"GET test HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "test");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_120,
        b"GET /foo%2Ehtml HTTP/1.1\r\nHost: www\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foo%2Ehtml");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"www");
        }
    }


    req! {
        urltest_121,
        b"GET /foo/html HTTP/1.1\r\nHost: www\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foo/html");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"www");
        }
    }


    req! {
        urltest_122,
        b"GET /foo HTTP/1.1\r\nHost: www.google.com\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foo");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"www.google.com");
        }
    }


    req! {
        urltest_123,
        b"GET /example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/example.com/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_124,
        b"GET /example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/example.com/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_125,
        b"GET /example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/example.com/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_126,
        b"GET /example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/example.com/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_127,
        b"GET /example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/example.com/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_128,
        b"GET /example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/example.com/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_129,
        b"GET example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "example.com/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_130,
        b"GET example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "example.com/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_131,
        b"GET example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "example.com/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_132,
        b"GET example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "example.com/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_133,
        b"GET example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "example.com/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_134,
        b"GET /test.txt HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/test.txt");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"www.example.com");
        }
    }


    req! {
        urltest_135,
        b"GET /test.txt HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/test.txt");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"www.example.com");
        }
    }


    req! {
        urltest_136,
        b"GET /test.txt HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/test.txt");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"www.example.com");
        }
    }


    req! {
        urltest_137,
        b"GET /test.txt HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/test.txt");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"www.example.com");
        }
    }


    req! {
        urltest_138,
        b"GET /aaa/test.txt HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/aaa/test.txt");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"www.example.com");
        }
    }


    req! {
        urltest_139,
        b"GET /test.txt HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/test.txt");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"www.example.com");
        }
    }


    req! {
        urltest_140,
        b"GET /%E4%B8%AD/test.txt HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/%E4%B8%AD/test.txt");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"www.example.com");
        }
    }


    req! {
        urltest_141,
        b"GET /... HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/...");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_142,
        b"GET /a HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/a");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_143,
        b"GET /%EF%BF%BD?%EF%BF%BD HTTP/1.1\r\nHost: x\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/%EF%BF%BD?%EF%BF%BD");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"x");
        }
    }


    req! {
        urltest_144,
        b"GET /bar HTTP/1.1\r\nHost: example.com\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/bar");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.com");
        }
    }


    req! {
        urltest_145,
        b"GET test HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "test");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_146,
        b"GET x@x.com HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "x@x.com");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_147,
        b"GET , HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), ",");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_148,
        b"GET blank HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "blank");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_149,
        b"GET test?test HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "test?test");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_150,
        b"GET /%60%7B%7D?`{} HTTP/1.1\r\nHost: h\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/%60%7B%7D?`{}");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"h");
        }

    }


    req! {
        urltest_151,
        b"GET /?%27 HTTP/1.1\r\nHost: host\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/?%27");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"host");
        }
    }


    req! {
        urltest_152,
        b"GET /?' HTTP/1.1\r\nHost: host\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/?'");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"host");
        }
    }


    req! {
        urltest_153,
        b"GET /some/path HTTP/1.1\r\nHost: example.org\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/some/path");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.org");
        }
    }


    req! {
        urltest_154,
        b"GET /smth HTTP/1.1\r\nHost: example.org\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/smth");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.org");
        }
    }


    req! {
        urltest_155,
        b"GET /some/path HTTP/1.1\r\nHost: example.org\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/some/path");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.org");
        }
    }


    req! {
        urltest_156,
        b"GET /pa/i HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/pa/i");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_157,
        b"GET /i HTTP/1.1\r\nHost: ho\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/i");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"ho");
        }
    }


    req! {
        urltest_158,
        b"GET /pa/i HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/pa/i");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_159,
        b"GET /i HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/i");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_160,
        b"GET /i HTTP/1.1\r\nHost: ho\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/i");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"ho");
        }
    }


    req! {
        urltest_161,
        b"GET /i HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/i");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_162,
        b"GET /i HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/i");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_163,
        b"GET /i HTTP/1.1\r\nHost: ho\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/i");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"ho");
        }
    }


    req! {
        urltest_164,
        b"GET /i HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/i");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_165,
        b"GET /pa/pa?i HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/pa/pa?i");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_166,
        b"GET /pa?i HTTP/1.1\r\nHost: ho\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/pa?i");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"ho");
        }
    }


    req! {
        urltest_167,
        b"GET /pa/pa?i HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/pa/pa?i");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_168,
        b"GET sd HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "sd");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_169,
        b"GET sd/sd HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "sd/sd");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_170,
        b"GET /pa/pa HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/pa/pa");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_171,
        b"GET /pa HTTP/1.1\r\nHost: ho\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/pa");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"ho");
        }
    }


    req! {
        urltest_172,
        b"GET /pa/pa HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/pa/pa");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_173,
        b"GET /x HTTP/1.1\r\nHost: %C3%B1\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/x");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"%C3%B1");
        }
    }


    req! {
        urltest_174,
        b"GET \\.\\./ HTTP/1.1\r\nHost: \r\n\r\n",
        Err(::Error::Token),
        |_r| {}
    }


    req! {
        urltest_175,
        b"GET :a@example.net HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), ":a@example.net");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_176,
        b"GET %NBD HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "%NBD");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_177,
        b"GET %1G HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "%1G");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_178,
        b"GET /relative_import.html HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/relative_import.html");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"127.0.0.1");
        }
    }


    req! {
        urltest_179,
        b"GET /?foo=%7B%22abc%22 HTTP/1.1\r\nHost: facebook.com\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/?foo=%7B%22abc%22");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"facebook.com");
        }
    }


    req! {
        urltest_180,
        b"GET /jqueryui@1.2.3 HTTP/1.1\r\nHost: localhost\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/jqueryui@1.2.3");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"localhost");
        }
    }


    req! {
        urltest_181,
        b"GET /path?query HTTP/1.1\r\nHost: host\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/path?query");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"host");
        }
    }


    req! {
        urltest_182,
        b"GET /foo/bar?a=b&c=d HTTP/1.1\r\nHost: example.org\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foo/bar?a=b&c=d");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.org");
        }
    }


    req! {
        urltest_183,
        b"GET /foo/bar??a=b&c=d HTTP/1.1\r\nHost: example.org\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foo/bar??a=b&c=d");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.org");
        }
    }


    req! {
        urltest_184,
        b"GET /foo/bar HTTP/1.1\r\nHost: example.org\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foo/bar");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.org");
        }
    }


    req! {
        urltest_185,
        b"GET /baz?qux HTTP/1.1\r\nHost: foo.bar\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/baz?qux");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"foo.bar");
        }
    }


    req! {
        urltest_186,
        b"GET /baz?qux HTTP/1.1\r\nHost: foo.bar\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/baz?qux");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"foo.bar");
        }
    }


    req! {
        urltest_187,
        b"GET /baz?qux HTTP/1.1\r\nHost: foo.bar\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/baz?qux");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"foo.bar");
        }
    }


    req! {
        urltest_188,
        b"GET /baz?qux HTTP/1.1\r\nHost: foo.bar\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/baz?qux");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"foo.bar");
        }
    }


    req! {
        urltest_189,
        b"GET /baz?qux HTTP/1.1\r\nHost: foo.bar\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/baz?qux");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"foo.bar");
        }
    }


    req! {
        urltest_190,
        b"GET /C%3A/ HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/C%3A/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_191,
        b"GET /C%7C/ HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/C%7C/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_192,
        b"GET /C:/Users/Domenic/Dropbox/GitHub/tmpvar/jsdom/test/level2/html/files/pix/submit.gif HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/C:/Users/Domenic/Dropbox/GitHub/tmpvar/jsdom/test/level2/html/files/pix/submit.gif");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_193,
        b"GET /C:/ HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/C:/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_194,
        b"GET /C:/ HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/C:/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_195,
        b"GET /d: HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/d:");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_196,
        b"GET /d:/ HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/d:/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_197,
        b"GET /test?test HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/test?test");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_198,
        b"GET /test?test HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/test?test");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_199,
        b"GET /test?x HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/test?x");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_200,
        b"GET /test?x HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/test?x");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_201,
        b"GET /test?test HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/test?test");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_202,
        b"GET /test?test HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/test?test");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_203,
        b"GET /?fox HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/?fox");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_204,
        b"GET /localhost//cat HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/localhost//cat");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_205,
        b"GET /localhost//cat HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/localhost//cat");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_206,
        b"GET /mouse HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/mouse");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_207,
        b"GET /pig HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/pig");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_208,
        b"GET /pig HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/pig");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_209,
        b"GET /pig HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/pig");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_210,
        b"GET /localhost//pig HTTP/1.1\r\nHost: lion\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/localhost//pig");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"lion");
        }
    }


    req! {
        urltest_211,
        b"GET /rooibos HTTP/1.1\r\nHost: tea\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/rooibos");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"tea");
        }
    }


    req! {
        urltest_212,
        b"GET /?chai HTTP/1.1\r\nHost: tea\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/?chai");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"tea");
        }
    }


    req! {
        urltest_213,
        b"GET /C: HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/C:");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_214,
        b"GET /C: HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/C:");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_215,
        b"GET /C: HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/C:");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_216,
        b"GET /C:/ HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/C:/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_217,
        b"GET /C:/ HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/C:/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_218,
        b"GET /C:/ HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/C:/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_219,
        b"GET /dir/C HTTP/1.1\r\nHost: host\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/dir/C");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"host");
        }
    }


    req! {
        urltest_220,
        b"GET /dir/C|a HTTP/1.1\r\nHost: host\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/dir/C|a");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"host");
        }
    }


    req! {
        urltest_221,
        b"GET /c:/foo/bar HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/c:/foo/bar");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_222,
        b"GET /c:/foo/bar HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/c:/foo/bar");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_223,
        b"GET /c:/foo/bar HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/c:/foo/bar");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_224,
        b"GET /c:/foo/bar HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/c:/foo/bar");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_225,
        b"GET /C:/ HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/C:/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_226,
        b"GET /C:/ HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/C:/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_227,
        b"GET /C:/ HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/C:/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_228,
        b"GET /C:/ HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/C:/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_229,
        b"GET /C:/ HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/C:/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_230,
        b"GET /?q=v HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/?q=v");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_231,
        b"GET ?x HTTP/1.1\r\nHost: %C3%B1\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "?x");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"%C3%B1");
        }
    }


    req! {
        urltest_232,
        b"GET ?x HTTP/1.1\r\nHost: %C3%B1\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "?x");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"%C3%B1");
        }
    }


    req! {
        urltest_233,
        b"GET // HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "//");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_234,
        b"GET //x/ HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "//x/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_235,
        b"GET /someconfig;mode=netascii HTTP/1.1\r\nHost: foobar.com\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/someconfig;mode=netascii");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"foobar.com");
        }
    }


    req! {
        urltest_236,
        b"GET /Index.ut2 HTTP/1.1\r\nHost: 10.10.10.10\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/Index.ut2");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"10.10.10.10");
        }
    }


    req! {
        urltest_237,
        b"GET /0?baz=bam&qux=baz HTTP/1.1\r\nHost: somehost\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/0?baz=bam&qux=baz");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"somehost");
        }
    }


    req! {
        urltest_238,
        b"GET /sup HTTP/1.1\r\nHost: host\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/sup");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"host");
        }
    }


    req! {
        urltest_239,
        b"GET /foo/bar.git HTTP/1.1\r\nHost: github.com\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foo/bar.git");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"github.com");
        }
    }


    req! {
        urltest_240,
        b"GET /channel?passwd HTTP/1.1\r\nHost: myserver.com\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/channel?passwd");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"myserver.com");
        }
    }


    req! {
        urltest_241,
        b"GET /foo.bar.org?type=TXT HTTP/1.1\r\nHost: fw.example.org\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foo.bar.org?type=TXT");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"fw.example.org");
        }
    }


    req! {
        urltest_242,
        b"GET /ou=People,o=JNDITutorial HTTP/1.1\r\nHost: localhost\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/ou=People,o=JNDITutorial");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"localhost");
        }
    }


    req! {
        urltest_243,
        b"GET /foo/bar HTTP/1.1\r\nHost: github.com\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/foo/bar");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"github.com");
        }
    }


    req! {
        urltest_244,
        b"GET ietf:rfc:2648 HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "ietf:rfc:2648");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_245,
        b"GET joe@example.org,2001:foo/bar HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "joe@example.org,2001:foo/bar");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_246,
        b"GET /path HTTP/1.1\r\nHost: H%4fSt\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/path");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"H%4fSt");
        }
    }


    req! {
        urltest_247,
        b"GET https://example.com:443/ HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "https://example.com:443/");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_248,
        b"GET d3958f5c-0777-0845-9dcf-2cb28783acaf HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "d3958f5c-0777-0845-9dcf-2cb28783acaf");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_249,
        b"GET /test?%22 HTTP/1.1\r\nHost: example.org\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/test?%22");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.org");
        }
    }


    req! {
        urltest_250,
        b"GET /test HTTP/1.1\r\nHost: example.org\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/test");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.org");
        }
    }


    req! {
        urltest_251,
        b"GET /test?%3C HTTP/1.1\r\nHost: example.org\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/test?%3C");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.org");
        }
    }


    req! {
        urltest_252,
        b"GET /test?%3E HTTP/1.1\r\nHost: example.org\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/test?%3E");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.org");
        }
    }


    req! {
        urltest_253,
        b"GET /test?%E2%8C%A3 HTTP/1.1\r\nHost: example.org\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/test?%E2%8C%A3");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.org");
        }
    }


    req! {
        urltest_254,
        b"GET /test?%23%23 HTTP/1.1\r\nHost: example.org\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/test?%23%23");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.org");
        }
    }


    req! {
        urltest_255,
        b"GET /test?%GH HTTP/1.1\r\nHost: example.org\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/test?%GH");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.org");
        }
    }


    req! {
        urltest_256,
        b"GET /test?a HTTP/1.1\r\nHost: example.org\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/test?a");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.org");
        }
    }


    req! {
        urltest_257,
        b"GET /test?a HTTP/1.1\r\nHost: example.org\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/test?a");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.org");
        }
    }


    req! {
        urltest_258,
        b"GET /test-a-colon-slash.html HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/test-a-colon-slash.html");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_259,
        b"GET /test-a-colon-slash-slash.html HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/test-a-colon-slash-slash.html");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_260,
        b"GET /test-a-colon-slash-b.html HTTP/1.1\r\nHost: \r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/test-a-colon-slash-b.html");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"");
        }
    }


    req! {
        urltest_261,
        b"GET /test-a-colon-slash-slash-b.html HTTP/1.1\r\nHost: b\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/test-a-colon-slash-slash-b.html");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"b");
        }
    }


    req! {
        urltest_262,
        b"GET /test?a HTTP/1.1\r\nHost: example.org\r\n\r\n",
        |req| {
            assert_eq!(req.method.unwrap(), "GET");
            assert_eq!(req.path.unwrap(), "/test?a");
            assert_eq!(req.version.unwrap(), 1);
            assert_eq!(req.headers.len(), 1);
            assert_eq!(req.headers[0].name, "Host");
            assert_eq!(req.headers[0].value, b"example.org");
        }
    }



    macro_rules! res {
        ($name:ident, $buf:expr, |$arg:ident| $body:expr) => (
            res! {$name, $buf, Ok(Status::Complete($buf.len())), |$arg| $body }
        );
        ($name:ident, $buf:expr, $len:expr, |$arg:ident| $body:expr) => (
        #[test]
        fn $name() {
            let mut headers = [EMPTY_HEADER; NUM_OF_HEADERS];
            let mut res = Response::new(&mut headers[..]);
            let status = res.parse($buf.as_ref());
            assert_eq!(status, $len);
            closure(res);

            fn closure($arg: Response) {
                $body
            }
        }
        )
    }

    res! {
        test_response_simple,
        b"HTTP/1.1 200 OK\r\n\r\n",
        |res| {
            assert_eq!(res.version.unwrap(), 1);
            assert_eq!(res.code.unwrap(), 200);
            assert_eq!(res.reason.unwrap(), "OK");
        }
    }

    res! {
        test_response_newlines,
        b"HTTP/1.0 403 Forbidden\nServer: foo.bar\n\n",
        |_r| {}
    }

    res! {
        test_response_reason_missing,
        b"HTTP/1.1 200 \r\n\r\n",
        |res| {
            assert_eq!(res.version.unwrap(), 1);
            assert_eq!(res.code.unwrap(), 200);
            assert_eq!(res.reason.unwrap(), "");
        }
    }

    res! {
        test_response_reason_missing_no_space,
        b"HTTP/1.1 200\r\n\r\n",
        |res| {
            assert_eq!(res.version.unwrap(), 1);
            assert_eq!(res.code.unwrap(), 200);
            assert_eq!(res.reason.unwrap(), "");
        }
    }

    res! {
        test_response_reason_missing_no_space_with_headers,
        b"HTTP/1.1 200\r\nFoo: bar\r\n\r\n",
        |res| {
            assert_eq!(res.version.unwrap(), 1);
            assert_eq!(res.code.unwrap(), 200);
            assert_eq!(res.reason.unwrap(), "");
            assert_eq!(res.headers.len(), 1);
            assert_eq!(res.headers[0].name, "Foo");
            assert_eq!(res.headers[0].value, b"bar");
        }
    }

    res! {
        test_response_reason_with_space_and_tab,
        b"HTTP/1.1 101 Switching Protocols\t\r\n\r\n",
        |res| {
            assert_eq!(res.version.unwrap(), 1);
            assert_eq!(res.code.unwrap(), 101);
            assert_eq!(res.reason.unwrap(), "Switching Protocols\t");
        }
    }

    static RESPONSE_REASON_WITH_OBS_TEXT_BYTE: &'static [u8] = b"HTTP/1.1 200 X\xFFZ\r\n\r\n";
    res! {
        test_response_reason_with_obsolete_text_byte,
        RESPONSE_REASON_WITH_OBS_TEXT_BYTE,
        Err(::Error::Status),
        |_res| {}
    }

    res! {
        test_response_reason_with_nul_byte,
        b"HTTP/1.1 200 \x00\r\n\r\n",
        Err(::Error::Status),
        |_res| {}
    }

    res! {
        test_response_version_missing_space,
        b"HTTP/1.1",
        Ok(Status::Partial),
        |_res| {}
    }

    res! {
        test_response_code_missing_space,
        b"HTTP/1.1 200",
        Ok(Status::Partial),
        |_res| {}
    }

    res! {
        test_response_empty_lines_prefix_lf_only,
        b"\n\nHTTP/1.1 200 OK\n\n",
        |_res| {}
    }

    #[test]
    fn test_chunk_size() {
        assert_eq!(parse_chunk_size(b"0\r\n"), Ok(Status::Complete((3, 0))));
        assert_eq!(parse_chunk_size(b"12\r\nchunk"), Ok(Status::Complete((4, 18))));
        assert_eq!(parse_chunk_size(b"3086d\r\n"), Ok(Status::Complete((7, 198765))));
        assert_eq!(parse_chunk_size(b"3735AB1;foo bar*\r\n"), Ok(Status::Complete((18, 57891505))));
        assert_eq!(parse_chunk_size(b"3735ab1 ; baz \r\n"), Ok(Status::Complete((16, 57891505))));
        assert_eq!(parse_chunk_size(b"77a65\r"), Ok(Status::Partial));
        assert_eq!(parse_chunk_size(b"ab"), Ok(Status::Partial));
        assert_eq!(parse_chunk_size(b"567f8a\rfoo"), Err(::InvalidChunkSize));
        assert_eq!(parse_chunk_size(b"567f8a\rfoo"), Err(::InvalidChunkSize));
        assert_eq!(parse_chunk_size(b"567xf8a\r\n"), Err(::InvalidChunkSize));
        assert_eq!(parse_chunk_size(b"ffffffffffffffff\r\n"), Ok(Status::Complete((18, ::core::u64::MAX))));
        assert_eq!(parse_chunk_size(b"1ffffffffffffffff\r\n"), Err(::InvalidChunkSize));
        assert_eq!(parse_chunk_size(b"Affffffffffffffff\r\n"), Err(::InvalidChunkSize));
        assert_eq!(parse_chunk_size(b"fffffffffffffffff\r\n"), Err(::InvalidChunkSize));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_std_error() {
        use super::Error;
        use std::error::Error as StdError;
        let err = Error::HeaderName;
        assert_eq!(err.to_string(), err.description());
    }
}
