use std::str;

macro_rules! eof {
    ($buf:expr, $i:expr) => (
        if $buf.len() == $i {
            return Ok(Status::Partial);
        }
    )
}
macro_rules! next {
    ($buf:expr, $i:ident) => ({
        let buf = $buf;
        eof!(buf, $i);
        let ret = unsafe { *$buf.get_unchecked($i) };
        $i += 1;
        ret
    })
}

macro_rules! expect {
    ($buf:ident[$i:ident] == $pat:pat => $ret:expr) => {
        match next!($buf, $i) {
            v@$pat => v,
            _ => return $ret
        }
    }
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
macro_rules! is_token {
    ($b:expr) => {
        $b > 0x1F && $b < 0x7F
    }
}

macro_rules! parse {
    ($obj:ident.$field:ident = parse_version ($buf:expr)) => ({
        $obj.$field = match try!(parse_version($buf)) {
            Status::Complete(val) => {
                $buf = $buf.split_at(8).1;
                Some(val)
            },
            Status::Partial => return Ok(Status::Partial)
        }
    });
    ($obj:ident.$field:ident = parse_code ($buf:expr)) => ({
        $obj.$field = match try!(parse_code($buf)) {
            Status::Complete(val) => {
                $buf = $buf.split_at(3).1;
                Some(val)
            },
            Status::Partial => return Ok(Status::Partial)
        }
    });
    ($obj:ident.$field:ident = $action:ident ($buf:expr)) => ({
        $obj.$field = match try!($action($buf)) {
            Status::Complete(val) => {
                $buf = $buf.split_at(val.len()).1;
                Some(val)
            },
            Status::Partial => return Ok(Status::Partial)
        }
    })
}

macro_rules! newline {
    ($buf:ident) => ({
        let mut i = 0;
        eof!($buf, i);
        match next!($buf, i) {
            b'\r' => {
                expect!($buf[i] == b'\n' => Ok(Status::Partial));
                $buf = $buf.split_at(2).1;
            },
            b'\n' => {
                $buf = $buf.split_at(1).1;
            },
            _ => return Err(Error::NewLine)
        }
    })
}


#[derive(Copy, Clone, PartialEq, Debug)]
pub enum Error {
    HeaderName,
    HeaderValue,
    NewLine,
    Status,
    Token,
    TooManyHeaders,
    Version
}

#[derive(Copy, Clone, PartialEq, Debug)]
pub enum Status<T> {
    Complete(T),
    Partial
}

impl<T> Status<T> {
    #[inline]
    pub fn is_complete(&self) -> bool {
        match *self {
            Status::Complete(..) => true,
            Status::Partial => false
        }
    }

    #[inline]
    pub fn is_partial(&self) -> bool {
        match *self {
            Status::Complete(..) => false,
            Status::Partial => true
        }
    }

    #[inline]
    pub fn unwrap(self) -> T {
        match self {
            Status::Complete(t) => t,
            Status::Partial => panic!("Tried to unwrap Status::Partial")
        }
    }
}

pub struct Request<'a> {
    pub method: Option<&'a str>,
    pub path: Option<&'a str>,
    pub version: Option<u8>,
    pub headers: &'a mut [Header<'a>]
}

impl<'a> Request<'a> {
    #[inline]
    pub fn new(headers: &'a mut [Header<'a>]) -> Request<'a> {
        Request {
            method: None,
            path: None,
            version: None,
            headers: headers,
        }
    }

    pub fn parse(&mut self, mut buf: &'a [u8]) -> Result<Status<usize>, Error> {
        let orig_len = buf.len();
        parse!(self.method = parse_token(buf));
        buf = buf.split_at(1).1;
        parse!(self.path = parse_token(buf));
        buf = buf.split_at(1).1;
        parse!(self.version = parse_version(buf));
        newline!(buf);

        let len = orig_len - buf.len();
        let headers_len = match try!(parse_headers(self.headers, buf)) {
            Status::Complete(len) => len,
            Status::Partial => return Ok(Status::Partial)
        };

        Ok(Status::Complete(len + headers_len))
    }
}

pub struct Response<'a> {
    pub version: Option<u8>,
    pub code: Option<u16>,
    pub reason: Option<&'a str>,
    pub headers: &'a mut [Header<'a>]
}

impl<'a> Response<'a> {
    #[inline]
    pub fn new(headers: &'a mut [Header<'a>]) -> Response<'a> {
        Response {
            version: None,
            code: None,
            reason: None,
            headers: headers,
        }
    }

    pub fn parse(&mut self, mut buf: &'a [u8]) -> Result<Status<usize>, Error> {
        let orig_len = buf.len();

        parse!(self.version = parse_version(buf));
        buf = buf.split_at(1).1;
        parse!(self.code = parse_code(buf));
        buf = buf.split_at(1).1;
        parse!(self.reason = parse_token(buf));
        newline!(buf);

        let headers_len = match try!(parse_headers(self.headers, buf)) {
            Status::Complete(len) => len,
            Status::Partial => return Ok(Status::Partial)
        };
        Ok(Status::Complete(orig_len - buf.len() - headers_len))
    }
}

#[derive(Copy, Clone, PartialEq, Debug)]
pub struct Header<'a> {
    pub name: &'a str,
    pub value: &'a [u8],
}


#[inline]
fn parse_version(buf: &[u8]) -> Result<Status<u8>, Error> {
    let mut i = 0;

    expect!(buf[i] == b'H' => Err(Error::Version));
    expect!(buf[i] == b'T' => Err(Error::Version));
    expect!(buf[i] == b'T' => Err(Error::Version));
    expect!(buf[i] == b'P' => Err(Error::Version));
    expect!(buf[i] == b'/' => Err(Error::Version));
    expect!(buf[i] == b'1' => Err(Error::Version));
    expect!(buf[i] == b'.' => Err(Error::Version));
    match next!(buf, i) {
        b'0' => Ok(Status::Complete(0)),
        b'1' => Ok(Status::Complete(1)),
        _ => Err(Error::Version)
    }
}

#[inline]
fn parse_token(buf: &[u8]) -> Result<Status<&str>, Error> {
    let mut i: usize = 0;
    loop {
        let b = next!(buf, i);
        if b == b' ' || b == b'\r' || b == b'\n' {
            return Ok(Status::Complete(unsafe {
                // all bytes up till `i` must have been `is_token`.
                str::from_utf8_unchecked(&buf[..i - 1])
            }));
        } else if !is_token!(b) {
            return Err(Error::Token);
        }
    }
}

#[inline]
fn parse_code(buf: &[u8]) -> Result<Status<u16>, Error> {
    let mut i = 0;
    let hundreds = expect!(buf[i] == b'0'...b'9' => Err(Error::Status));
    let tens = expect!(buf[i] == b'0'...b'9' => Err(Error::Status));
    let ones = expect!(buf[i] == b'0'...b'9' => Err(Error::Status));

    Ok(Status::Complete((hundreds - b'0') as u16 * 100 +
                        (tens - b'0') as u16 * 10 +
                        (ones - b'0') as u16))
}

fn parse_headers<'a>(headers: &mut [Header<'a>], buf: &'a [u8]) -> Result<Status<usize>, Error> {
    let mut i: usize = 0;
    let mut last_i: usize = 0;
    for header in headers {
        // a newline here means the head is over!
        eof!(buf, i);
        let b = unsafe { *buf.get_unchecked(i) };
        if b == b'\r' {
            i += 1;
            expect!(buf[i] == b'\n' => Err(Error::NewLine));
            return Ok(Status::Complete(i));
        } else if b == b'\n' {
            i += 1;
            return Ok(Status::Complete(i));
        }

        // parse header name until colon
        loop {
            let b = next!(buf, i);
            if b == b':' {
                header.name = unsafe {
                    str::from_utf8_unchecked(&buf[last_i..i - 1])
                }; //TODO: remove bounds checks
                break;
            } else if !is_token!(b) {
                return Err(Error::HeaderName);
            }
        }

        // eat white space between colon and value
        loop {
            let b = next!(buf, i);
            if !(b == b' ' || b == b'\t') {
                i -= 1;
                last_i = i;
                break;
            }
        }

        // parse value till EOL
        loop {
            let b = next!(buf, i);
            if !is_token!(b) {
                if b == b'\r' {
                    expect!(buf[i] == b'\n' => Err(Error::HeaderValue));
                    header.value = &buf[last_i..i - 2];
                    break;
                } else if b == b'\n' {
                    header.value = &buf[last_i..i - 1];
                    break;
                } else {
                    return Err(Error::HeaderValue);
                }
                last_i = i;
            }
        }
    }

    Err(Error::TooManyHeaders)
}

#[cfg(test)]
mod tests {
    use super::{Request, Response, Header};

    #[test]
    fn test_request_complete() {
        let mut headers = [Header{ name: "", value: &[] }; 16];
        let mut req = Request::new(&mut headers[]);
        let status = req.parse(b"GET / HTTP/1.1\r\n\r\n").unwrap();
        assert!(status.is_complete());
        assert_eq!(req.method.unwrap(), "GET");
        assert_eq!(req.path.unwrap(), "/");
        assert_eq!(req.version.unwrap(), 1);

        let mut headers = [Header{ name: "", value: &[] }; 16];
        let mut req = Request::new(&mut headers[]);
        let status = req.parse(b"GET / HTTP/1.1\r\nHost: foo.com\r\n\r\n").unwrap();
        assert!(status.is_complete());
        assert_eq!(req.method.unwrap(), "GET");
        assert_eq!(req.path.unwrap(), "/");
        assert_eq!(req.version.unwrap(), 1);
        assert_eq!(req.headers[0].name, "Host");
        assert_eq!(req.headers[0].value, b"foo.com");

    }

    #[test]
    fn test_request_partial() {
        let mut headers = [Header{ name: "", value: &[] }; 16];
        let mut req = Request::new(&mut headers[]);
        assert!(req.parse(b"GET").unwrap().is_partial());
        assert!(req.method.is_none());

        let mut headers = [Header{ name: "", value: &[] }; 16];
        let mut req = Request::new(&mut headers);
        assert!(req.parse(b"GET ").unwrap().is_partial());
        assert_eq!(req.method.unwrap(), "GET");
        assert!(req.path.is_none());
    }

    #[test]
    fn test_response_complete() {
        let mut headers = [Header{ name: "", value: &[] }; 16];
        let mut res = Response::new(&mut headers[]);
        assert!(res.parse(b"HTTP/1.1 200 OK\r\n\r\n").unwrap().is_complete());
        assert_eq!(res.version.unwrap(), 1);
        assert_eq!(res.code.unwrap(), 200);
        assert_eq!(res.reason.unwrap(), "OK");
    }
}
