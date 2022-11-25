///! Utility macros

macro_rules! next {
    ($bytes:ident) => ({
        match $bytes.next() {
            Some(b) => b,
            None => return Ok(Status::Partial)
        }
    })
}

macro_rules! expect {
    ($bytes:ident.next() == $pat:pat => $ret:expr) => {
        expect!(next!($bytes) => $pat |? $ret)
    };
    ($e:expr => $pat:pat |? $ret:expr) => {
        match $e {
            v@$pat => v,
            _ => return $ret
        }
    };
}

#[cfg(feature = "icap")]
macro_rules! expect2 {
    ($bytes:ident.next() == $pat:pat|$pat2:pat => $ret:expr) => {
        expect2!(next!($bytes) => $pat|$pat2 |? $ret)
    };
    ($e:expr => $pat:pat|$pat2:pat |? $ret:expr) => {
        match $e {
            v@$pat => v,
            v@$pat2 => v,
            _ => return $ret
        }
    };
}

macro_rules! complete {
    ($e:expr) => {
        match $e? {
            Status::Complete(v) => v,
            Status::Partial => return Ok(Status::Partial)
        }
    }
}

macro_rules! byte_map {
    ($($flag:expr,)*) => ([
        $($flag != 0,)*
    ])
}

macro_rules! space {
    ($bytes:ident or $err:expr) => ({
        expect!($bytes.next() == b' ' => Err($err));
        $bytes.slice();
    })
}

macro_rules! newline {
    ($bytes:ident) => ({
        match next!($bytes) {
            b'\r' => {
                expect!($bytes.next() == b'\n' => Err(Error::NewLine));
                $bytes.slice();
            },
            b'\n' => {
                $bytes.slice();
            },
            _ => return Err(Error::NewLine)
        }
    })
}
