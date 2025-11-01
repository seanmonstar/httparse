mod swar;

#[cfg(any(
    httparse_disable_simd,
    miri,
    not(feature = "std"),
    not(any(
        target_arch = "x86",
        target_arch = "x86_64",
        all(
            target_arch = "aarch64",
            target_feature = "neon",
        )
    ))
))]
pub use self::swar::*;

#[cfg(all(
    not(any(httparse_disable_simd, miri)),
    feature = "std",
    not(target_feature = "avx2"),
    any(
        target_arch = "x86",
        target_arch = "x86_64",
    ),
))]
mod sse42;

#[cfg(all(
    not(any(httparse_disable_simd, miri)),
    feature = "std",
    any(
        target_feature = "avx2",
        not(target_feature = "sse4.2"),
    ),
    any(
        target_arch = "x86",
        target_arch = "x86_64",
    ),
))]
mod avx2;

#[cfg(all(
    not(any(httparse_disable_simd, miri)),
    feature = "std",
    not(any(
        target_feature = "sse4.2",
        target_feature = "avx2",
    )),
    any(
        target_arch = "x86",
        target_arch = "x86_64",
    ),
))]
mod runtime;

#[cfg(all(
    not(any(httparse_disable_simd, miri)),
    feature = "std",
    not(any(
        target_feature = "sse4.2",
        target_feature = "avx2",
    )),
    any(
        target_arch = "x86",
        target_arch = "x86_64",
    ),
))]
pub use self::runtime::*;

#[cfg(all(
    not(any(httparse_disable_simd, miri)),
    feature = "std",
    target_feature = "sse4.2",
    not(target_feature = "avx2"),
    any(
        target_arch = "x86",
        target_arch = "x86_64",
    ),
))]
mod sse42_compile_time {
    #[inline(always)]
    pub fn match_header_name_vectored(b: &mut crate::iter::Bytes<'_>) {
        super::swar::match_header_name_vectored(b);
    }

    #[inline(always)]
    pub fn match_uri_vectored(b: &mut crate::iter::Bytes<'_>) {
        unsafe { super::sse42::match_uri_vectored(b) }
    }

    #[inline(always)]
    pub fn match_header_value_vectored(b: &mut crate::iter::Bytes<'_>) {
        unsafe { super::sse42::match_header_value_vectored(b) }
    }
}

#[cfg(all(
    not(any(httparse_disable_simd, miri)),
    feature = "std",
    target_feature = "sse4.2",
    not(target_feature = "avx2"),
    any(
        target_arch = "x86",
        target_arch = "x86_64",
    ),
))]
pub use self::sse42_compile_time::*;

#[cfg(all(
    not(any(httparse_disable_simd, miri)),
    feature = "std",
    target_feature = "avx2",
    any(
        target_arch = "x86",
        target_arch = "x86_64",
    ),
))]
mod avx2_compile_time {
    #[inline(always)]
    pub fn match_header_name_vectored(b: &mut crate::iter::Bytes<'_>) {
        super::swar::match_header_name_vectored(b);
    }

    #[inline(always)]
    pub fn match_uri_vectored(b: &mut crate::iter::Bytes<'_>) {
        unsafe { super::avx2::match_uri_vectored(b) }
    }

    #[inline(always)]
    pub fn match_header_value_vectored(b: &mut crate::iter::Bytes<'_>) {
        unsafe { super::avx2::match_header_value_vectored(b) }
    }
}

#[cfg(all(
    not(any(httparse_disable_simd, miri)),
    feature = "std",
    target_feature = "avx2",
    any(
        target_arch = "x86",
        target_arch = "x86_64",
    ),
))]
pub use self::avx2_compile_time::*;

#[cfg(all(
    not(any(httparse_disable_simd, miri)),
    feature = "std",
    target_arch = "aarch64",
    target_feature = "neon",
))]
mod neon;

#[cfg(all(
    not(any(httparse_disable_simd, miri)),
    feature = "std",
    target_arch = "aarch64",
    target_feature = "neon",
))]
pub use self::neon::*;
