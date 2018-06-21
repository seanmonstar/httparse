#[cfg(not(all(
    httparse_simd,
    any(
        target_arch = "x86",
        target_arch = "x86_64",
    ),
)))]
mod fallback;

#[cfg(not(all(
    httparse_simd,
    any(
        target_arch = "x86",
        target_arch = "x86_64",
    ),
)))]
pub use self::fallback::*;

#[cfg(all(
    httparse_simd,
    any(
        target_arch = "x86",
        target_arch = "x86_64",
    ),
))]
mod sse42;

#[cfg(all(
    httparse_simd,
    any(
        target_arch = "x86",
        target_arch = "x86_64",
    ),
))]
mod avx2;

#[cfg(all(
    httparse_simd,
    any(
        target_arch = "x86",
        target_arch = "x86_64",
    ),
))]
mod vector {
    pub fn match_uri_vectored(bytes: &mut ::Bytes) {
        if is_x86_feature_detected!("avx2") {
            unsafe {
                super::avx2::parse_uri_batch_32(bytes);
            }

        } else if is_x86_feature_detected!("sse4.2") {
            unsafe {
                super::sse42::parse_uri_batch_16(bytes);
            }
        }

        // else do nothing
    }

    pub fn match_header_value_vectored(bytes: &mut ::Bytes) {
        if is_x86_feature_detected!("avx2") {
            unsafe {
                super::avx2::match_header_value_batch_32(bytes);
            }
        } else if is_x86_feature_detected!("sse4.2") {
            unsafe {
                super::sse42::match_header_value_batch_16(bytes);
            }
        }

        // else do nothing
    }
}

#[cfg(all(
    httparse_simd,
    any(
        target_arch = "x86",
        target_arch = "x86_64",
    ),
))]
pub use self::vector::*;
