mod swar;

#[cfg(not(all(
    httparse_simd,
    any(
        target_arch = "x86",
        target_arch = "x86_64",
        all(
            target_arch = "aarch64",
            httparse_simd_neon_intrinsics,
        )
    ),
)))]
pub(crate) use self::swar::*;

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
        httparse_simd_target_feature_avx2,
        not(httparse_simd_target_feature_sse42),
    ),
    any(
        target_arch = "x86",
        target_arch = "x86_64",
    ),
))]
mod avx2;

#[cfg(all(
    httparse_simd,
    not(any(
        httparse_simd_target_feature_sse42,
        httparse_simd_target_feature_avx2,
    )),
    any(
        target_arch = "x86",
        target_arch = "x86_64",
    ),
))]
mod runtime;

#[cfg(all(
    httparse_simd,
    not(any(
        httparse_simd_target_feature_sse42,
        httparse_simd_target_feature_avx2,
    )),
    any(
        target_arch = "x86",
        target_arch = "x86_64",
    ),
))]
pub(crate) use self::runtime::*;

#[cfg(all(
    httparse_simd,
    httparse_simd_target_feature_sse42,
    not(httparse_simd_target_feature_avx2),
    any(
        target_arch = "x86",
        target_arch = "x86_64",
    ),
))]
mod sse42_compile_time {
    #[inline(always)]
    pub(crate) fn match_header_name_vectored(b: &[u8]) -> usize {
        super::swar::match_header_name_vectored(b)
    }

    #[inline(always)]
    pub(crate) fn match_uri_vectored(b: &[u8]) -> usize {
        // SAFETY: calls are guarded by a compile time feature check
        unsafe { crate::simd::sse42::match_uri_vectored(b) }
    }

    #[inline(always)]
    pub(crate) fn match_header_value_vectored(b: &[u8]) -> usize {
        // SAFETY: calls are guarded by a compile time feature check
        unsafe { crate::simd::sse42::match_header_value_vectored(b) }
    }
}

#[cfg(all(
    httparse_simd,
    httparse_simd_target_feature_sse42,
    not(httparse_simd_target_feature_avx2),
    any(
        target_arch = "x86",
        target_arch = "x86_64",
    ),
))]
pub(crate) use self::sse42_compile_time::*;

#[cfg(all(
    httparse_simd,
    httparse_simd_target_feature_avx2,
    any(
        target_arch = "x86",
        target_arch = "x86_64",
    ),
))]
mod avx2_compile_time {
    #[inline(always)]
    pub(crate) fn match_header_name_vectored(b: &[u8]) -> usize {
        super::swar::match_header_name_vectored(b)
    }

    #[inline(always)]
    pub(crate) fn match_uri_vectored(b: &[u8]) -> usize {
        // SAFETY: calls are guarded by a compile time feature check
        unsafe { crate::simd::avx2::match_uri_vectored(b) }
    }

    #[inline(always)]
    pub(crate) fn match_header_value_vectored(b: &[u8]) -> usize {
        // SAFETY: calls are guarded by a compile time feature check
        unsafe { crate::simd::avx2::match_header_value_vectored(b) }
    }
}

#[cfg(all(
    httparse_simd,
    httparse_simd_target_feature_avx2,
    any(
        target_arch = "x86",
        target_arch = "x86_64",
    ),
))]
pub(crate) use self::avx2_compile_time::*;

#[cfg(all(
    httparse_simd,
    target_arch = "aarch64",
    httparse_simd_neon_intrinsics,
))]
mod neon;

#[cfg(all(
    httparse_simd,
    target_arch = "aarch64",
    httparse_simd_neon_intrinsics,
))]
pub(crate) use self::neon::*;
