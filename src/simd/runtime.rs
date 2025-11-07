use crate::iter::Bytes;

pub fn match_header_name_vectored(bytes: &mut Bytes) {
    super::swar::match_header_name_vectored(bytes);
}

pub fn match_uri_vectored(bytes: &mut Bytes) {
    // SAFETY: calls are guarded by a feature check
    unsafe {
        if is_x86_feature_detected!("avx2") {
            super::avx2::match_uri_vectored(bytes)
        } else if is_x86_feature_detected!("sse4.2") {
            super::sse42::match_uri_vectored(bytes)
        } else {
            super::swar::match_uri_vectored(bytes)
        }
    }
}

pub fn match_header_value_vectored(bytes: &mut Bytes) {
    // SAFETY: calls are guarded by a feature check
    unsafe {
        if is_x86_feature_detected!("avx2") {
            super::avx2::match_header_value_vectored(bytes)
        } else if is_x86_feature_detected!("sse4.2") {
            super::sse42::match_header_value_vectored(bytes)
        } else {
            super::swar::match_header_value_vectored(bytes)
        }
    }
}
