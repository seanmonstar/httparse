/// SWAR: SIMD Within A Register
/// SIMD validator backend that validates register-sized chunks of data at a time.
// TODO: current impl assumes 64-bit registers, optimize for 32-bit
use crate::{is_header_name_token, is_header_value_token, is_uri_token, Bytes};

#[inline]
pub fn match_uri_vectored(bytes: &mut Bytes) {
    loop {
        if let Some(bytes8) = bytes.peek_n::<[u8; 8]>(8) {
            let n = match_uri_char_8_swar(bytes8);
            unsafe {
                bytes.advance(n);
            }
            if n == 8 {
                continue;
            }
        }
        if let Some(b) = bytes.peek() {
            if is_uri_token(b) {
                unsafe { bytes.advance(1); }
                continue;
            }
        }
        break;
    }
}

#[inline]
pub fn match_header_value_vectored(bytes: &mut Bytes) {
    loop {
        if let Some(bytes8) = bytes.peek_n::<[u8; 8]>(8) {
            let n = match_header_value_char_8_swar(bytes8);
            unsafe {
                bytes.advance(n);
            }
            if n == 8 {
                continue;
            }
        }
        if let Some(b) = bytes.peek() {
            if is_header_value_token(b) {
                unsafe { bytes.advance(1); }
                continue;
            }
        }
        break;
    }
}

#[inline]
pub fn match_header_name_vectored(bytes: &mut Bytes) {
    while let Some(block) = bytes.peek_n::<[u8; 8]>(8) {
        let n = match_block(is_header_name_token, block);
        unsafe {
            bytes.advance(n);
        }
        if n != 8 {
            return;
        }
    }
    unsafe { bytes.advance(match_tail(is_header_name_token, bytes.as_ref())) };
}

// Matches "tail", i.e: when we have <8 bytes in the buffer, should be uncommon
#[cold]
#[inline]
fn match_tail(f: impl Fn(u8) -> bool, bytes: &[u8]) -> usize {
    for (i, &b) in bytes.iter().enumerate() {
        if !f(b) {
            return i;
        }
    }
    bytes.len()
}

// Naive fallback block matcher
#[inline(always)]
fn match_block(f: impl Fn(u8) -> bool, block: [u8; 8]) -> usize {
    for (i, &b) in block.iter().enumerate() {
        if !f(b) {
            return i;
        }
    }
    8
}

/// // A const alternative to u64::from_ne_bytes to avoid bumping MSRV (1.36 => 1.44)
// creates a u64 whose bytes are each equal to b
const fn uniform_block(b: u8) -> u64 {
    b as u64 * 0x01_01_01_01_01_01_01_01 // [1_u8; 8]
}

// A byte-wise range-check on an enire word/block,
// ensuring all bytes in the word satisfy
// `33 <= x <= 126 && x != '>' && x != '<'`
// IMPORTANT: it false negatives if the block contains '?'
#[inline]
fn match_uri_char_8_swar(block: [u8; 8]) -> usize {
    // 33 <= x <= 126
    const M: u8 = 0x21;
    const N: u8 = 0x7E;
    const BM: u64 = uniform_block(M);
    const BN: u64 = uniform_block(127 - N);
    const M128: u64 = uniform_block(128);

    let x = u64::from_ne_bytes(block); // Really just a transmute
    let lt = x.wrapping_sub(BM) & !x; // <= m
    let gt = x.wrapping_add(BN) | x; // >= n

    // XOR checks to catch '<' & '>' for correctness
    //
    // XOR can be thought of as a "distance function"
    // (somewhat extrapolating from the `xor(x, x) = 0` identity and ∀ x != y: xor(x, y) != 0`
    // (each u8 "xor key" providing a unique total ordering of u8)
    // '<' and '>' have a "xor distance" of 2 (`xor('<', '>') = 2`)
    // xor(x, '>') <= 2 => {'>', '?', '<'}
    // xor(x, '<') <= 2 => {'<', '=', '>'}
    //
    // We assume P('=') > P('?'),
    // given well/commonly-formatted URLs with querystrings contain
    // a single '?' but possibly many '='
    //
    // Thus it's preferable/near-optimal to "xor distance" on '>',
    // since we'll slowpath at most one block per URL
    //
    // Some rust code to sanity check this yourself:
    // ```rs
    // fn xordist(x: u8, n: u8) -> Vec<(char, u8)> {
    //     (0..=255).into_iter().map(|c| (c as char, c ^ x)).filter(|(_c, y)| *y <= n).collect()
    // }
    // (xordist(b'<', 2), xordist(b'>', 2))
    // ```
    const B3: u64 = uniform_block(3); // (dist <= 2) + 1 to wrap
    const BGT: u64 = uniform_block(b'>');

    let xgt = x ^ BGT;
    let ltgtq = xgt.wrapping_sub(B3) & !xgt;

    offsetnz((ltgtq | lt | gt) & M128)
}

// A byte-wise range-check on an entire word/block,
// ensuring all bytes in the word satisfy `32 <= x <= 126`
// IMPORTANT: false negatives if obs-text is present (0x80..=0xFF)
#[inline]
fn match_header_value_char_8_swar(block: [u8; 8]) -> usize {
    // 32 <= x <= 126
    const M: u8 = 0x20;
    const N: u8 = 0x7E;
    const BM: u64 = uniform_block(M);
    const BN: u64 = uniform_block(127 - N);
    const M128: u64 = uniform_block(128);

    let x = u64::from_ne_bytes(block); // Really just a transmute
    let lt = x.wrapping_sub(BM) & !x; // <= m
    let gt = x.wrapping_add(BN) | x; // >= n
    offsetnz((lt | gt) & M128)
}

/// Check block to find offset of first non-zero byte
// NOTE: Curiously `block.trailing_zeros() >> 3` appears to be slower, maybe revisit
#[inline]
fn offsetnz(block: u64) -> usize {
    // fast path optimistic case (common for long valid sequences)
    if block == 0 {
        return 8;
    }

    // perf: rust will unroll this loop
    for (i, b) in block.to_ne_bytes().iter().copied().enumerate() {
        if b != 0 {
            return i;
        }
    }
    unreachable!()
}

#[test]
fn test_is_header_value_block() {
    let is_header_value_block = |b| match_header_value_char_8_swar(b) == 8;

    // 0..32 => false
    for b in 0..32_u8 {
        assert_eq!(is_header_value_block([b; 8]), false, "b={}", b);
    }
    // 32..127 => true
    for b in 32..127_u8 {
        assert_eq!(is_header_value_block([b; 8]), true, "b={}", b);
    }
    // 127..=255 => false
    for b in 127..=255_u8 {
        assert_eq!(is_header_value_block([b; 8]), false, "b={}", b);
    }

    // A few sanity checks on non-uniform bytes for safe-measure
    assert!(!is_header_value_block(*b"foo.com\n"));
    assert!(!is_header_value_block(*b"o.com\r\nU"));
}

#[test]
fn test_is_uri_block() {
    let is_uri_block = |b| match_uri_char_8_swar(b) == 8;

    // 0..33 => false
    for b in 0..33_u8 {
        assert_eq!(is_uri_block([b; 8]), false, "b={}", b);
    }
    // 33..127 => true if b not in { '<', '?', '>' }
    let falsy = |b| b"<?>".contains(&b);
    for b in 33..127_u8 {
        assert_eq!(is_uri_block([b; 8]), !falsy(b), "b={}", b);
    }
    // 127..=255 => false
    for b in 127..=255_u8 {
        assert_eq!(is_uri_block([b; 8]), false, "b={}", b);
    }
}

#[test]
fn test_offsetnz() {
    let seq = [0_u8; 8];
    for i in 0..8 {
        let mut seq = seq.clone();
        seq[i] = 1;
        let x = u64::from_ne_bytes(seq);
        assert_eq!(offsetnz(x), i);
    }
}
