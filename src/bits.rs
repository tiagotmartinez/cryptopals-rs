// Bit manipulation utilities

#![allow(dead_code)]

use rand::prelude::*;
use rand::distributions::Uniform;
use std::collections::HashSet;

/// Given to slices `left` and `right` *with exactly the same size*, return a `Vec<u8>`
/// with the XOR of the bytes of each.
pub fn xor_bytes(left: &[u8], right: &[u8]) -> Vec<u8> {
    left.iter().zip(right).map(|(l, r)| l ^ r).collect()
}

/// XOR the bytes of `right` into `left`, modifying `left` in place.
pub fn xor_into_left(left: &mut [u8], right: &[u8]) {
    for (l, r) in left.iter_mut().zip(right) {
        *l ^= r;
    }
}

/// Return a `Vec<u8>` with the result of XOR'ing each byte of `data` with `key`.
pub fn xor_byte(data: &[u8], key: u8) -> Vec<u8> {
    data.iter().map(|x| x ^ key).collect()
}

/// Return XOR of `data` with as many repetitions of `key` as necessary to cover all bytes.
pub fn xor_repeat(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter().zip(key.iter().cycle()).map(|(a, b)| a ^ b).collect()
}

/// Compute the hamming (bit) distance between `a` and `b`.
pub fn hamming_distance(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b.iter()).fold(0, |n, (&a, &b)| n + (a ^ b).count_ones()) as usize
}

/// Compute `hamming_distance` normalized by lengths of `a` and `b`
pub fn normalized_distance(a: &[u8], b: &[u8]) -> f64 {
    assert_eq!(a.len(), b.len());
    hamming_distance(a, b) as f64 / a.len() as f64
}

/// Repeat a random `usize` in the open range `[0, limit)`
pub fn random_usize(limit: usize) -> usize {
    thread_rng().sample(Uniform::new(0, limit))
}

/// Return a vector of `n` random bytes.
pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; n];
    thread_rng().fill_bytes(&mut bytes);
    bytes
}

/// Return a random ASCII string (for passwords).
pub fn random_ascii_string(n: usize) -> String {
    let mut s = String::new();
    let mut rng = thread_rng();
    let ascii = rand::distributions::Uniform::<u8>::new(32, 128);
    for _ in 0..n {
        s.push(ascii.sample(&mut rng) as char);
    }
    s
}

/// Return `true` if breaking `data` in blocks of exactly `block_size` bytes
/// at least one block repeats.
pub fn repeats_block(data: &[u8], block_size: usize) -> bool {
    let mut seen = HashSet::new();
    for blk in data.chunks(block_size) {
        if seen.contains(blk) {
            return true;
        } else {
            seen.insert(blk.to_vec());
        }
    }
    false
}

pub fn repeat(n: usize, b: u8) -> Vec<u8> {
    std::iter::repeat(b).take(n).collect()
}

pub fn base64_decode_text(text: &str) -> Vec<u8> {
    base64::decode(text.split('\n').collect::<Vec<&str>>().join("")).unwrap()
}

pub fn u64_into_bytes_little_endian(value: u64, bytes: &mut [u8]) {
    assert!(bytes.len() >= 8);
    let mut value = value;
    for i in 0..8 {
        bytes[i] = (value & 0xFF) as u8;
        value >>= 8;
    }
}
