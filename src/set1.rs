// Cryptopals Set 1

#![allow(dead_code)]

use crate::english::*;
use crate::aes::*;
use crate::bits::*;
use std::collections::HashSet;


/// Convert hex to base64
pub fn challenge1() {
    let source_hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let target_b64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    let decoded_hex = hex::decode(source_hex).expect("invalid hex");
    let encoded_b64 = base64::encode(&decoded_hex[..]);

    assert_eq!(target_b64, encoded_b64);
}

/// Fixed XOR
pub fn challenge2() {
    let hex1 = hex::decode("1c0111001f010100061a024b53535009181c").unwrap();
    let hex2 = hex::decode("686974207468652062756c6c277320657965").unwrap();
    let expected = hex::decode("746865206b696420646f6e277420706c6179").unwrap();

    assert_eq!(xor_bytes(&hex1, &hex2), expected);
}

/// Single-byte XOR cipher
pub fn challenge3() {
    let ciphered = hex::decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736").unwrap();
    let mut best = (f64::MAX, 0u8, Vec::new());
    for key in 0 ..= 255 {
        let pt = xor_byte(&ciphered, key);
        let er = english_grade(&pt);
        if less(er, best.0) {
            best = (er, key, pt);
        }
    }

    let text = String::from_utf8(best.2).unwrap();
    assert_eq!(text, "Cooking MC's like a pound of bacon");
}

/// Detect single-character XOR
pub fn challenge4() {
    let mut best = (f64::MAX, 0u8, Vec::new());
    for line in include_str!("1-4.txt").split('\n') {
        let ct = hex::decode(line).unwrap();
        for key in 0 ..= 255 {
            let pt = xor_byte(&ct, key);
            let eg = english_grade(&pt);
            if less(eg, best.0) {
                best = (eg, key, pt);
            }
        }
    }

    let text = String::from_utf8(best.2.to_vec()).unwrap();
    assert_eq!(text, "Now that the party is jumping\n");
}

/// Implement repeating-key XOR
pub fn challenge5() {
    let text = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    let ct = xor_repeat(text, b"ICE");
    assert_eq!(hex::encode(&ct), "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f");
}

/// Compute possible key sizes for challenge 6
fn possible_key_sizes(ct: &[u8]) -> Vec<(f64, usize)> {
    let mut key_sizes = vec![];
    for key_size in 2 .. 41 {
        // split `ct` into chunks of exactly (2 * key_size) and the compute the hamming distance
        // between both halves (i.e. pair-wise chunks), and then average it all
        let chunks = ct.chunks_exact(2 * key_size);
        let n = chunks.len();
        let x : f64 = chunks.map(|slice| normalized_distance(&slice[..key_size], &slice[key_size..])).sum();
        key_sizes.push((x / n as f64, key_size));
    }

    key_sizes.sort_by(|a, b| a.partial_cmp(b).unwrap());
    key_sizes
}

/// Break repeating-key XOR
pub fn challenge6() {
    assert_eq!(hamming_distance(b"this is a test", b"wokka wokka!!!"), 37);

    let ct = base64_decode_text(include_str!("1-6.txt"));

    // use hamming distance of chunks to list and order all potential key sizes
    let key_sizes = possible_key_sizes(&ct);

    // this will store the "best" key option, using `english_grade` to measure
    let mut best_key = (f64::MAX, Vec::new(), Vec::new());

    // loop over the better rated key sizes...
    for &(_, key_size) in &key_sizes[..3] {

        // transpose[i] = concatenation of all i'th bytes of each chunk
        let chunks = ct.chunks_exact(key_size);
        let mut transpose = vec![vec![]; key_size];
        for c in chunks {
            for i in 0..key_size {
                transpose[i].push(c[i]);
            }
        }

        // for each byte of this key size, find the one that "better"
        // decrypt, according to `english_grade` metric
        let mut best = vec![0u8; key_size];
        for i in 0..key_size {
            let mut best_byte = (f64::MAX, 0u8);
            for k in 0 .. 255 {
                let pt = xor_byte(&transpose[i], k);
                let eg = english_grade(&pt);
                if less(eg, best_byte.0) {
                    best_byte = (eg, k);
                }
            }
            best[i] = best_byte.1;
        }

        // take the best key option for this key size and compare to the other
        // ones already tested
        let pt = xor_repeat(&ct, &best);
        let eg = english_grade(&pt);
        if less(eg, best_key.0) {
            best_key = (eg, best, pt)
        }
    }

    let key_text = String::from_utf8(best_key.1).unwrap();
    assert_eq!(key_text, "Terminator X: Bring the noise");

    let pt_text = String::from_utf8(best_key.2).unwrap();
    assert!(pt_text.starts_with("I'm back and I'm ringin' the bell \n"));
}

/// AES in ECB mode
pub fn challenge7() {
    let ct = base64_decode_text(include_str!("1-7.txt"));
    let key = b"YELLOW SUBMARINE";
    let pt = decipher_ecb(key, &ct);
    let pt_text = String::from_utf8(pt).unwrap();
    assert!(pt_text.starts_with("I'm back and I'm ringin' the bell \n"));
}

/// Detect AES in ECB mode
pub fn challenge8() {

    // detect ECB encryption by search for repeated blocks
    // input test set has exactly one cipher-text with repeated blocks

    let mut found = None;
    for line in include_str!("1-8.txt").split('\n') {
        let ct = hex::decode(line).unwrap();
        let mut count_repeated = 0;
        let mut seen = HashSet::new();
        for c in ct.chunks_exact(aes::BLOCK_SIZE) {
            if seen.contains(c) {
                count_repeated += 1;
            } else {
                seen.insert(c.to_vec());
            }
        }

        if count_repeated > 0 {
            found = Some(line.to_string());
        }
    }

    assert!(found.unwrap().starts_with("d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283"));
}
