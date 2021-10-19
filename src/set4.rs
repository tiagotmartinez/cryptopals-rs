// Cryptopals Set 4

#![allow(dead_code)]

// use rand::RngCore;
// use rand::distributions::{Distribution, Uniform};

// use crate::english::*;
use crate::pkcs7::*;
use crate::aes::*;
use crate::bits::*;
use crate::sha1::*;
use crate::md4::*;
// use crate::mt::*;

use aes::Aes128;
use aes::cipher::NewBlockCipher;

static mut GLOBAL_KEY: [u8; 16] = [0u8; 16];

//=============================================================================
// CHALLENGE 25
//=============================================================================

// Generate the keystream from (`key`, `nonce`) starting at `offset` with `length` bytes.
fn aes_ctr_keystream_at(key: &[u8], nonce: u64, offset: usize, length: usize) -> Vec<u8> {
    let mut block_id = offset / aes::BLOCK_SIZE;
    let mut index = offset % aes::BLOCK_SIZE;
    let mut ks = vec![];
    let mut blk = vec![0u8; 16];
    let aes = Aes128::new_from_slice(key).unwrap();
    while ks.len() != length {
        aes_ctr_block(&aes, nonce, block_id as u64, &mut blk);
        while ks.len() != length && index < aes::BLOCK_SIZE {
            ks.push(blk[index]);
            index += 1;
        }
        index = 0;
        block_id += 1;
    }
    ks
}

// Modify the contents of `ciphertext[offset .. offset+newtext.len()]` to the encrypted value of `newtext`.
fn edit(ciphertext: &mut [u8], offset: usize, newtext: &[u8]) {
    let ks = aes_ctr_keystream_at(unsafe { &GLOBAL_KEY }, 0, offset, newtext.len());
    for i in 0..newtext.len() {
        ciphertext[offset + i] = newtext[i] ^ ks[i];
    }
}

// Break "random access read/write" AES CTR
pub fn challenge25() {
    unsafe {
        GLOBAL_KEY.copy_from_slice(&random_bytes(16));
    }

    let text = base64_decode_text(include_str!("4-25.txt"));
    let mut cipher = aes_ctr(unsafe { &GLOBAL_KEY }, 0, &text);

    // decrypt byte-per-byte; could also operate on larger blocks
    let mut plain = vec![];
    for i in 0..cipher.len() {
        let b = cipher[i];
        edit(&mut cipher, i, &[0]);
        plain.push(b ^ cipher[i]);
    }

    assert_eq!(plain, text);
}

//=============================================================================
// CHALLENGE 26
//=============================================================================

// Generate a query with given `userdata`, discarding all "special" chars
fn make_query(userdata: &str) -> Vec<u8> {
    let replaced = userdata.replace(';', "_").replace('=', "_");
    let mut pt = b"comment1=cooking%20MCs;userdata=".to_vec(); // 32 bytes
    pt.extend_from_slice(replaced.as_bytes());
    pt.extend_from_slice(b";comment2=%20like%20a%20pound%20of%20bacon"); // 42 bytes
    aes_ctr(unsafe { &GLOBAL_KEY }, 0, &pt)
}

// Check if `query` is "admin=true", or not
fn parse_query(query: &[u8]) -> bool {
    let pt = aes_ctr(unsafe { &GLOBAL_KEY }, 0, query);
    let text = String::from_utf8_lossy(&pt);
    for p in text.split(';') {
        let t : Vec<&str> = p.split('=').collect();
        if t[0] == "admin" && t[1] == "true" {
            return true
        }
    }
    false
}

// CTR bitflipping
pub fn challenge26() {
    unsafe {
        GLOBAL_KEY.copy_from_slice(&random_bytes(16));
    }

    let desired =  ";admin=true";
    let userdata = "AAAAAAAAAAA";

    let mut q = make_query(userdata);
    assert!(!parse_query(&q));

    // CTR bitflipping is actually easier...
    let desired_bytes = desired.as_bytes();
    let userdata_bytes = userdata.as_bytes();
    for i in 0..desired_bytes.len() {
        q[32+i] ^= desired_bytes[i] ^ userdata_bytes[i];
    }

    assert!(parse_query(&q));
}

//=============================================================================
// CHALLENGE 27
//=============================================================================

// Just like the code from Challenge 16, but using key as IV
fn make_query_27(userdata: &str) -> Vec<u8> {
    let replaced = userdata.replace(';', "_").replace('=', "_");
    let mut pt = b"comment1=cooking%20MCs;userdata=".to_vec(); // 32 bytes
    pt.extend_from_slice(replaced.as_bytes());
    pt.extend_from_slice(b";comment2=%20like%20a%20pound%20of%20bacon"); // 42 bytes
    encipher_cbc(unsafe { &GLOBAL_KEY }, unsafe { &GLOBAL_KEY }, &pad(aes::BLOCK_SIZE, &pt))
}

// Decrypt query and, in case of padding error or invalid ASCII, return an error and
// leak the decrypted content
fn open_query_27(query: &[u8]) -> Result<Vec<u8>, Vec<u8>> {
    let plain = decipher_cbc(unsafe { &GLOBAL_KEY }, unsafe { &GLOBAL_KEY }, query);
    if let Ok(pt) = unpad(&plain) {
        if pt.iter().any(|&b| b < 32 || b >= 127) {
            Err(pt)
        } else {
            Ok(pt)
        }
    } else {
        Err(plain)
    }
}

// Recover the key from CBC with IV=Key
pub fn challenge27() {
    unsafe {
        GLOBAL_KEY.copy_from_slice(&random_bytes(16));
    }

    let q = make_query_27("");

    // decrypt Q[0..16], <zeroes>, Q[0..16]
    // the (wrong) decryption has now both (IV ^ BLK0) and (0 ^ BLK0),
    // therefore it is easy to record IV that, behold!, has the same
    // value as key!!!
    let c = [&q[..16], &repeat(16, 0), &q[..16]].concat();
    if let Err(ce) = open_query_27(&c) {
        let k = xor_bytes(&ce[..16], &ce[32..]);
        assert_eq!(&k, unsafe { &GLOBAL_KEY });
    } else {
        panic!("failed");
    }
}

//=============================================================================
// CHALLENGE 28
//=============================================================================

// Return the hex-coded digest of an UTF-8 string `data`
fn sha1_digest(data: &str) -> String {
    let mut sha1 = Sha1::new();
    sha1.write(data.as_bytes());
    hex::encode(sha1.finish())
}

// Compute the keyed SHA-1 MAC of `message` under `key`
fn sha1_mac(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut sha1 = Sha1::new();
    sha1.write(key);
    sha1.write(message);
    sha1.finish()
}

// Implement a SHA-1 keyed MAC
pub fn challenge28() {
    let tests = [
        ("The quick brown fox jumps over the lazy dog",
         "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"),
        ("The quick brown fox jumps over the lazy cog",
         "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3"),
        ("", "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
        ("testing\n", "9801739daae44ec5293d4e1f53d3f4d2d426d91c"),
        ("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
         "025ecbd5d70f8fb3c5457cd96bab13fda305dc59"),
        ("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
         "4300320394f7ee239bcdce7d3b8bcee173a0cd5c"),
        ("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
         "cef734ba81a024479e09eb5a75b6ddae62e6abf1"),
    ];

    for (s, h) in tests.iter() {
        assert_eq!(&sha1_digest(s), h);
    }

    let key = random_bytes(16);
    let mac = sha1_mac(&key, b"the amount is 100.00");
    assert_eq!(mac, sha1_mac(&key, b"the amount is 100.00"));
    assert_ne!(mac, sha1_mac(&key, b"the amount is 100000"));

    let other_key = random_bytes(16);
    assert_ne!(mac, sha1_mac(&other_key, b"the amount is 100.00"));
}

//=============================================================================
// CHALLENGE 29
//=============================================================================

// Return the same padding that SHA-1 would append to a message of length `message_bytes`
fn make_padding_sha1(message_bytes: usize) -> Vec<u8> {
    let mut blk = vec![];
    blk.push(0x80);
    while (message_bytes + blk.len() + 8) % 64 != 0 {
        blk.push(0);
    }

    let message_bits = message_bytes as u64 * 8;
    blk.extend_from_slice(&message_bits.to_be_bytes());

    blk
}

// Check if the `sha1_mac` of `message` under `key` matches `mac`
fn sha1_check(key: &[u8], message: &[u8], mac: &[u8]) -> bool {
    &sha1_mac(key, message) == mac
}

// Break a SHA-1 keyed MAC using length extension
pub fn challenge29() {
    // test the base functionality
    let key = random_bytes(16);
    let msg = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
    let mac = sha1_mac(&key, msg);
    assert!(sha1_check(&key, msg, &mac));

    // our final message will include the original message, the (previous) SHA-1 padding and the new payload
    let pad = make_padding_sha1(msg.len() + 16);
    let extra = b";admin=true";
    let mut fake_msg = msg.to_vec();
    fake_msg.extend_from_slice(&pad);
    fake_msg.extend_from_slice(extra);

    // but the original mac already includes the (previous) padding, so we only feed the new payload
    // (Sha1::finish will add the new padding)
    let mut sha1 = Sha1::new_from_digest(&mac, (msg.len() as u64 + 16 + pad.len() as u64) * 8);
    sha1.write(extra);
    let fake_mac = sha1.finish();

    // check that our fake_msg and fake_mac validate as if computed by sha1_mac
    assert!(sha1_check(&key, &fake_msg, &fake_mac));
}

//=============================================================================
// CHALLENGE 30
//=============================================================================

// Return the same padding that SHA-1 would append to a message of length `message_bytes`
fn make_padding_md4(message_bytes: usize) -> Vec<u8> {
    let mut blk = vec![];
    blk.push(0x80);
    while (message_bytes + blk.len() + 8) % 64 != 0 {
        blk.push(0);
    }

    let message_bits = message_bytes as u64 * 8;
    blk.extend_from_slice(&message_bits.to_le_bytes());

    blk
}


// Return the hex-coded digest of an UTF-8 string `data`
fn md4_digest(data: &str) -> String {
    let mut md4 = Md4::new();
    md4.write(data.as_bytes());
    hex::encode(md4.finish())
}

// Compute the keyed SHA-1 MAC of `message` under `key`
fn md4_mac(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut md4 = Md4::new();
    md4.write(key);
    md4.write(message);
    md4.finish()
}

// Check if the `sha1_mac` of `message` under `key` matches `mac`
fn md4_check(key: &[u8], message: &[u8], mac: &[u8]) -> bool {
    &md4_mac(key, message) == mac
}

// Break an MD4 keyed MAC using length extension
pub fn challenge30() {
    let tests = [
        ("",
         "31d6cfe0d16ae931b73c59d7e0c089c0"),
        ("a",
         "bde52cb31de33e46245e05fbdbd6fb24"),
        ("abc",
         "a448017aaf21d8525fc10ae87aa6729d"),
        ("message digest",
         "d9130a8164549fe818874806e1c7014b"),
        ("abcdefghijklmnopqrstuvwxyz",
         "d79e1c308aa5bbcdeea8ed63df412da9"),
        ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
         "043f8582f241db351ce627e153e7f0e4"),
        ("12345678901234567890123456789012345678901234567890123456789012345678901234567890",
         "e33b4ddc9c38f2199c3e7b164fcc0536"),
    ];

    for (m, d) in tests {
        assert_eq!(&md4_digest(m), d);
    }

    // test the base functionality
    let key = random_bytes(16);
    let msg = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
    let mac = md4_mac(&key, msg);
    assert!(md4_check(&key, msg, &mac));

    // our final message will include the original message, the (previous) SHA-1 padding and the new payload
    let pad = make_padding_md4(msg.len() + 16);
    let extra = b";admin=true";
    let mut fake_msg = msg.to_vec();
    fake_msg.extend_from_slice(&pad);
    fake_msg.extend_from_slice(extra);

    // but the original mac already includes the (previous) padding, so we only feed the new payload
    let mut md4 = Md4::new_from_digest(&mac, (msg.len() as u64 + 16 + pad.len() as u64) * 8);
    md4.write(extra);
    let fake_mac = md4.finish();

    // check that our fake_msg and fake_mac validate as if computed by sha1_mac
    assert!(md4_check(&key, &fake_msg, &fake_mac));
}
