// Cryptopals Set 2

#![allow(dead_code)]

use std::collections::HashMap;

use lazy_static::lazy_static;
use crate::pkcs7::*;
use crate::aes::*;
use crate::bits::*;

lazy_static! {
    static ref UNKNOWN_STRING_12: Vec<u8> = base64::decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK").unwrap();
}

static mut GLOBAL_KEY: [u8; 16] = [0u8; 16];
static mut PREFIX_BYTES_14: Vec<u8> = Vec::new();

//=============================================================================
// CHALLENGE 9
//=============================================================================

/// Implement PKCS#7 padding
pub fn challenge9() {
    let data = b"YELLOW SUBMARINE";
    let padded = pad(20, data);
    assert_eq!(padded, b"YELLOW SUBMARINE\x04\x04\x04\x04");

    // let's do some more testing to be confident that it works...
    assert_eq!(pad(10, b""), b"\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A");
    assert_eq!(pad(10, b"X"), b"X\x09\x09\x09\x09\x09\x09\x09\x09\x09");
    assert_eq!(pad(10, b"XX"), b"XX\x08\x08\x08\x08\x08\x08\x08\x08");
    assert_eq!(pad(10, b"XXX"), b"XXX\x07\x07\x07\x07\x07\x07\x07");
    assert_eq!(pad(10, b"XXXX"), b"XXXX\x06\x06\x06\x06\x06\x06");
    assert_eq!(pad(10, b"XXXXX"), b"XXXXX\x05\x05\x05\x05\x05");
    assert_eq!(pad(10, b"XXXXXX"), b"XXXXXX\x04\x04\x04\x04");
    assert_eq!(pad(10, b"XXXXXXX"), b"XXXXXXX\x03\x03\x03");
    assert_eq!(pad(10, b"XXXXXXXX"), b"XXXXXXXX\x02\x02");
    assert_eq!(pad(10, b"XXXXXXXXX"), b"XXXXXXXXX\x01");
    assert_eq!(pad(10, b"XXXXXXXXXX"), b"XXXXXXXXXX\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A");

    for i in 0 .. 100 {
        let data = random_bytes(i);
        let padded = pad(20, &data);
        let unpadded = unpad(&padded).unwrap();
        assert_eq!(data, unpadded);
    }
}

//=============================================================================
// CHALLENGE 10
//=============================================================================

/// Implement CBC mode
pub fn challenge10() {
    let data = base64_decode_text(include_str!("2-10.txt"));
    let pt = unpad(&decipher_cbc(b"YELLOW SUBMARINE", &ZERO_IV, &data)).unwrap();
    let pt_text = String::from_utf8(pt).unwrap();
    assert!(pt_text.starts_with("I'm back and I'm ringin' the bell \n"));

    // let's do some random AES-CBC testing, shall we...
    for _ in 0 .. 100 {
        let key = random_bytes(16);
        let iv = random_bytes(aes::BLOCK_SIZE);
        let length = random_usize(1024);
        let pt = random_bytes(length);
        let ct = encipher_cbc(&key, &iv, &pad(aes::BLOCK_SIZE, &pt));
        let ot = unpad(&decipher_cbc(&key, &iv, &ct)).unwrap();
        assert_eq!(ot, pt);
    }
}

//=============================================================================
// CHALLENGE 11
//=============================================================================

/// Encrypt `pt` in either ECB or CBC modes, using random key and IV.
///
/// Return a tuple with a boolean `true` indicating if it was ECB or
/// `false` for CBC and the padded and encrypted result.
///
/// The ECB flag is used to validate that the solution of challenges
/// that must detect the cipher mode is correct.
fn encryption_oracle(pt: &[u8]) -> (bool, Vec<u8>) {
    let key = random_bytes(16);
    let is_ecb = random_usize(2) == 0;

    let ct = if is_ecb {
        encipher_ecb(&key, &pad(aes::BLOCK_SIZE, pt))
    } else {
        let iv = random_bytes(aes::BLOCK_SIZE);
        encipher_cbc(&key, &iv, &pad(aes::BLOCK_SIZE, pt))
    };

    (is_ecb, ct)
}

/// Check if `data` is cipher-text produced by ECB mode.
///
/// Do this by looking for any repeating block in `data`, so
/// if this works or not depends on the original plain-text.
pub fn is_ecb(data: &[u8]) -> bool {
    repeats_block(data, aes::BLOCK_SIZE)
}

/// An ECB/CBC detection oracle
pub fn challenge11() {
    let middle_data = repeat(aes::BLOCK_SIZE * 4, b'A');
    for _ in 0..100 {
        let (ecb_flag, ct) = encryption_oracle(&middle_data[..]);
        assert_eq!(ecb_flag, is_ecb(&ct));
    }
}

//=============================================================================
// CHALLENGE 12
//=============================================================================

/// Oracle function for Challenge 12
fn oracle12(pt: &[u8]) -> Vec<u8> {
    let mut pt = pt.to_vec();
    pt.extend_from_slice(&UNKNOWN_STRING_12);
    encipher_ecb(unsafe { &GLOBAL_KEY }, &pad(aes::BLOCK_SIZE, &pt))
}

/// Byte-at-a-time ECB decryption (Simple)
pub fn challenge12() {
    // the key is always randomly created
    // not cheatin' here...
    unsafe {
        let key = random_bytes(16);
        GLOBAL_KEY.copy_from_slice(&key);
    }

    // find block size of `oracle12` cipher function
    let mut block_size = 1;
    loop {
        let pt = repeat(block_size, b'A');
        let ct1 = oracle12(&pt);
        let pt = repeat(block_size + 1, b'A');
        let ct2 = oracle12(&pt);
        if &ct1[.. block_size] == &ct2[.. block_size] {
            break
        }
        block_size += 1;
    }
    assert_eq!(block_size, aes::BLOCK_SIZE);

    // confirm that `oracle12` is indeed ECB
    let pt = repeat(block_size * 2, b'A');
    assert!(is_ecb(&oracle12(&pt)));

    // how many blocks to decode?
    let total_blocks = oracle12(b"").len() / block_size;

    // store here the unknown string we have found
    let mut unknown = vec![];

    // iterate block by block (it's ECB after all...)
    let mut block = 0;
    loop {
        let block_offset = block * block_size;
        let mut found = vec![];

        // for each block we "slide" the bytes so we have all but the last
        // then all but the last two, last three, so on (see the site)
        for count in (0..block_size).rev() {
            let mut pt = repeat(count, b'?');
            let reference = oracle12(&pt);
            pt.extend_from_slice(&unknown);
            pt.extend_from_slice(&found);
            for b in 0..=255 {
                pt.push(b);
                let ct = oracle12(&pt);
                let left = &ct[block_offset..block_offset + block_size];
                let right = &reference[block_offset..block_offset + block_size];
                if left == right {
                    found.push(b);
                    break
                }
                pt.pop();
            }
        }

        unknown.extend_from_slice(&found);
        block += 1;
        if block == total_blocks {
            break
        }
    }

    // did we get it right?
    assert_eq!(unpad(&unknown).unwrap(), UNKNOWN_STRING_12.to_vec());
}

//=============================================================================
// CHALLENGE 13
//=============================================================================

fn parse_token(data: &str) -> HashMap<String, String> {
    let mut values = HashMap::new();
    for entries in data.split('&') {
        let mut entry = entries.split('=');
        let key = if let Some(k) = entry.next() { k } else { continue };
        let value = entry.next().unwrap_or("");
        values.insert(key.to_string(), value.to_string());
    }
    values
}

fn parse_encrypted_token(key: &[u8], data: &[u8]) -> HashMap<String, String> {
    let pt = unpad(&decipher_ecb(key, data)).unwrap();
    parse_token(&String::from_utf8(pt).unwrap())
}

fn profile_for(email: &str) -> String {
    format!("email={}&uid=10&role=user", email.replace('&', "_").replace('=', "_"))
}

fn encrypted_profile_for(key: &[u8], email: &str) -> Vec<u8> {
    let profile = profile_for(email);
    encipher_ecb(key, &pad(aes::BLOCK_SIZE, profile.as_bytes()))
}

/// ECB cut-and-paste
pub fn challenge13() {

    {
        // test token parser
        let items = parse_token("foo=bar&baz=qux&zap=zazzle");
        assert!(items.contains_key("foo"));
        assert!(items.contains_key("baz"));
        assert!(items.contains_key("zap"));
        assert_eq!(items.get("foo").unwrap(), "bar");
        assert_eq!(items.get("baz").unwrap(), "qux");
        assert_eq!(items.get("zap").unwrap(), "zazzle");
    }

    {
        // test profile for
        assert_eq!(profile_for("foo@bar.com"), "email=foo@bar.com&uid=10&role=user");
        assert_eq!(profile_for("foo@bar.com&role=admin"), "email=foo@bar.com_role_admin&uid=10&role=user");
    }

    {
        // test encrypted
        let key = random_bytes(16);
        let ct = encrypted_profile_for(&key, "foo@bar.com");
        let pt = parse_encrypted_token(&key, &ct);
        assert!(pt.contains_key("email"));
        assert!(pt.contains_key("uid"));
        assert!(pt.contains_key("role"));
        assert_eq!(pt.get("email").unwrap(), "foo@bar.com");
        assert_eq!(pt.get("uid").unwrap(), "10");
        assert_eq!(pt.get("role").unwrap(), "user");
    }

    let key = random_bytes(16);

    // 1234567890123
    // user1@foo.bar
    let t1 = encrypted_profile_for(&key, "user1@foo.bar");
    let t2 = encrypted_profile_for(&key, "1234567890admin");
    let t3 = &[&t1[..2*aes::BLOCK_SIZE], &t2[aes::BLOCK_SIZE..2*aes::BLOCK_SIZE], &t1[2*aes::BLOCK_SIZE..]].concat();

    let pt = parse_encrypted_token(&key, &t3);
    assert_eq!(pt.get("role").unwrap(), "admin");
    assert_eq!(pt.get("email").unwrap(), "user1@foo.bar");
}

//=============================================================================
// CHALLENGE 14
//=============================================================================

fn oracle14(data: &[u8]) -> Vec<u8> {
    let mut pt = unsafe { &PREFIX_BYTES_14 }.clone();
    pt.extend_from_slice(data);
    pt.extend_from_slice(&UNKNOWN_STRING_12);
    encipher_ecb(unsafe { &GLOBAL_KEY }, &pad(aes::BLOCK_SIZE, &pt))
}

// Byte-at-a-time ECB decryption (Harder)
pub fn challenge14() {
    unsafe {
        let key = random_bytes(16);
        GLOBAL_KEY.copy_from_slice(&key);
        let prefix_bytes = random_usize(100);
        PREFIX_BYTES_14 = random_bytes(prefix_bytes);
    }

    // let's skip the block_size and ECB stuff...
    let block_size = aes::BLOCK_SIZE;

    // find random prefix length
    let prefix_bytes = {
        // how many blocks of prefix
        let prefix_block = {
            let ct1 = oracle14(b"");
            let ct2 = oracle14(b"?");
            ct1.iter().zip(ct2.iter())
                .position(|(blk1, blk2)| blk1 != blk2)
                .unwrap()
        };

        // how many bytes need to have as data before suffix move to another block
        // if not found then prefix_bytes is multiple of block_size
        let mut remain = 0;
        let mut prev = oracle14(b"");
        for i in 1 ..= block_size {
            let ct = oracle14(&repeat(i, b'?'));
            if &ct[prefix_block..prefix_block + block_size] == &prev[prefix_block..prefix_block + block_size] {
                remain = i;
                break;
            }
            prev = ct;
        }

        // why those two, can calculate exact number of prefix bytes
        if remain == 0 { prefix_block } else { prefix_block + 17 - remain }
    };

    assert_eq!(prefix_bytes, unsafe { PREFIX_BYTES_14.len() });

    // difference between prefix_bytes and block_size
    let fill_bytes = block_size - (prefix_bytes % block_size);
    assert!((fill_bytes + prefix_bytes) % block_size == 0);

    // store here the unknown string we have found
    let mut unknown = vec![];

    // do the same as challenge 12,
    // but start on block after random-prefix
    let mut block = (prefix_bytes + fill_bytes) / block_size;
    loop {
        let block_offset = block * block_size;
        let mut found = vec![];

        for count in (0..block_size).rev() {
            let mut pt = repeat(fill_bytes + count, b'?');
            let reference = oracle14(&pt);
            pt.extend_from_slice(&unknown);
            pt.extend_from_slice(&found);
            for b in 0..=255 {
                pt.push(b);
                let ct = oracle14(&pt);
                let left = &ct[block_offset..block_offset + block_size];
                let right = &reference[block_offset..block_offset + block_size];
                if left == right {
                    found.push(b);
                    break
                }
                pt.pop();
            }
        }

        unknown.extend_from_slice(&found);
        block += 1;
        if unknown.len() >= UNKNOWN_STRING_12.len() {
            break
        }
    }

    // did we get it right?
    assert_eq!(unpad(&unknown).unwrap(), UNKNOWN_STRING_12.to_vec());
}

//=============================================================================
// CHALLENGE 15
//=============================================================================

// PKCS#7 padding validation
pub fn challenge15() {
    assert_eq!(unpad(b"ICE ICE BABY\x04\x04\x04\x04"), Ok(b"ICE ICE BABY".to_vec()));
    assert!(unpad(b"ICE ICE BABY\x05\x05\x05\x05").is_err());
    assert!(unpad(b"ICE ICE BABY\x01\x02\x03\x04").is_err());
}

//=============================================================================
// CHALLENGE 16
//=============================================================================

fn make_query(userdata: &str) -> Vec<u8> {
    let replaced = userdata.replace(';', "_").replace('=', "_");
    let mut pt = b"comment1=cooking%20MCs;userdata=".to_vec(); // 32 bytes
    pt.extend_from_slice(replaced.as_bytes());
    pt.extend_from_slice(b";comment2=%20like%20a%20pound%20of%20bacon"); // 42 bytes
    encipher_cbc(unsafe { &GLOBAL_KEY }, &ZERO_IV, &pad(aes::BLOCK_SIZE, &pt))
}

fn parse_query(query: &[u8]) -> bool {
    if let Ok(pt) = unpad(&decipher_cbc(unsafe { &GLOBAL_KEY }, &ZERO_IV, query)) {
        let text = String::from_utf8_lossy(&pt);
        for p in text.split(';') {
            let t : Vec<&str> = p.split('=').collect();
            if t[0] == "admin" && t[1] == "true" {
                return true
            }
        }
        false
    } else {
        false
    }
}

// CBC bitflipping attacks
pub fn challenge16() {
    unsafe {
        GLOBAL_KEY.copy_from_slice(&random_bytes(16));
    }

    // the plan is: provide make_query with userdata of two blocks of 'A's
    // (destructively) modify the first of those blocks so that the CBC XOR
    // of the *next* block of 'A's will result in what we want

    let from = b"AAAAAAAAAAAAAAAA";
    let want = b"xxxxx;admin=true";
    let diff = xor_bytes(from, want);

    let mut ct = make_query("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

    for i in 0..16 {
        ct[32+i] ^= diff[i]
    }

    assert!(parse_query(&ct));
}
