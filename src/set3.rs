// Cryptopals Set 2

#![allow(dead_code)]

use rand::RngCore;
use rand::distributions::{Distribution, Uniform};

use crate::english::*;
use crate::pkcs7::*;
use crate::aes::*;
use crate::bits::*;
use crate::mt::*;

static mut GLOBAL_KEY: [u8; 16] = [0u8; 16];

//=============================================================================
// CHALLENGE 17
//=============================================================================

static MESSAGES17: [&str; 10] = [
    "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
];

fn encrypt17() -> (Vec<u8>, Vec<u8>) {
    unsafe {
        GLOBAL_KEY.copy_from_slice(&random_bytes(16));
    }

    let which_message = random_usize(MESSAGES17.len());
    let pt = base64_decode_text(MESSAGES17[which_message]);
    let padded = pad(16, &pt);
    let iv = random_bytes(16);
    let ct = encipher_cbc(unsafe { &GLOBAL_KEY }, &iv, &padded);

    (iv, ct)
}

fn decrypt17(iv: &[u8], ct: &[u8]) -> bool {
    let pt = decipher_cbc(unsafe { &GLOBAL_KEY }, iv, ct);
    return unpad(&pt).is_ok();
}

// The CBC padding oracle
pub fn challenge17() {
    let (mut iv, mut ct) = encrypt17();
    assert!(decrypt17(&iv, &ct));
    assert!(ct.len() >= 32);

    // keep a copy of the original IV, as we scramble it during the algorithm
    let orig_iv = iv.clone();
    let mut pt = vec![];

    // insert the original IV as first block of cipher-text to make algorithm
    // simpler to follow
    ct.splice(0..0, iv.clone());
    for blk in ct.chunks_exact(aes::BLOCK_SIZE) {

        // for each single block, use the padding check to find the padding
        // bytes and from that the original bytes

        let mut zeroing_iv = vec![0u8; aes::BLOCK_SIZE];
        for i in (0..16).rev() {

            // iterate [15, 14, 13, ..., 0].  for each case we initialize the
            // other bytes (to the right) with what would be the expected padding
            // value for a message of (i - 1) bytes and loop over i to find the
            // value that matches (i - 1) when XOR'ed with original byte

            let npad = 16 - i;
            let mut test_iv = vec![0u8; aes::BLOCK_SIZE];
            for j in 0..aes::BLOCK_SIZE {
                test_iv[j] = zeroing_iv[j] ^ npad as u8;
            }

            for x in 0..=255 {
                test_iv[i] = x;
                if decrypt17(&test_iv, &blk) {
                    // found it! store and move to next position
                    zeroing_iv[i] = npad as u8 ^ x;
                    break;
                }
            }
        }

        // the found "zero-IV" xor'ed with the actual IV gives the original plain-text
        // for this block
        pt.extend_from_slice(&xor_bytes(&zeroing_iv, &iv));

        // IV of *next* block is the encrypted value of this block
        iv.copy_from_slice(&blk);
    }

    // undo the "insert IV as first block" step before the loop
    ct = ct.into_iter().skip(aes::BLOCK_SIZE).collect();

    assert_eq!(decipher_cbc(unsafe { &GLOBAL_KEY }, &orig_iv, &ct), &pt[16..]);
}

//=============================================================================
// CHALLENGE 18
//=============================================================================

// Implement CTR, the stream cipher mode
pub fn challenge18() {
    let pt = base64::decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==").unwrap();
    let ct = aes_ctr(b"YELLOW SUBMARINE", 0, &pt);
    assert_eq!(b"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ".to_vec(), ct);

    let mut rnd = rand::thread_rng();
    let lengths = Uniform::new(1, 500);
    for _ in 0..100 {
        let length = lengths.sample(&mut rnd);
        let key = random_bytes(16);
        let pt = random_bytes(length);
        let nonce = rnd.next_u64();
        let ct = aes_ctr(&key, nonce, &pt);
        let ot = aes_ctr(&key, nonce, &ct);
        assert_eq!(ot, pt);
    }
}

//=============================================================================
// CHALLENGE 19
//=============================================================================

static MESSAGES19 : [&str; 40] = [
    "SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
    "Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
    "RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
    "RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
    "SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
    "T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
    "T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
    "UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
    "QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
    "T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
    "VG8gcGxlYXNlIGEgY29tcGFuaW9u",
    "QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
    "QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
    "QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
    "QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
    "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
    "VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
    "SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
    "SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
    "VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
    "V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
    "V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
    "U2hlIHJvZGUgdG8gaGFycmllcnM/",
    "VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
    "QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
    "VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
    "V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
    "SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
    "U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
    "U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
    "VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
    "QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
    "SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
    "VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
    "WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
    "SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
    "SW4gdGhlIGNhc3VhbCBjb21lZHk7",
    "SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
    "VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
    "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
];

// Break fixed-nonce CTR mode using substitutions
pub fn challenge19() {
    let key = random_bytes(16);

    let mut cts = vec![];
    for pt in MESSAGES19 {
        let pt = base64::decode(pt).unwrap();
        cts.push(aes_ctr(&key, 0, &pt));
    }

    // apply the exact same code as set1::challenge6(), but using key_size
    // as the same as the smallest encrypted cipher text

    let key_size = cts.iter().map(|ct| ct.len()).min().unwrap();

    // transpose[i] = concatenation of all i'th bytes of each chunk
    let mut transpose = vec![vec![]; key_size];
    for c in cts.iter() {
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

    let pts : Vec<_> = cts.iter().map(|ct| xor_bytes(&ct, &best)).collect();
    let sts : Vec<_> = pts.iter().map(|pt| String::from_utf8(pt.clone()).unwrap()).collect();

    assert_eq!(sts[0], "I have met them at c");
    assert_eq!(sts[sts.len() - 1], "A terrible beauty is");
}

//=============================================================================
// CHALLENGE 20
//=============================================================================

// Break fixed-nonce CTR statistically
pub fn challenge20() {
    let text = include_str!("3-20.txt");
    let cts : Vec<_> = text.lines().map(|s| base64::decode(s).unwrap()).collect();

    // to the same as challenge above (19)... I ended up solving the "easy" challenge
    // using the general method that can be used for the "harder" one...

    let key_size = cts.iter().map(|ct| ct.len()).min().unwrap();

    // transpose[i] = concatenation of all i'th bytes of each chunk
    let mut transpose = vec![vec![]; key_size];
    for c in cts.iter() {
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

    let pts : Vec<_> = cts.iter().map(|ct| xor_bytes(&ct, &best)).collect();
    let sts : Vec<_> = pts.iter().map(|pt| String::from_utf8(pt.clone()).unwrap()).collect();

    assert_eq!(sts[0], "I'm rated \"R\"...this is a warning, ya better void / P");
    assert_eq!(sts[sts.len() - 1], "And we outta here / Yo, what happened to peace? / Pea");
}

//=============================================================================
// CHALLENGE 21
//=============================================================================

// Implement the MT19937 Mersenne Twister RNG
pub fn challenge21() {
    let mut mt1 = Mt19937::with_seed(42);
    let mut mt2 = Mt19937::with_seed(42);

    assert_eq!(mt1.next(), mt2.next());
    assert_eq!(mt1.next(), mt2.next());
    assert_eq!(mt1.next(), mt2.next());
    assert_eq!(mt1.next(), mt2.next());
    assert_eq!(mt1.next(), mt2.next());
    assert_eq!(mt1.next(), mt2.next());

    let mut mt1 = Mt19937::with_seed(42);
    let mut mt2 = Mt19937::with_seed(43);

    assert_ne!(mt1.next(), mt2.next());
    assert_ne!(mt1.next(), mt2.next());
    assert_ne!(mt1.next(), mt2.next());
    assert_ne!(mt1.next(), mt2.next());
    assert_ne!(mt1.next(), mt2.next());
    assert_ne!(mt1.next(), mt2.next());
}

//=============================================================================
// CHALLENGE 22
//=============================================================================

// Seconds since UNIX_EPOCH
fn unix_time() -> u32 {
    use std::time::SystemTime;
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() as u32
}

// Do some processing with timeouts and unix_time() as seed for random number generator
fn random_value() -> (u32, u32) {
    let mut rnd = rand::thread_rng();

    // wait random number of seconds...
    // changed back to smaller delays so we can run all tests
    let wait_s = rand::distributions::Uniform::new(4, 11).sample(&mut rnd);
    std::thread::sleep(std::time::Duration::from_secs(wait_s));

    // seed the random number generator
    let seed = unix_time();
    let mut mt = Mt19937::with_seed(seed);

    // wait more random number of seconds...
    let wait_s = rand::distributions::Uniform::new(4, 11).sample(&mut rnd);
    std::thread::sleep(std::time::Duration::from_secs(wait_s));

    (seed, mt.next())
}

// Crack an MT19937 seed
pub fn challenge22() {
    let (seed, random) = random_value();

    // lets try to guess going backwards...
    let mut current_time = unix_time();
    while current_time != 0 {
        let mut mt = Mt19937::with_seed(current_time);
        if mt.next() == random {
            assert_eq!(current_time, seed);
            return;
        }
        current_time -= 1;
    }

    panic!("failed")
}

//=============================================================================
// CHALLENGE 23
//=============================================================================

// Reverse the "temper" operation of Mt19937
// https://www.maths.tcd.ie/~fionn/misc/mt/
fn untemper(value: u32) -> u32 {
    let mut value = value;
    value ^= value >> L;
    value ^= (value << T) & C;
    for _ in 0..7 {
        value ^= (value << S) & B;
    }
    for _ in 0..3 {
        value ^= value >> U;
    }

    value
}

// Clone an MT19937 RNG from its output
pub fn challenge23() {
    // collect 624 output samples
    let mut mt = Mt19937::with_seed(unix_time());
    let state : Vec<_> = (0..624).map(|_| mt.next()).map(|x| untemper(x)).collect();

    // from reconstructed state, create a new MT instance and check
    let mut mt2 = Mt19937::with_state(state);
    for _ in 0..1248 {
        assert_eq!(mt.next(), mt2.next());
    }

    // to make MT harder to clone, the "temper" operation should be one-way (NOT a bijection)
    // and also never output enough state to be able to reconstruct (e.g. truncation)
    // this, of course, oversimplifies the difficulty of *actually* making this in a secure
    // and not workaround-able way... but this is the idea!
}

//=============================================================================
// CHALLENGE 24
//=============================================================================

// "Encrypt" with MT by generating a random generated seeded by `key` and XOR'ing output with `input`
fn encrypt_mt(key: u16, input: &[u8]) -> Vec<u8> {
    let mut mt = Mt19937::with_seed(key as u32);
    let keystream = (0..input.len()).map(|_| mt.next() as u8);
    input.iter().zip(keystream).map(|(input, ks)| input ^ ks).collect()
}

// "Decryption" is, of course, exactly the same as encryption, but create separate function to make reading easier
fn decrypt_mt(key: u16, input: &[u8]) -> Vec<u8> {
    encrypt_mt(key, input)
}

fn is_mt_token(token: u32) -> bool {
    // check tokens generated in the last hour
    // (could be more...)
    let mut current_time = unix_time();
    let check_limit = current_time - 60 * 60;
    while current_time != check_limit {
        let value = Mt19937::with_seed(current_time).next();
        if value == token {
            return true;
        }
        current_time -= 1;
    }
    false
}

fn create_password_token() -> u32 {
    Mt19937::with_seed(unix_time()).next()
}

// Create the MT19937 stream cipher and break it
pub fn challenge24() {
    for _ in 0..20 {
        let key = random_usize(65536) as u16;
        let length = random_usize(100) + 1;
        let input = random_bytes(length);
        let cipher = encrypt_mt(key, &input);
        let plain = decrypt_mt(key, &cipher);
        assert_eq!(input, plain);
    }

    let key = random_usize(65536) as u16;
    let length = random_usize(100);
    let input = [random_bytes(length), repeat(14, b'A')].concat();
    let cipher = encrypt_mt(key, &input);

    // decipher by guessing the key
    let mut found = false;
    for k in 0..=65535 {
        let guess = decrypt_mt(k, &cipher);
        if guess[guess.len() - 14 ..].iter().all(|&b| b == b'A') {
            assert_eq!(k, key);
            found = true;
            break;
        }
    }

    assert!(found);

    let password_token = create_password_token();
    let other_value = Mt19937::with_seed(5489).next();

    assert!(is_mt_token(password_token));
    assert!(!is_mt_token(other_value));
}
