use std::convert::TryInto;

use crate::bits::*;

/// A reference pure-Rust implementation of SHA-1, to be used as test bed.
///
/// Not meant to be either fast or low-resource or whatever.  Just easy to hack.
#[derive(Debug)]
pub struct Sha1 {
    h: [u32; 5],
    message_length: u64,
    blk: Vec<u8>,
}

impl Sha1 {

    /// Create a new Sha1 instance.
    pub fn new() -> Sha1 {
        Sha1 {
            h: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
            message_length: 0,
            blk: vec![],
        }
    }

    pub fn new_from_digest(digest: &[u8], message_length: u64) -> Sha1 {
        assert!(digest.len() >= 20);
        Sha1 {
            h: [
                u32::from_be_bytes(digest[0..4].try_into().unwrap()),
                u32::from_be_bytes(digest[4..8].try_into().unwrap()),
                u32::from_be_bytes(digest[8..12].try_into().unwrap()),
                u32::from_be_bytes(digest[12..16].try_into().unwrap()),
                u32::from_be_bytes(digest[16..20].try_into().unwrap()),
            ],
            message_length,
            blk: vec![],
        }

    }

    /// Called when at least 64-bytes of blk is pending.
    /// Process the next 64-byte block (extracting it from `self.blk`).
    fn process_block(&mut self) {
        assert!(self.blk.len() >= 64);

        let mut w = [0u32; 80];
        for i in (0..64).step_by(4) {
            w[i / 4] = u32::from_be_bytes(self.blk[i..i+4].try_into().unwrap());
        }

        for i in 16..80 {
            w[i] = (w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]).rotate_left(1);
        }

        let mut a = self.h[0];
        let mut b = self.h[1];
        let mut c = self.h[2];
        let mut d = self.h[3];
        let mut e = self.h[4];

        for i in 0..80 {
            let (f, k) = match i {
                0..=19  => ((b & c) | (!b & d), 0x5A827999),
                20..=39 => (b ^c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                60..=79 => (b ^ c ^ d, 0xCA62C1D6),
                _ => unreachable!(),
            };

            let tmp = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }

        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);

        self.message_length += 512;
        self.blk.drain(0..64);
    }

    /// Write `data` to the internal buffers and process as much as possible.
    pub fn write(&mut self, data: &[u8]) {
        self.blk.extend_from_slice(data);
        while self.blk.len() >= 64 {
            self.process_block();
        }
    }

    /// Finalize and return the final hash value
    pub fn finish(mut self) -> Vec<u8> {
        let message_length = self.message_length + (self.blk.len() * 8) as u64;

        // padding trailer
        self.blk.push(0x80);
        while (self.blk.len() + 8) % 64 != 0 {
            self.blk.push(0);
        }

        // 64-bit length
        self.blk.extend_from_slice(&message_length.to_be_bytes());

        // process final block(s)
        assert!(self.blk.len() % 64 == 0);
        while self.blk.len() >= 64 {
            self.process_block();
        }

        // expand 5 x u32 into one 20-byte Vec<u8>
        [
            self.h[0].to_be_bytes(),
            self.h[1].to_be_bytes(),
            self.h[2].to_be_bytes(),
            self.h[3].to_be_bytes(),
            self.h[4].to_be_bytes(),
        ].concat()
    }
}

// Compute HMAC-SHA1 of a message
pub fn hmac_sha1(key: &[u8], message: &[u8]) -> Vec<u8> {
    let key = {
        // keys longer than blockSize are shortened by hashing them
        let mut key = if key.len() > 64 {
            let mut sha1 = Sha1::new();
            sha1.write(key);
            sha1.finish()
        } else {
            key.to_vec()
        };

        // keys shorter than blockSize are padded to blockSize by padding with zeros on the right
        while key.len() < 64 {
            key.push(0);
        }

        key
    };

    let okey = xor_byte(&key, 0x5c);
    let ikey = xor_byte(&key, 0x36);

    let mut inner = Sha1::new();
    inner.write(&ikey);
    inner.write(message);
    let mut outer = Sha1::new();
    outer.write(&okey);
    outer.write(&inner.finish());
    outer.finish()
}
