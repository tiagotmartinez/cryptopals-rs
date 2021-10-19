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
                ((digest[0] as u32) << 24) | ((digest[1] as u32) << 16) | ((digest[2] as u32) << 8) | (digest[3] as u32),
                ((digest[4] as u32) << 24) | ((digest[5] as u32) << 16) | ((digest[6] as u32) << 8) | (digest[7] as u32),
                ((digest[8] as u32) << 24) | ((digest[9] as u32) << 16) | ((digest[10] as u32) << 8) | (digest[11] as u32),
                ((digest[12] as u32) << 24) | ((digest[13] as u32) << 16) | ((digest[14] as u32) << 8) | (digest[15] as u32),
                ((digest[16] as u32) << 24) | ((digest[17] as u32) << 16) | ((digest[18] as u32) << 8) | (digest[19] as u32),
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
            let n = ((self.blk[i] as u32) << 24) | ((self.blk[i+1] as u32) << 16) | ((self.blk[i+2] as u32) << 8) | (self.blk[i+3] as u32);
            w[i / 4] = n;
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
        for i in (0..8).rev() {
            self.blk.push((message_length >> (8 * i)) as u8);
        }

        // process final block(s)
        assert!(self.blk.len() % 64 == 0);
        while self.blk.len() >= 64 {
            self.process_block();
        }

        // expand 5x4-byte into one 20-byte
        let mut digest = vec![];
        for i in 0..5 {
            for j in (0..4).rev() {
                digest.push((self.h[i] >> (j * 8)) as u8);
            }
        }

        digest
    }
}
