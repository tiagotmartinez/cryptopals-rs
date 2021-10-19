use std::convert::TryInto;

#[derive(Debug)]
pub struct Md4 {
    state: [u32; 4],
    length_bits: u64,
    buffer: Vec<u8>,
}

impl Md4 {

    pub fn new() -> Md4 {
        Md4 {
            state: [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476],
            length_bits: 0,
            buffer: vec![],
        }
    }

    pub fn new_from_digest(digest: &[u8], length_bits: u64) -> Md4 {
        assert!(digest.len() >= 16);
        Md4 {
            state: [
                u32::from_le_bytes(digest[0..4].try_into().unwrap()),
                u32::from_le_bytes(digest[4..8].try_into().unwrap()),
                u32::from_le_bytes(digest[8..12].try_into().unwrap()),
                u32::from_le_bytes(digest[12..16].try_into().unwrap()),
            ],
            length_bits,
            buffer: vec![],
        }
    }

    pub fn write(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
        while self.buffer.len() >= 64 {
            self.process_block();
        }
    }

    pub fn finish(mut self) -> Vec<u8> {
        let length_bits = self.length_bits + (self.buffer.len() as u64) * 8;

        // padding trailer
        self.buffer.push(0x80);
        while (self.buffer.len() + 8) % 64 != 0 {
            self.buffer.push(0);
        }

        // 64-bit length
        self.buffer.extend_from_slice(&length_bits.to_le_bytes());

        // process final block(s)
        assert!(self.buffer.len() % 64 == 0);
        while self.buffer.len() >= 64 {
            self.process_block();
        }

        // expand 4 x u32 into one 20-byte Vec<u8>
        [
            self.state[0].to_le_bytes(),
            self.state[1].to_le_bytes(),
            self.state[2].to_le_bytes(),
            self.state[3].to_le_bytes(),
        ].concat()
    }

    fn process_block(&mut self) {
        assert!(self.buffer.len() >= 64);

        fn f(x: u32, y: u32, z: u32) -> u32 {
            (x & y) | (!x & z)
        }

        fn g(x: u32, y: u32, z: u32) -> u32 {
            (x & y) | (x & z) | (y & z)
        }

        fn h(x: u32, y: u32, z: u32) -> u32 {
            x ^ y ^ z
        }

        fn op1(a: u32, b: u32, c: u32, d: u32, k: u32, s: u32) -> u32 {
            a.wrapping_add(f(b, c, d)).wrapping_add(k).rotate_left(s)
        }

        fn op2(a: u32, b: u32, c: u32, d: u32, k: u32, s: u32) -> u32 {
            a.wrapping_add(g(b, c, d))
                .wrapping_add(k)
                .wrapping_add(0x5A82_7999)
                .rotate_left(s)
        }

        fn op3(a: u32, b: u32, c: u32, d: u32, k: u32, s: u32) -> u32 {
            a.wrapping_add(h(b, c, d))
                .wrapping_add(k)
                .wrapping_add(0x6ED9_EBA1)
                .rotate_left(s)
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];

        let input : Vec<_> = self.buffer.drain(..64).collect();
        self.length_bits += 512;

        // load block to data
        let mut data = [0u32; 16];
        for (o, chunk) in data.iter_mut().zip(input.chunks_exact(4)) {
            *o = u32::from_le_bytes(chunk.try_into().unwrap());
        }

        // round 1
        for &i in &[0, 4, 8, 12] {
            a = op1(a, b, c, d, data[i], 3);
            d = op1(d, a, b, c, data[i + 1], 7);
            c = op1(c, d, a, b, data[i + 2], 11);
            b = op1(b, c, d, a, data[i + 3], 19);
        }

        // round 2
        for i in 0..4 {
            a = op2(a, b, c, d, data[i], 3);
            d = op2(d, a, b, c, data[i + 4], 5);
            c = op2(c, d, a, b, data[i + 8], 9);
            b = op2(b, c, d, a, data[i + 12], 13);
        }

        // round 3
        for &i in &[0, 2, 1, 3] {
            a = op3(a, b, c, d, data[i], 3);
            d = op3(d, a, b, c, data[i + 8], 9);
            c = op3(c, d, a, b, data[i + 4], 11);
            b = op3(b, c, d, a, data[i + 12], 15);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
    }
}
