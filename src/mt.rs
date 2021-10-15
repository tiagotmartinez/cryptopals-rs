/// A simplist Mersenne Twister implementation in Rust
pub struct Mt19937 {
    w: u32,
    n: u32,
    m: u32,
    a: u32,
    u: u32,
    d: u32,
    s: u32,
    b: u32,
    t: u32,
    c: u32,
    f: u32,

    mt: Vec<u32>,
    index: usize,
    lower_mask: u32,
    upper_mask: u32,
}

impl Mt19937 {

    /// Return a new Mt19937 instance *without* seed.
    pub fn new() -> Mt19937 {
        Mt19937 {
            w: 32,
            n: 624,
            m: 397,
            a: 0x9908B0DF,
            u: 11,
            d: 0xFFFFFFFF,
            s: 7,
            b: 0x9D2C5680,
            t: 15,
            c: 0xEFC60000,
            f: 1812433253,

            mt: vec![0; 624],
            index: 625,
            lower_mask: (1 << 31) - 1,
            upper_mask: (1 << 31),
        }
    }

    /// Return a new Mt19937 instance seeded by `seed`.
    pub fn with_seed(seed: u32) -> Mt19937 {
        let mut mt = Self::new();
        mt.seed(seed);
        mt
    }

    /// Re-seed this instance with `seed`.
    pub fn seed(&mut self, seed: u32) {
        self.index = self.n as usize;
        self.mt[0] = seed;
        for i in 1..self.n as usize {
            self.mt[i] = self.f.wrapping_mul(self.mt[i - 1] ^ (self.mt[i - 1] >> (self.w - 2))).wrapping_add(i as u32);
        }
    }

    /// Return the next 32-bit number.
    pub fn next(&mut self) -> u32 {
        if self.index >= self.n as usize {
            if self.index > self.n as usize {
                self.seed(5489);
            }
            self.twist();
        }

        let mut y = self.mt[self.index];
        y ^= (y >> self.u) & self.d;
        y ^= (y << self.s) & self.b;
        y ^= (y << self.t) & self.c;
        y ^= y >> 1;

        self.index += 1;
        y
    }

    // The twist operation on MT internal state.
    fn twist(&mut self) {
        for i in 0..self.n as usize {
            let x = (self.mt[i] & self.upper_mask).wrapping_add(self.mt[(i + 1) % self.n as usize] & self.lower_mask);
            let mut x_a = x >> 1;
            if (x & 1) != 0 {
                x_a = x_a ^ self.a;
            }
            self.mt[i] = self.mt[(i + self.m as usize) % self.n as usize] ^ x_a
        }
        self.index = 0;
    }
}
