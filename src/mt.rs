/// A simplist Mersenne Twister implementation in Rust
#[derive(Debug)]
pub struct Mt19937 {
    mt: Vec<u32>,
    index: usize,
}

pub const W: u32 = 32;
pub const N: u32 = 624;
pub const M: u32 = 397;
pub const A: u32 = 0x9908B0DF;
pub const U: u32 = 11;
pub const S: u32 = 7;
pub const B: u32 = 0x9D2C5680;
pub const T: u32 = 15;
pub const C: u32 = 0xEFC60000;
pub const F: u32 = 1812433253;
pub const L: u32 = 18;

const LOWER_MASK: u32 = (1 << 31) - 1;
const UPPER_MASK: u32 = 1 << 31;

impl Mt19937 {

    /// Return a new Mt19937 instance *without* seed.
    pub fn new() -> Mt19937 {
        Mt19937 {
            mt: vec![0; 624],
            index: 625,
        }
    }

    /// Return a new Mt19937 instance seeded by `seed`.
    pub fn with_seed(seed: u32) -> Mt19937 {
        let mut mt = Self::new();
        mt.seed(seed);
        mt
    }

    pub fn with_state(state: Vec<u32>) -> Mt19937 {
        assert_eq!(state.len(), 624);
        Mt19937 {
            mt: state,
            index: 624,
        }
    }

    /// Re-seed this instance with `seed`.
    pub fn seed(&mut self, seed: u32) {
        self.index = N as usize;
        self.mt[0] = seed;
        for i in 1..N as usize {
            self.mt[i] = F.wrapping_mul(self.mt[i - 1] ^ (self.mt[i - 1] >> (W - 2))).wrapping_add(i as u32);
        }
    }

    /// Return the next 32-bit number.
    pub fn next(&mut self) -> u32 {
        if self.index >= N as usize {
            if self.index > N as usize {
                self.seed(5489);
            }
            self.twist();
        }

        let mut y = self.mt[self.index];
        self.index += 1;

        y ^= y >> U;
        y ^= (y << S) & B;
        y ^= (y << T) & C;
        y ^= y >> L;

        y
    }

    // The twist operation on MT internal state.
    fn twist(&mut self) {
        for i in 0..N as usize {
            let x = (self.mt[i] & UPPER_MASK).wrapping_add(self.mt[(i + 1) % N as usize] & LOWER_MASK);
            let mut x_a = x >> 1;
            if (x & 1) != 0 {
                x_a = x_a ^ A;
            }
            self.mt[i] = self.mt[(i + M as usize) % N as usize] ^ x_a
        }
        self.index = 0;
    }
}
