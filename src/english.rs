// detection of english language and text patterns

use lazy_static::lazy_static;

/// letter distribution of english
static ENGLISH_LETTER_FREQ: [(char, char, f64); 26] = [
    ('e', 'E', 12.02),
    ('t', 'T', 9.10),
    ('a', 'A', 8.12),
    ('o', 'O', 7.68),
    ('i', 'I', 7.31),
    ('n', 'N', 6.95),
    ('s', 'S', 6.28),
    ('r', 'R', 6.02),
    ('h', 'H', 5.92),
    ('d', 'D', 4.32),
    ('l', 'L', 3.98),
    ('u', 'U', 2.88),
    ('c', 'C', 2.71),
    ('m', 'M', 2.61),
    ('f', 'F', 2.30),
    ('y', 'Y', 2.11),
    ('w', 'W', 2.09),
    ('g', 'G', 2.03),
    ('p', 'P', 1.82),
    ('b', 'B', 1.49),
    ('v', 'V', 1.11),
    ('k', 'K', 0.69),
    ('x', 'X', 0.17),
    ('q', 'Q', 0.11),
    ('j', 'J', 0.10),
    ('z', 'Z', 0.07),
];

lazy_static! {
    /// Associate ASCII code to frequency for english alphabet.
    /// Computed from `ENGLISH_LETTER_FREQ`.
    static ref ENGLISH_FREQ : Vec<f64> = {
        let mut t = vec![0.0f64; 256];
        for &(a, b, f) in &ENGLISH_LETTER_FREQ {
            t[a as usize] = f;
            t[b as usize] = f;
        }
        t
    };
}

/// Compute the frequency histogram of bytes in `data`.
pub fn histogram(data: &[u8]) -> [f64; 256] {
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }

    let mut freq = [0.0f64; 256];
    for i in 0..256 {
        freq[i] = counts[i] as f64 / data.len() as f64;
    }

    freq
}

/// Compute chi-square test between `observed` and `expected`.
pub fn chi_square(observed: &[f64], expected: &[f64]) -> f64 {
    assert_eq!(observed.len(), expected.len());
    observed.iter().zip(expected.iter())
        .map(|(&o, &e)| (o - e) * (o - e) / e)
        .filter(|&x| x.is_normal())
        .sum()
}

/// `true` if `data` has only ASCII chars and space, '\n' or '\r'.
pub fn is_ascii(data: &[u8]) -> bool {
    data.iter().all(|&b| b == 10 || b == 13 || (32 <= b && b < 127))
}

/// Return a "grade" of possibility of `data` being english text:
/// * The lower the better
/// * If `data` is not ASCII return a *very large number*
pub fn english_grade(data: &[u8]) -> f64 {
    if !is_ascii(data) {
        f64::MAX
    } else {
        chi_square(&histogram(data), &ENGLISH_FREQ)
    }
}

/// `true` if `new` can compare with `previous` and is smaller.
pub fn less(new: f64, previous: f64) -> bool {
    if let Some(std::cmp::Ordering::Less) = new.partial_cmp(&previous) {
        true
    } else {
        false
    }
}

