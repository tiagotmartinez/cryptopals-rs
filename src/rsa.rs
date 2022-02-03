// RSA utility functions

use num::{
    bigint::ToBigInt,
    Integer,
    Signed,
    BigUint,
    BigInt,
    One,
    Zero,
};

use glass_pumpkin::prime;

/// Return (gcd(a, b), s, t) where gcd(a, b) = a*s + b*t
fn egcd(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
    let (mut r0, mut r1) = (a.clone(), b.clone());
    let (mut s0, mut s1) = (BigInt::one(), BigInt::zero());
    let (mut t0, mut t1) = (BigInt::zero(), BigInt::one());

    while !r1.is_zero() {
        let (q1, r2) = r0.div_mod_floor(&r1);
        r0 = r1;
        r1 = r2;

        let s2 = &s0 - &q1 * &s1;
        s0 = s1;
        s1 = s2;

        let t2 = &t0 - &q1 * &t1;
        t0 = t1;
        t1 = t2;
    }

    if t0.is_negative() {
        t0 += b;
    }

    (r0, s0, t0)
}

/// Return the modular multiplicative inverse of (a mod m) or None if not invertible
pub fn invmod(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    let a = a.to_bigint().unwrap();
    let m = m.to_bigint().unwrap();
    let (r, mut s, _) = egcd(&a, &m);

    if r.is_one() {
        // gcd == 1, `a` and `m` are relatively prime
        if s.is_negative() {
            s += &m;
        }
        Some((s % m).to_biguint().unwrap())
    } else {
        None
    }
}

#[derive(Debug)]
pub struct PublicKey(pub BigUint, pub BigUint);

#[derive(Debug)]
pub struct PrivateKey(pub BigUint, pub BigUint);

pub fn random_keypair(bits: usize) -> (PublicKey, PrivateKey) {
    loop {
        let p = prime::new(bits).unwrap();
        let q = prime::new(bits).unwrap();
        let n = &p * &q;
        let et = (&p - BigUint::one()) * (&q - BigUint::one());
        let e = BigUint::from(3u32);
        if let Some(d) = invmod(&e, &et) {
            // got keys
            let pk = PublicKey(e, n.clone());
            let sk = PrivateKey(d, n);
            return (pk, sk);
        } else {
            // try again
        }
    }
}

pub fn message_to_biguint(m: &[u8]) -> BigUint {
    BigUint::from_bytes_be(m)
}

pub fn biguint_to_message(m: &BigUint) -> Vec<u8> {
    m.to_bytes_be()
}

pub fn encrypt_pk(m: &BigUint, pk: &PublicKey) -> BigUint {
    m.modpow(&pk.0, &pk.1)
}

pub fn decrypt_sk(c: &BigUint, sk: &PrivateKey) -> BigUint {
    c.modpow(&sk.0, &sk.1)
}
