use num::{BigUint, Zero};
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac, NewMac};
use rand::prelude::random;

use crate::bits::*;

/// An implementation of SRP protocol **client** for the challenges 36-38, including both default and simplified versions.
#[derive(Debug)]
pub struct SRPClient {
    prime: BigUint,
    g: BigUint,
    k: BigUint,
    user: String,

    a: BigUint,
    aa: BigUint,
    key: Vec<u8>,
}

impl SRPClient {

    pub fn new(prime: BigUint, g: BigUint, k: BigUint, user: &str) -> SRPClient {
        SRPClient {
            prime, g, k,
            user: user.into(),
            a: BigUint::zero(),
            aa: BigUint::zero(),
            key: Vec::new(),
        }
    }

    pub fn first(&mut self) -> (String, BigUint) {
        self.a = BigUint::from_bytes_be(&random_bytes(128));
        self.aa = self.g.modpow(&self.a, &self.prime);
        (self.user.clone(), self.aa.clone())
    }

    /// A version of `second` for the simplified SRP used in challenge 38
    pub fn second_simplified(&mut self, password: &str, salt: u128, bb: &BigUint, u: u128) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(salt.to_string().as_bytes());
        hasher.update(password.as_bytes());
        let x = BigUint::from_bytes_be(&hasher.finalize_reset());

        let u = BigUint::from(u);
        let s = bb.modpow(&(&self.a + (&u * &x)), &self.prime);

        hasher.update(&s.to_bytes_be());
        self.key = hasher.finalize().to_vec();

        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key).unwrap();
        mac.update(salt.to_string().as_bytes());
        mac.finalize().into_bytes().to_vec()
    }

    pub fn second(&mut self, password: &str, salt: u128, bb: &BigUint) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(&self.aa.to_bytes_be());
        hasher.update(&bb.to_bytes_be());
        let u = BigUint::from_bytes_be(&hasher.finalize_reset());

        hasher.update(salt.to_string().as_bytes());
        hasher.update(password.as_bytes());
        let x = BigUint::from_bytes_be(&hasher.finalize_reset());

        let s = (bb - (&self.k * self.g.modpow(&x, &self.prime))).modpow(&(&self.a + &(&u * &x)), &self.prime);

        hasher.update(&s.to_bytes_be());
        self.key = hasher.finalize().to_vec();

        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key).unwrap();
        mac.update(salt.to_string().as_bytes());
        mac.finalize().into_bytes().to_vec()
    }
}

/// An implementation of SRP protocol **server** for the challenges 36-38, including both default and simplified versions.
#[derive(Debug)]
pub struct SRPServer {
    prime: BigUint,
    g: BigUint,
    k: BigUint,
    salt: u128,
    v: BigUint,
    user: String,

    b: BigUint,
    bb: BigUint,

    key: Vec<u8>,
    u: u128,
}

impl SRPServer {

    pub fn new(prime: BigUint, g: BigUint, k: BigUint) -> SRPServer {
        SRPServer {
            prime, g, k,
            salt: 0,
            v: BigUint::zero(),
            user: String::default(),
            b: BigUint::zero(),
            bb: BigUint::zero(),
            key: Vec::new(),

            u: 0,
        }
    }

    pub fn enroll(&mut self, user: &str, password: &str) {
        self.salt = random();
        self.user = user.into();

        let mut hasher = Sha256::new();
        hasher.update(self.salt.to_string().as_bytes());
        hasher.update(password.as_bytes());
        let x = BigUint::from_bytes_be(&hasher.finalize());

        self.v = self.g.modpow(&x, &self.prime);
    }

    /// A version of `first` for the simplified SRP used in challenge 38
    pub fn first_simplified(&mut self) -> (u128, BigUint, u128) {
        self.b = BigUint::from_bytes_be(&random_bytes(128));
        self.bb = self.g.modpow(&self.b, &self.prime);
        self.u = random();
        (self.salt, self.bb.clone(), self.u)
    }

    pub fn first(&mut self) -> (u128, BigUint) {
        self.b = BigUint::from_bytes_be(&random_bytes(128));
        self.bb = (&self.k * &self.v) + self.g.modpow(&self.b, &self.prime);
        (self.salt, self.bb.clone())
    }

    /// A version of `second` for the simplified SRP used in challenge 38
    pub fn second_simplified(&mut self, _user: &str, aa: &BigUint) -> Vec<u8> {
        let u = BigUint::from(self.u);
        let vu = self.v.modpow(&u, &self.prime);
        let s = (aa * &vu).modpow(&self.b, &self.prime);

        let mut hasher = Sha256::new();
        hasher.update(&s.to_bytes_be());
        self.key = hasher.finalize().to_vec();

        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key).unwrap();
        mac.update(self.salt.to_string().as_bytes());
        mac.finalize().into_bytes().to_vec()
    }

    pub fn second(&mut self, _user: &str, aa: &BigUint) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(&aa.to_bytes_be());
        hasher.update(&self.bb.to_bytes_be());
        let u = BigUint::from_bytes_be(&hasher.finalize_reset());

        let s = (aa * self.v.modpow(&u, &self.prime)).modpow(&self.b, &self.prime);

        hasher.update(&s.to_bytes_be());
        self.key = hasher.finalize().to_vec();

        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key).unwrap();
        mac.update(self.salt.to_string().as_bytes());
        mac.finalize().into_bytes().to_vec()
    }
}

