#![allow(dead_code)]

use num::BigUint;
use crate::bits::*;
use crate::sha1::*;
use crate::aes::*;
use crate::pkcs7::*;

// First step on a DH key exchange
// have only the generators and my own key parameters
pub struct DHKeyExchange1 {
    // generators
    p: BigUint,
    g: BigUint,

    // private key
    sk: BigUint,

    // public key
    pk: BigUint,
}

/// Second (final) step on a DH key exchange
/// Compute secret from generators and public-keys
pub struct DHKeyExchange2 {
    // generators
    p: BigUint,
    g: BigUint,

    // private key
    sk: BigUint,

    // public key
    pk: BigUint,

    // computed secret
    secret: BigUint,
    secret_key: Vec<u8>,
}

impl DHKeyExchange1 {

    /// Create a new DH with given generators
    pub fn new(p: BigUint, g: BigUint) -> DHKeyExchange1 {
        let sk = BigUint::from_bytes_be(&random_bytes(193)) % &p;
        let pk = g.modpow(&sk, &p);

        DHKeyExchange1 {
            p, g,
            sk, pk,
        }
    }

    /// Compute the secret from the public-key of the other party
    pub fn generate_secret(self, other_pk: &BigUint) -> DHKeyExchange2 {
        let secret = other_pk.modpow(&self.sk, &self.p);
        let secret_key = sha1(&secret.to_bytes_be()).drain(..16).collect();

        DHKeyExchange2 {
            p: self.p, g: self.g,
            sk: self.sk, pk: self.pk,
            secret,
            secret_key,
        }
    }

    /// Return the public-key for this end-point.
    pub fn public_key(&self) -> &BigUint {
        &self.pk
    }
}

impl DHKeyExchange2 {

    /// Encrypt `message` with `self.secret_key` and a random IV
    /// Return the concatenation of <random-iv> || <cipher-text>
    pub fn encipher(&self, message: &[u8]) -> Vec<u8> {
        let iv = random_bytes(16);
        let ct = encipher_cbc(&self.secret_key, &iv, &pad(16, message));
        [iv, ct].concat()
    }

    /// Decrypt `message` with `self.secret_key`.
    /// The first 16-bytes are used as IV for decryption.
    /// Return `None` on any error (padding, length, etc).
    pub fn decipher(&self, message: &[u8]) -> Option<Vec<u8>> {
        if message.len() < 32 || message.len() % 16 != 0 {
            // need at least two blocks (IV + cipher-text) and multiple of aes::BLOCK_SIZE
            None
        } else {
            let iv = &message[..16];
            let ct = &message[16..];
            match unpad(&decipher_cbc(&self.secret_key, iv, ct)) {
                Ok(pt) => Some(pt),
                Err(_) => None,
            }
        }
    }

    /// Return the public-key for this end-point.
    pub fn public_key(&self) -> &BigUint {
        &self.pk
    }

    /// Return the computed 16-byte secret key
    pub fn secret_key(&self) -> &[u8] {
        &self.secret_key
    }

    /// Return the (numeric value) of the computed secret
    pub fn secret(&self) -> &BigUint {
        &self.secret
    }
}
