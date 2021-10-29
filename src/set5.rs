// Cryptopals Set 5

#![allow(dead_code)]

// use std::time::{Instant, Duration};
// use rand::RngCore;
// use rand::distributions::{Distribution, Uniform};

// use crate::english::*;
use crate::pkcs7::*;
use crate::aes::*;
use crate::bits::*;
use crate::sha1::*;
// use crate::md4::*;
// use crate::mt::*;

use num::{Num, BigUint};

//=============================================================================
// CHALLENGE 33
//=============================================================================

// Implement Diffie-Hellman
pub fn challenge33() {
    // the NIST generators
    let p = BigUint::from_str_radix("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16).unwrap();
    let g = BigUint::from(2u32);

    // A secret and public keys
    let sa = BigUint::from_bytes_be(&random_bytes(192)) % &p;
    let pa = g.modpow(&sa, &p);

    // B secret and public keys
    let sb = BigUint::from_bytes_be(&random_bytes(192)) % &p;
    let pb = g.modpow(&sb, &p);

    // A compute shared secret from sa and pb
    let secret_a = pb.modpow(&sa, &p);

    // B compute shared secret from sb and pa
    let secret_b = pa.modpow(&sb, &p);

    assert_eq!(secret_a, secret_b);
}

//=============================================================================
// CHALLENGE 34
//=============================================================================



// Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection
pub fn challenge34() {

    // Part I: the simple protocol with DH key-exchange

    // A -> B
    let p = BigUint::from_str_radix("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16).unwrap();
    let g = BigUint::from(2u32);
    let sa = BigUint::from_bytes_be(&random_bytes(192)) % &p;
    let pa = g.modpow(&sa, &p);

    // B -> A
    let sb = BigUint::from_bytes_be(&random_bytes(192)) % &p;
    let pb = g.modpow(&sb, &p);

    // A -> B
    let secret_a = pb.modpow(&sa, &p);
    let msg_a = random_bytes(32);
    let iv_a = random_bytes(16);
    let cipher_a = encipher_cbc(&sha1(&secret_a.to_bytes_be())[..16], &iv_a, &msg_a);

    // B -> A
    let secret_b = pa.modpow(&sb, &p);
    let msg_b = decipher_cbc(&sha1(&secret_b.to_bytes_be())[..16], &iv_a, &cipher_a);
    assert_eq!(msg_a, msg_b);

    // Part II: breaking it

    // A -> M (!!)
    // the values are already compute above

    // M (!!) -> B
    // sends p, g, p instead of p, g, pa

    // A compute secret with p instead of pb
    // (p^X) mod p == 0, always
    let secret_a = p.modpow(&sa, &p);
    assert_eq!(secret_a, BigUint::from(0u32));

    // B compute secret with p instead of pa
    let secret_b = p.modpow(&sb, &p);
    assert_eq!(secret_b, BigUint::from(0u32));

    let cipher_a = encipher_cbc(&sha1(&secret_a.to_bytes_be())[..16], &iv_a, &msg_a);
    let msg_b = decipher_cbc(&sha1(&secret_b.to_bytes_be())[..16], &iv_a, &cipher_a);
    assert_eq!(msg_a, msg_b);

    // of course, knowing that secret is 0, M has a very easy time...
}
