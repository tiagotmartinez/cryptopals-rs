// Cryptopals Set 5

#![allow(dead_code)]

// use std::time::{Instant, Duration};
// use rand::RngCore;
// use rand::distributions::{Distribution, Uniform};

// use crate::english::*;
// use crate::pkcs7::*;
// use crate::aes::*;
use crate::bits::*;
use crate::sha1::*;
use crate::dh::*;
use crate::srp::*;
// use crate::md4::*;
// use crate::mt::*;

use num::{Num, BigUint, One, Zero};
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac, NewMac};

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

    let p = BigUint::from_str_radix("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16).unwrap();
    let g = BigUint::from(2u32);

    let alice = DHKeyExchange1::new(p.clone(), g.clone());
    let bob = DHKeyExchange1::new(p.clone(), g.clone());

    let alice = alice.generate_secret(bob.public_key());
    let bob = bob.generate_secret(alice.public_key());

    assert_eq!(alice.secret_key(), bob.secret_key());

    let message = random_bytes(32);
    let cipher_a = alice.encipher(&message);
    let message_b = bob.decipher(&cipher_a).unwrap();
    assert_eq!(message, message_b);

    // Part II: breaking it with key-fixing

    let alice = DHKeyExchange1::new(p.clone(), g.clone());
    let bob = DHKeyExchange1::new(p.clone(), g.clone());

    // Oh noes!!! M sent `p` instead of public key to both Alice and Bob!!!
    let alice = alice.generate_secret(&p);
    let bob = bob.generate_secret(&p);
    assert_eq!(alice.secret_key(), bob.secret_key());

    // Since (p^<whatever>) mod p == 0, Marge can simply *not* do the DH math
    // and only SHA1(<zeroes>)... WHA HA HA HA!!!
    let key : Vec<_> = sha1(&[0]).drain(..16).collect();
    assert_eq!(&key, alice.secret_key());

    // Do the long test
    let marge = DHKeyExchange1::new(p.clone(), g.clone()).generate_secret(&p);
    let cipher_a = alice.encipher(&message);
    let message_m = marge.decipher(&cipher_a).unwrap();
    assert_eq!(message, message_m);
}

//=============================================================================
// CHALLENGE 35
//=============================================================================

// Implement DH with negotiated groups, and break with malicious "g" parameters
pub fn challenge35() {
    let p = BigUint::from_str_radix("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16).unwrap();


    // g == 1, secret is always 1
    let g = BigUint::one();
    let alice = DHKeyExchange1::new(p.clone(), g.clone());
    let bob = DHKeyExchange1::new(p.clone(), g.clone());
    let bob = bob.generate_secret(alice.public_key());
    assert_eq!(bob.secret(), &BigUint::one());

    // g == p, secret is always 0
    let g = p.clone();
    let alice = DHKeyExchange1::new(p.clone(), g.clone());
    let bob = DHKeyExchange1::new(p.clone(), g.clone());
    let bob = bob.generate_secret(alice.public_key());
    assert_eq!(bob.secret(), &BigUint::zero());

    // g == p - 1, therefore secret is either 1 or p - 1
    let g = &p - BigUint::one();
    let alice = DHKeyExchange1::new(p.clone(), g.clone());
    let bob = DHKeyExchange1::new(p.clone(), g.clone());
    let bob = bob.generate_secret(alice.public_key());
    assert!(bob.secret() == &BigUint::one() || bob.secret() == &g);
}

//=============================================================================
// CHALLENGE 36
//=============================================================================

// Implement Secure Remote Password (SRP)
pub fn challenge36() {
    let p = BigUint::from_str_radix("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16).unwrap();
    let user = "user@example.com";
    let password = random_ascii_string(16);

    let mut client = SRPClient::new(p.clone(), BigUint::from(2u32), BigUint::from(3u32), user);
    let mut server = SRPServer::new(p.clone(), BigUint::from(2u32), BigUint::from(3u32));
    server.enroll(user, &password);

    let (salt, bb) = server.first();
    let (user, aa) = client.first();

    let client_mac = client.second(&password, salt, &bb);
    let server_mac = server.second(&user, &aa);

    assert_eq!(client_mac, server_mac);
}

//=============================================================================
// CHALLENGE 37
//=============================================================================

// Break SRP with a zero key
pub fn challenge37() {
    // we are the evil client, but use the standard (working) SRPServer from challenge 36
    let p = BigUint::from_str_radix("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16).unwrap();
    let user = "user@example.com";
    let password = random_ascii_string(16);

    // the actual enroll on the server
    let mut server = SRPServer::new(p.clone(), BigUint::from(2u32), BigUint::from(3u32));
    server.enroll(user, &password);

    // evil client!
    let (salt, _bb) = server.first();
    let aa = BigUint::zero();
    let server_mac = server.second(&user, &aa);

    // if aa == 0 then s == 0 inside SRPServer::server()
    let s = BigUint::zero();

    let mut hasher = Sha256::new();
    hasher.update(&s.to_bytes_be());
    let key = hasher.finalize().to_vec();

    let mut mac = Hmac::<Sha256>::new_from_slice(&key).unwrap();
    mac.update(salt.to_string().as_bytes());
    let client_mac = mac.finalize().into_bytes().to_vec();

    assert_eq!(client_mac, server_mac);

    // test with aa == k*N. as N is the zero element mod N, then s == 0 as well

    // use k == 3, but can be anything really
    let aa = &p * BigUint::from(3u32);
    let mut server = SRPServer::new(p.clone(), BigUint::from(2u32), BigUint::from(3u32));
    server.enroll(user, &password);
    let (salt, _bb) = server.first();
    let server_mac = server.second(&user, &aa);

    // recompute Hmac because of different salt
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).unwrap();
    mac.update(salt.to_string().as_bytes());
    let client_mac = mac.finalize().into_bytes().to_vec();

    assert_eq!(client_mac, server_mac);
}
