// Cryptopals Set 5

#![allow(dead_code)]

use crate::bits::*;
use crate::sha1::*;
use crate::dh::*;
use crate::srp::*;

use num::{
    bigint::ToBigInt,
    Integer,
    Signed,
    Num,
    BigUint,
    BigInt,
    One,
    Zero,
};

use rand::{thread_rng, seq::SliceRandom};
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac, NewMac};

use glass_pumpkin::prime;

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

//=============================================================================
// CHALLENGE 38
//=============================================================================

// Offline dictionary attack on simplified SRP
pub fn challenge38() {
    let p = BigUint::from_str_radix("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16).unwrap();
    let g = BigUint::from(2u32);
    let k = BigUint::from(3u32);
    let user = "user@example.com";
    let password = random_ascii_string(16);

    // part I -- test that simplified SRP is working
    let mut server = SRPServer::new(p.clone(), g.clone(), k.clone());
    server.enroll(user, &password);

    let mut client = SRPClient::new(p.clone(), g.clone(), k.clone(), user);
    let (user, aa) = client.first();

    let (salt, bb, u) = server.first_simplified();

    let client_mac = client.second_simplified(&password, salt, &bb, u);
    let server_mac = server.second_simplified(&user, &aa);

    assert_eq!(client_mac, server_mac);

    // part II -- evil server does the dictionary attack

    // lets make a realer version using a list of words
    // (a very small one, I wanted this code to run fast even in debug mode)
    let words : Vec<_> = include_str!("5-38.txt").lines().collect();
    let mut client = SRPClient::new(p.clone(), g.clone(), k.clone(), &user);

    // password is randomly choosen from the list of words above
    let mut rng = thread_rng();
    let password = *words.choose(&mut rng).unwrap();

    let b = BigUint::from_bytes_be(&random_bytes(128));
    let bb = g.modpow(&b, &p);
    let u = 1u128;
    let salt = 0u128;

    let (_, aa) = client.first();
    let aab = aa.modpow(&b, &p);
    let client_mac = client.second_simplified(&password, salt, &bb, u);
    let ub = BigUint::from(u);

    let mut hasher = Sha256::new();
    let mut found = None;
    for guess in words {
        hasher.update(salt.to_string().as_bytes());
        hasher.update(guess.as_bytes());
        let x = BigUint::from_bytes_be(&hasher.finalize_reset());

        // S == B**(a + ux) == (B**a) * (B**ux) == (A**b) * (B**ux)
        let s = (&aab * bb.modpow(&(&ub * &x), &p)) % &p;
        hasher.update(&s.to_bytes_be());
        let key = hasher.finalize_reset();

        let mut mac = Hmac::<Sha256>::new_from_slice(&key).unwrap();
        mac.update(salt.to_string().as_bytes());
        let server_mac = mac.finalize().into_bytes().to_vec();

        if server_mac == client_mac {
            found = Some(guess.to_string());
            break;
        }
    }

    assert!(found.is_some());
    assert_eq!(found.unwrap(), password);
}

//=============================================================================
// CHALLENGE 39
//=============================================================================

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
fn invmod(a: &BigUint, m: &BigUint) -> Option<BigUint> {
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
struct PublicKey(BigUint, BigUint);

#[derive(Debug)]
struct PrivateKey(BigUint, BigUint);

fn random_keypair(bits: usize) -> (PublicKey, PrivateKey) {
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

fn message_to_biguint(m: &[u8]) -> BigUint {
    BigUint::from_bytes_be(m)
}

fn biguint_to_message(m: &BigUint) -> Vec<u8> {
    m.to_bytes_be()
}

fn encrypt_pk(m: &BigUint, pk: &PublicKey) -> BigUint {
    m.modpow(&pk.0, &pk.1)
}

fn decrypt_sk(c: &BigUint, sk: &PrivateKey) -> BigUint {
    c.modpow(&sk.0, &sk.1)
}

// Implement RSA
pub fn challenge39() {
    // quick'n'dirty check
    assert_eq!(invmod(&BigUint::from(17u32), &BigUint::from(3120u32)).unwrap(), BigUint::from(2753u32));

    // using 256-bit keys for speed
    // validate the math anyway
    for _ in 0..10 {
        let (pk, sk) = random_keypair(256);
        let msg = random_bytes(31);
        let m = message_to_biguint(&msg);
        let c = encrypt_pk(&m, &pk);
        let d = decrypt_sk(&c, &sk);
        let opn = biguint_to_message(&d);
        assert_eq!(msg, opn);
    }
}

//=============================================================================
// CHALLENGE 40
//=============================================================================

// Implement an E=3 RSA Broadcast attack
pub fn challenge40() {

    let msg = random_bytes(31);
    let m = BigUint::from_bytes_be(&msg);

    let (pk1, _sk1) = random_keypair(512);
    let c1 = encrypt_pk(&m, &pk1);

    let (pk2, _sk2) = random_keypair(512);
    let c2 = encrypt_pk(&m, &pk2);

    let (pk3, _sk3) = random_keypair(512);
    let c3 = encrypt_pk(&m, &pk3);

    let ms0 = &pk2.1 * &pk3.1;
    let ms1 = &pk1.1 * &pk3.1;
    let ms2 = &pk1.1 * &pk2.1;
    let n012 = &pk1.1 * &pk2.1 * &pk3.1;

    let result =
        ((&c1 * &ms0 * &invmod(&ms0, &pk1.1).expect("invmod(ms0, pk1)")) +
         (&c2 * &ms1 * &invmod(&ms1, &pk2.1).expect("invmod(ms1, pk2)")) +
         (&c3 * &ms2 * &invmod(&ms2, &pk3.1).expect("invmod(ms2, pk3)"))) % &n012;

    assert_eq!(&m * &m * &m, result);

    let m2 = result.nth_root(3);
    assert_eq!(&m, &m2);
}

