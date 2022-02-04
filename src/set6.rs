// Cryptopals Set 6

#![allow(dead_code)]

use std::collections::HashSet;

use num::BigUint;

//use crate::bits::*;
use crate::sha1::*;
//use crate::dh::*;
//use crate::srp::*;
use crate::rsa::*;

//=============================================================================
// CHALLENGE 41
//=============================================================================

// Implement unpadded message recovery oracle
pub fn challenge41() {

    let (pk, sk) = random_keypair(512);
    let mut seen = HashSet::new();

    fn make_message(social: &str) -> Vec<u8> {
        let now = std::time::SystemTime::now();
        format!("{{ time: {}, social: '{}' }}",
            now.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
            social
        ).as_bytes().to_vec()
    }

    fn decrypt(seen: &mut HashSet<Vec<u8>>, sk: &PrivateKey, data: &[u8]) -> Option<Vec<u8>> {
        let h = sha1(data);
        if seen.get(&h).is_some() {
            None
        } else {
            seen.insert(h);
            Some(biguint_to_message(&decrypt_sk(&message_to_biguint(data), sk)))
        }
    }

    // check that decryption works and that repeated messages are not decrypted
    let msg1 = make_message("555-55-5555");
    let big1 = message_to_biguint(&msg1);
    let ct1 = encrypt_pk(&big1, &pk);
    let pt1 = decrypt(&mut seen, &sk, &biguint_to_message(&ct1));
    assert!(pt1.is_some());
    assert_eq!(pt1.unwrap(), msg1);
    let pt1 = decrypt(&mut seen, &sk, &biguint_to_message(&ct1));
    assert!(pt1.is_none());

    // attack time!
    let s = BigUint::from(41u32);
    let si = invmod(&s, &pk.1).unwrap();
    let ct2 = (&encrypt_pk(&s, &pk) * &ct1) % &pk.1;
    let pt2 = decrypt(&mut seen, &sk, &biguint_to_message(&ct2)).unwrap();
    let pt2 = biguint_to_message(&((&message_to_biguint(&pt2) * &si) % &pk.1));
    assert_eq!(pt2, msg1);
}
