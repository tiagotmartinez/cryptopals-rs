// AES encryption/decryption helpers

#![allow(dead_code)]

use crate::bits::*;
use aes::{Aes128, Block};
use aes::cipher::{
    BlockEncrypt, BlockDecrypt, NewBlockCipher,
};

/// A zero value IV for use with AES
pub static ZERO_IV: [u8; aes::BLOCK_SIZE] = [0u8; aes::BLOCK_SIZE];

/// Decipher `ct` in AES-128-ECB using `key`.
pub fn decipher_ecb(key: &[u8], ct: &[u8]) -> Vec<u8> {
    assert!(ct.len() % aes::BLOCK_SIZE == 0);
    let cipher = Aes128::new_from_slice(key).unwrap();
    let mut pt = vec![];
    for c in ct.chunks(aes::BLOCK_SIZE) {
        let mut blk = Block::clone_from_slice(c);
        cipher.decrypt_block(&mut blk);
        pt.extend_from_slice(&blk);
    }
    pt
}

/// Encipher `pt` in AES-128-ECB using `key`.
pub fn encipher_ecb(key: &[u8], pt: &[u8]) -> Vec<u8> {
    assert!(pt.len() % aes::BLOCK_SIZE == 0);
    let cipher = Aes128::new_from_slice(key).unwrap();
    let mut ct = vec![];
    for p in pt.chunks(aes::BLOCK_SIZE) {
        let mut blk = Block::clone_from_slice(p);
        cipher.encrypt_block(&mut blk);
        ct.extend_from_slice(&blk);
    }
    ct
}

/// Decipher `ct` in AES-128-CBC using `key` and `iv`.
///
/// Does **not** remove padding!!! Must do this manually on result!!!
pub fn decipher_cbc(key: &[u8], iv: &[u8], ct: &[u8]) -> Vec<u8> {
    assert!(ct.len() % aes::BLOCK_SIZE == 0);
    assert!(iv.len() == aes::BLOCK_SIZE);

    let mut pt = Vec::new();
    let mut iv = iv.to_vec();

    let cipher = Aes128::new_from_slice(&key).unwrap();
    for c in ct.chunks(aes::BLOCK_SIZE) {
        let mut blk = Block::clone_from_slice(c);
        cipher.decrypt_block(&mut blk);
        xor_into_left(&mut blk, &iv);
        pt.extend_from_slice(&blk);
        iv.copy_from_slice(c);
    }

    pt
}

/// Encipher `pt` in AES-128-CBC using `key` and `iv`.
pub fn encipher_cbc(key: &[u8], iv: &[u8], pt: &[u8]) -> Vec<u8> {
    assert!(pt.len() % aes::BLOCK_SIZE == 0);
    assert!(iv.len() == aes::BLOCK_SIZE);

    let mut ct = Vec::new();
    let mut iv = iv.to_vec();

    let cipher = Aes128::new_from_slice(&key).unwrap();
    for p in pt.chunks(aes::BLOCK_SIZE) {
        let mut blk = Block::clone_from_slice(p);
        xor_into_left(&mut blk, &iv);
        cipher.encrypt_block(&mut blk);
        ct.extend_from_slice(&blk);
        iv.copy_from_slice(&blk);
    }

    ct
}

/// XOR `data` with the keystream from AES-CTR with `key` and `nonce`, return
/// the result.
pub fn aes_ctr(key: &[u8], nonce: u64, data: &[u8]) -> Vec<u8> {
    let cipher = Aes128::new_from_slice(&key).unwrap();
    let mut ct = data.to_vec();
    let mut blk = Block::default();
    for (count, p) in ct.chunks_mut(aes::BLOCK_SIZE).enumerate() {
        u64_into_bytes_little_endian(nonce, &mut blk[..8]);
        u64_into_bytes_little_endian(count as u64, &mut blk[8..]);
        cipher.encrypt_block(&mut blk);
        for i in 0..p.len() {
            p[i] ^= blk[i];
        }
    }
    ct
}
