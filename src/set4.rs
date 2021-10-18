// Cryptopals Set 4

#![allow(dead_code)]

use rand::RngCore;
use rand::distributions::{Distribution, Uniform};

use crate::english::*;
use crate::pkcs7::*;
use crate::aes::*;
use crate::bits::*;
use crate::mt::*;

use aes::Aes128;
use aes::cipher::NewBlockCipher;

static mut GLOBAL_KEY: [u8; 16] = [0u8; 16];

//=============================================================================
// CHALLENGE 25
//=============================================================================

// Generate the keystream from (`key`, `nonce`) starting at `offset` with `length` bytes.
fn aes_ctr_keystream_at(key: &[u8], nonce: u64, offset: usize, length: usize) -> Vec<u8> {
    let mut block_id = offset / aes::BLOCK_SIZE;
    let mut index = offset % aes::BLOCK_SIZE;
    let mut ks = vec![];
    let mut blk = vec![0u8; 16];
    let aes = Aes128::new_from_slice(key).unwrap();
    while ks.len() != length {
        aes_ctr_block(&aes, nonce, block_id as u64, &mut blk);
        while ks.len() != length && index < aes::BLOCK_SIZE {
            ks.push(blk[index]);
            index += 1;
        }
        index = 0;
        block_id += 1;
    }
    ks
}

// Modify the contents of `ciphertext[offset .. offset+newtext.len()]` to the encrypted value of `newtext`.
fn edit(ciphertext: &mut [u8], offset: usize, newtext: &[u8]) {
    let ks = aes_ctr_keystream_at(unsafe { &GLOBAL_KEY }, 0, offset, newtext.len());
    for i in 0..newtext.len() {
        ciphertext[offset + i] = newtext[i] ^ ks[i];
    }
}

// Break "random access read/write" AES CTR
pub fn challenge25() {
    unsafe {
        GLOBAL_KEY.copy_from_slice(&random_bytes(16));
    }

    let text = base64_decode_text(include_str!("4-25.txt"));
    let mut cipher = aes_ctr(unsafe { &GLOBAL_KEY }, 0, &text);

    // decrypt byte-per-byte; could also operate on larger blocks
    let mut plain = vec![];
    for i in 0..cipher.len() {
        let b = cipher[i];
        edit(&mut cipher, i, &[0]);
        plain.push(b ^ cipher[i]);
    }

    assert_eq!(plain, text);
}
