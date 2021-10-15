// PKCS#7 padding

#![allow(dead_code)]

pub fn pad(n: usize, data: &[u8]) -> Vec<u8> {
    let pad_bytes = if data.len() % n == 0 { n } else { n - (data.len() % n) };
    assert!(pad_bytes <= n);
    let mut v = data.to_vec();
    for _ in 0 .. pad_bytes {
        v.push(pad_bytes as u8);
    }
    v
}

pub fn unpad(data: &[u8]) -> Result<Vec<u8>, String> {
    if let Some(&pad_byte) = data.last() {
        let pad_bytes = pad_byte as usize;
        if pad_bytes == 0 || data.len() < pad_bytes || !data[data.len() - pad_bytes ..].iter().all(|&b| b == pad_byte) {
            Err(format!("invalid padding"))
        } else {
            Ok(data[..data.len() - pad_bytes].to_vec())
        }
    } else {
        Err("invalid padding".to_string())
    }
}

