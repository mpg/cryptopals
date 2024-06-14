use aes::cipher::{
    generic_array::GenericArray, BlockDecrypt, BlockEncrypt, BlockSizeUser, KeyInit,
};
use aes::Aes128;
use std::iter::zip;

fn check_lengths(iv: &[u8], data: &[u8]) -> Option<usize> {
    let block_size = Aes128::block_size();
    if data.len() % block_size != 0 || iv.len() != block_size {
        None
    } else {
        Some(block_size)
    }
}

pub fn aes_128_cbc_decrypt(key: &[u8], iv: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
    let cipher = Aes128::new_from_slice(key).ok()?;
    let block_size = check_lengths(iv, ct)?;

    let mut pt = Vec::new();
    let mut prev = iv;
    for i in (0..ct.len()).step_by(block_size) {
        let j = i + block_size;
        let in_block = GenericArray::from_slice(&ct[i..j]);
        let mut out_block = Default::default();
        cipher.decrypt_block_b2b(in_block, &mut out_block);
        let pt_block = zip(out_block, prev).map(|(x, &y)| x ^ y);
        pt.extend(pt_block);
        prev = &ct[i..j];
    }

    Some(pt)
}

pub fn aes_128_cbc_encrypt(key: &[u8], iv: &[u8], pt: &[u8]) -> Option<Vec<u8>> {
    let cipher = Aes128::new_from_slice(key).ok()?;
    let block_size = check_lengths(iv, pt)?;

    let mut ct = Vec::new();
    let mut prev = iv.to_vec();
    for i in (0..pt.len()).step_by(block_size) {
        let j = i + block_size;
        let in_block: Vec<_> = zip(&pt[i..j], &prev).map(|(&x, &y)| x ^ y).collect();
        let in_block = GenericArray::from_slice(&in_block);
        let mut out_block = Default::default();
        cipher.encrypt_block_b2b(in_block, &mut out_block);
        ct.extend_from_slice(out_block.as_slice());
        prev = out_block.to_vec();
    }

    Some(ct)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::prelude::*;

    fn read_ct() -> Vec<u8> {
        let filename = "data/10.txt";
        let mut b64 = std::fs::read(filename).unwrap();
        b64.retain(|&c| c != b'\n');
        BASE64_STANDARD.decode(b64).unwrap()
    }

    #[test]
    fn challenge_decrypt() {
        let ct = read_ct();
        let exp = std::fs::read("data/10-pt.txt").unwrap();
        assert!(ct.len() >= exp.len());
        assert!(ct.len() / 16 == (exp.len() + 15) / 16);

        let key = b"YELLOW SUBMARINE";
        let iv = [0; 16];
        let mut got = aes_128_cbc_decrypt(key, &iv, &ct).unwrap();
        assert!(got.len() == ct.len());
        got.truncate(exp.len());
        assert_eq!(got, exp);
    }

    #[test]
    fn challenge_encrypt() {
        let pt_full = std::fs::read("data/10-pt.txt").unwrap();
        let pt = &pt_full[0..pt_full.len() / 16 * 16];
        let exp = &read_ct()[0..pt.len()];
        let key = b"YELLOW SUBMARINE";
        let iv = [0; 16];

        let got = aes_128_cbc_encrypt(key, &iv, pt).unwrap();
        assert_eq!(got, exp);
    }

    #[test]
    fn bad_len() {
        let s15 = b"WHITE SUBMARINE";
        let s16 = b"YELLOW SUBMARINE";
        let s17 = b"BLUEISH SUBMARINE";

        assert_eq!(aes_128_cbc_decrypt(s16, s16, s15), None);
        assert_eq!(aes_128_cbc_decrypt(s16, s16, s17), None);
        assert_eq!(aes_128_cbc_decrypt(s16, s15, s16), None);
        assert_eq!(aes_128_cbc_decrypt(s16, s17, s16), None);
        assert_eq!(aes_128_cbc_decrypt(s15, s16, s16), None);
        assert_eq!(aes_128_cbc_decrypt(s17, s16, s16), None);

        assert!(aes_128_cbc_decrypt(s16, s16, s16).is_some());

        assert_eq!(aes_128_cbc_encrypt(s16, s16, s15), None);
        assert_eq!(aes_128_cbc_encrypt(s16, s16, s17), None);
        assert_eq!(aes_128_cbc_encrypt(s16, s15, s16), None);
        assert_eq!(aes_128_cbc_encrypt(s16, s17, s16), None);
        assert_eq!(aes_128_cbc_encrypt(s15, s16, s16), None);
        assert_eq!(aes_128_cbc_encrypt(s17, s16, s16), None);

        assert!(aes_128_cbc_encrypt(s16, s16, s16).is_some());
    }
}
