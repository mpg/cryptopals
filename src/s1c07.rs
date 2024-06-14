use aes::cipher::{
    generic_array::GenericArray, BlockDecrypt, BlockEncrypt, BlockSizeUser, KeyInit,
};
use aes::Aes128;

enum Way {
    Encrypt,
    Decrypt,
}
use Way::*;

fn aes_128_ecb(key: &[u8], inp: &[u8], way: Way) -> Option<Vec<u8>> {
    let cipher = Aes128::new_from_slice(key).ok()?;

    let block_size = Aes128::block_size();
    if inp.len() % block_size != 0 {
        return None;
    }

    let mut out = Vec::new();
    for in_chunk in inp.chunks_exact(block_size) {
        let in_block = GenericArray::from_slice(in_chunk);
        let mut out_block = Default::default();
        match way {
            Encrypt => cipher.encrypt_block_b2b(in_block, &mut out_block),
            Decrypt => cipher.decrypt_block_b2b(in_block, &mut out_block),
        }
        out.extend_from_slice(out_block.as_slice());
    }

    Some(out)
}

pub fn aes_128_ecb_decrypt(key: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
    aes_128_ecb(key, ct, Decrypt)
}

pub fn aes_128_ecb_encrypt(key: &[u8], pt: &[u8]) -> Option<Vec<u8>> {
    aes_128_ecb(key, pt, Encrypt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::prelude::*;

    fn read_ct() -> Vec<u8> {
        let filename = "data/07.txt";
        let mut b64 = std::fs::read(filename).unwrap();
        b64.retain(|&c| c != b'\n');
        BASE64_STANDARD.decode(b64).unwrap()
    }

    #[test]
    fn challenge_decrypt() {
        let ct = read_ct();
        let exp = std::fs::read("data/07-pt.txt").unwrap();
        assert!(ct.len() >= exp.len());
        assert!(ct.len() / 16 == (exp.len() + 15) / 16);

        let key = b"YELLOW SUBMARINE";
        let mut got = aes_128_ecb_decrypt(key, &ct).unwrap();
        assert!(got.len() == ct.len());
        got.truncate(exp.len());
        assert_eq!(got, exp);
    }

    #[test]
    fn challenge_encrypt() {
        let pt_full = std::fs::read("data/07-pt.txt").unwrap();
        let pt = &pt_full[0..pt_full.len() / 16 * 16];
        let exp = &read_ct()[0..pt.len()];
        let key = b"YELLOW SUBMARINE";

        let got = aes_128_ecb_encrypt(key, pt).unwrap();
        assert_eq!(got, exp);
    }

    #[test]
    fn bad_len() {
        let ct1 = b"WHITE SUBMARINE";
        let key = b"YELLOW SUBMARINE";
        let ct2 = b"BLUEISH SUBMARINE";
        assert_eq!(aes_128_ecb_decrypt(key, ct1), None);
        assert_eq!(aes_128_ecb_decrypt(key, ct2), None);
        assert_eq!(aes_128_ecb_decrypt(ct1, key), None);
        assert_eq!(aes_128_ecb_decrypt(ct2, key), None);

        assert_eq!(aes_128_ecb_encrypt(key, ct1), None);
        assert_eq!(aes_128_ecb_encrypt(key, ct2), None);
        assert_eq!(aes_128_ecb_encrypt(ct1, key), None);
        assert_eq!(aes_128_ecb_encrypt(ct2, key), None);
    }
}
