use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockSizeUser, KeyInit};
use aes::Aes128;

pub fn aes_128_ecb_decrypt(key: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
    let cipher = Aes128::new_from_slice(key).ok()?;

    let block_size = Aes128::block_size();
    if ct.len() % block_size != 0 {
        return None;
    }

    let mut pt = Vec::new();
    for i in (0..ct.len()).step_by(block_size) {
        let j = i + block_size;
        let in_block = GenericArray::from_slice(&ct[i..j]);
        let mut out_block = Default::default();
        cipher.decrypt_block_b2b(in_block, &mut out_block);
        pt.extend_from_slice(out_block.as_slice());
    }

    Some(pt)
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
    fn challenge() {
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
    fn bad_len() {
        let ct1 = b"WHITE SUBMARINE";
        let key = b"YELLOW SUBMARINE";
        let ct2 = b"BLUEISH SUBMARINE";
        assert_eq!(aes_128_ecb_decrypt(key, ct1), None);
        assert_eq!(aes_128_ecb_decrypt(key, ct2), None);
        assert_eq!(aes_128_ecb_decrypt(ct1, key), None);
        assert_eq!(aes_128_ecb_decrypt(ct2, key), None);
    }
}
