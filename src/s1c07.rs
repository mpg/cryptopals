pub fn aes_128_ecb_decrypt(key: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
    todo!("Decrypt {:?}... using {:?}...", ct[0], key[0]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::prelude::*;

    fn read_ct() -> Vec<u8> {
        let filename = "data/06.txt";
        let mut b64 = std::fs::read(filename).unwrap();
        b64.retain(|&c| c != b'\n');
        BASE64_STANDARD.decode(b64).unwrap()
    }

    #[test]
    #[ignore]
    fn challenge() {
        let ct = read_ct();
        let pt = std::fs::read("data/06-pt.txt").unwrap();
        assert_eq!(ct.len(), pt.len());
        let key = b"YELLOW SUBMARINE";
        assert_eq!(aes_128_ecb_decrypt(key, &ct), Some(pt));
    }

    #[test]
    #[ignore]
    fn bad_len() {
        let ct1 = b"WHITE SUBMARINE";
        let key = b"YELLOW SUBMARINE";
        let ct2 = b"BLUEISH SUBMARINE";
        assert_eq!(aes_128_ecb_decrypt(key, ct1), None);
        assert_eq!(aes_128_ecb_decrypt(key, ct2), None);
    }
}
