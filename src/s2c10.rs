pub fn aes_128_cbc_decrypt(key: &[u8], iv: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
    todo!("Decrypt {:?}... using {:?}+{:?}...", ct[0], key[0], iv[0]);
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
    #[ignore]
    fn challenge() {
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
    #[ignore]
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
    }
}
