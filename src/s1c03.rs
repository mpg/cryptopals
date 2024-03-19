#[derive(PartialEq, Debug)]
pub struct SXorCracked {
    pub key: u8,
    pub pt: String,
}

// Cracks a ciphertext encrypted with single-byte XOR,
// assuming the plaintext is English text.
pub fn sxor_crack(ct: &[u8]) -> Option<SXorCracked> {
    todo!("crack {:?}", ct);
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn challenge() {
        let cth = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        let exp = SXorCracked {
            key: 88,
            pt: String::from("Cooking MC's like a pound of bacon"),
        };

        let ct = hex::decode(cth).unwrap();
        assert_eq!(sxor_crack(&ct), Some(exp));
    }
}
