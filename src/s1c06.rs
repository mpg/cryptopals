#[derive(PartialEq, Debug)]
pub struct RepXorCracked {
    pub key: Vec<u8>,
    pub pt: String,
}

pub fn crack_rep_xor(ct: &[u8]) -> Option<RepXorCracked> {
    todo!("Crack ciphertext of length {}", ct.len());
}

pub fn hamming_dst(a: &[u8], b: &[u8]) -> u32 {
    std::iter::zip(a, b)
        .map(|(&x, &y)| (x ^ y).count_ones())
        .sum()
}

pub fn guess_key_size(ct: &[u8]) -> usize {
    todo!("Guess the key size for ciphertext of length {}", ct.len());
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::prelude::*;

    #[test]
    fn step1() {
        let a = b"this is a test";
        let b = b"wokka wokka!!!";

        assert_eq!(hamming_dst(a, b), 37);
    }

    fn read_ct() -> Vec<u8> {
        let filename = "data/06.txt";
        let mut b64 = std::fs::read(filename).unwrap();
        b64.retain(|&c| c != b'\n');
        BASE64_STANDARD.decode(b64).unwrap()
    }

    #[test]
    fn step2() {
        let ct = read_ct();
        assert_eq!(guess_key_size(&ct), 29);
    }

    #[ignore]
    #[test]
    fn challenge() {
        let ct = read_ct();
        let key = b"Terminator X: Bring the noise".to_vec();
        let pt = std::fs::read_to_string("data/06-pt.txt").unwrap();
        assert_eq!(ct.len(), pt.len());
        let exp = RepXorCracked { key, pt };
        assert_eq!(crack_rep_xor(&ct), Some(exp));
    }
}
