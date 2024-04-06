#[derive(PartialEq, Debug)]
pub struct RepXorCracked {
    pub key: Vec<u8>,
    pub pt: String,
}

pub fn crack_rep_xor(ct: &[u8]) -> Option<RepXorCracked> {
    let key_size = guess_key_size(ct);
    todo!("Crack ciphertext now that we now key size is {}", key_size);
}

// Average hamming distance between a char and that one block away.
// (Equivalent to the recommended method though slightly different.)
// Don't return f32 as those are not comparable.
fn avg_hamming_dst(ct: &[u8], bs: usize) -> u32 {
    let end = ct.len() - bs;
    (0..end)
        .map(|i| (ct[i] ^ ct[i + bs]).count_ones())
        .sum::<u32>()
        * 100 // preserve some precision
        / end as u32
}

fn guess_key_size(ct: &[u8]) -> usize {
    (2..42).min_by_key(|&bs| avg_hamming_dst(ct, bs)).unwrap()
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
    fn step2_key_size() {
        let ct = read_ct();
        assert_eq!(guess_key_size(&ct), 29);
    }

    #[test]
    #[ignore]
    fn challenge() {
        let ct = read_ct();
        let key = b"Terminator X: Bring the noise".to_vec();
        let pt = std::fs::read_to_string("data/06-pt.txt").unwrap();
        assert_eq!(ct.len(), pt.len());
        let exp = RepXorCracked { key, pt };
        assert_eq!(crack_rep_xor(&ct), Some(exp));
    }
}
