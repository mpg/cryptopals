use crate::s1c03::sxor_crack;
use crate::s1c05::rep_xor;

#[derive(PartialEq, Debug)]
pub struct RepXorCracked {
    pub key: Vec<u8>,
    pub pt: String,
}

pub fn crack_rep_xor(ct: &[u8]) -> Option<RepXorCracked> {
    let key_size = guess_key_size(ct);
    let slices = transpose(ct, key_size);
    let key = guess_key(&slices)?;
    let pt_bytes = rep_xor(&key, ct);
    let pt = String::from_utf8(pt_bytes).unwrap();
    Some(RepXorCracked { key, pt })
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

fn transpose(ct: &[u8], bs: usize) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = vec![vec![]; bs];
    (0..ct.len()).for_each(|i| out[i % bs].push(ct[i]));
    out
}

fn guess_key(slices: &[Vec<u8>]) -> Option<Vec<u8>> {
    let mut key = vec![0; slices.len()];
    for i in 0..key.len() {
        let sol = sxor_crack(&slices[i])?;
        key[i] = sol.key;
    }
    Some(key)
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
    fn challenge() {
        let ct = read_ct();
        let key = b"Terminator X: Bring the noise".to_vec();
        let pt = std::fs::read_to_string("data/06-pt.txt").unwrap();
        assert_eq!(ct.len(), pt.len());
        let exp = RepXorCracked { key, pt };
        assert_eq!(crack_rep_xor(&ct), Some(exp));
    }
}
