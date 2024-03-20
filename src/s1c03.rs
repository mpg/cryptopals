use std::iter::zip;

#[derive(PartialEq, Debug)]
pub struct SXorCracked {
    pub key: u8,
    pub pt: String,
    pub score: f32,
}

// Cracks a ciphertext encrypted with single-byte XOR,
// assuming the plaintext is English text.
//
// If no key yields a plaintext that's valid UTF-8
// without any control characters, return None.
// Otherwise, return the plaintext whose letter frequencies are
// the most similar to those of English prose.
pub fn sxor_crack(ct: &[u8]) -> Option<SXorCracked> {
    (0..=255)
        .filter_map(|key| sxor_try(key, ct))
        .fold(None, |cur, new| match cur {
            None => Some(new),
            Some(c) => {
                if c.score > new.score {
                    Some(c)
                } else {
                    Some(new)
                }
            }
        })
}

// Trial decryption with one key
fn sxor_try(key: u8, ct: &[u8]) -> Option<SXorCracked> {
    let pt = sxor_decrypt(key, ct)?;
    Some(SXorCracked {
        score: eng_freq_score(&pt),
        key,
        pt,
    })
}

// Decrypt single-byte XOR ciphertext with the given key.
fn sxor_decrypt(key: u8, ct: &[u8]) -> Option<String> {
    let pt_bytes = ct.iter().map(|x| x ^ key).collect();

    // Reject invalid UTF-8
    let pt = String::from_utf8(pt_bytes);
    if pt.is_err() {
        return None;
    }

    // Reject plaintext containing control chars
    let pt = pt.unwrap();
    if pt.chars().any(|c| c.is_control()) {
        return None;
    }

    Some(pt)
}

// Counts each ASCII letter (case-insensitive) in the given text.
fn letter_counts(text: &str) -> Vec<u32> {
    let mut counts = vec![0; 27];
    for c in text.chars() {
        match c {
            'a'..='z' => counts[c as usize - 'a' as usize] += 1,
            'A'..='Z' => counts[c as usize - 'A' as usize] += 1,
            ' ' => counts[26] += 1,
            _ => (),
        }
    }

    counts
}

// https://en.wikipedia.org/wiki/Letter_frequency
// First table, percentages mutiplied by 1000.
// In last position, expected number of spaces for that many letters.
// (Sum of all letters: 100119, divided by 5, rounded.)
const ENGLISH_FREQUENCIES: [u32; 27] = [
    8200, 1500, 2800, 4300, 12700, 2200, 2000, 6100, 7000, 150, 770, 4000, 2400, 6700, 7500, 1900,
    95, 6000, 6300, 9100, 2800, 980, 2400, 150, 2000, 74, 20000,
];

// Computes the scalar product of two vectors
fn scalar_prod(a: &[u32], b: &[u32]) -> u64 {
    assert_eq!(a.len(), b.len());
    zip(a, b).map(|(&x, &y)| x as u64 * y as u64).sum()
}

// Compute a score for letter counts similarity to English text.
// The score is proportional* to the cosine of the angle between
// the vector of letter counts and that of expected letter frequencies:
// the higher the score, the more likely this is English prose.
// (*No need to fully normalize, we only want to compare scores.)
fn eng_freq_score(text: &str) -> f32 {
    let counts = letter_counts(text);
    let norm = scalar_prod(&counts, &counts);
    if norm == 0 {
        return 0.0;
    }
    let prod = scalar_prod(&counts, &ENGLISH_FREQUENCIES);

    prod as f32 / norm as f32
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn challenge() {
        let cth = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        let exp_key = 88;
        let exp_pt = String::from("Cooking MC's like a pound of bacon");

        let ct = hex::decode(cth).unwrap();
        let res = sxor_crack(&ct).unwrap();
        assert_eq!(res.key, exp_key);
        assert_eq!(res.pt, exp_pt);
    }

    #[test]
    fn error() {
        let ct = b"\x00\x20\x40\x60";
        assert_eq!(sxor_crack(ct), None);
    }
}
