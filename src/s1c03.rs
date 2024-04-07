use std::iter::zip;

#[derive(PartialEq, Debug)]
pub struct SXorCracked {
    pub key: u8,
    pub pt: String,
    pub badness: u32,
}

// Cracks a ciphertext encrypted with single-byte XOR,
// assuming the plaintext is English text.
//
// If no key yields a plaintext that's printable ASCII, return None.
// Otherwise, return the plaintext whose letter frequencies are
// the most similar to those of English prose.
pub fn sxor_crack(ct: &[u8]) -> Option<SXorCracked> {
    (0..=255)
        .filter_map(|key| sxor_try(key, ct))
        .min_by_key(|res| res.badness)
}

// Trial decryption with one key
fn sxor_try(key: u8, ct: &[u8]) -> Option<SXorCracked> {
    let pt = sxor_decrypt(key, ct)?;
    Some(SXorCracked {
        badness: eng_freq_badness(&pt),
        key,
        pt,
    })
}

// Decrypt single-byte XOR ciphertext with the given key.
fn sxor_decrypt(key: u8, ct: &[u8]) -> Option<String> {
    let pt_bytes = ct.iter().map(|x| x ^ key).collect();
    let pt = String::from_utf8(pt_bytes).ok()?;

    // Only accept printable ASCII
    match pt
        .chars()
        .all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
    {
        true => Some(pt),
        false => None,
    }
}

// Frequencies of each category: each letter, space, other.
fn cat_freqs(text: &str) -> Vec<f32> {
    let unit = 1.0 / text.len() as f32;
    let mut freqs = vec![0.0; 28];
    for c in text.chars() {
        match c {
            'a'..='z' => freqs[c as usize - 'a' as usize] += unit,
            'A'..='Z' => freqs[c as usize - 'A' as usize] += unit,
            ' ' => freqs[26] += unit,
            _ => freqs[27] += unit,
        }
    }
    freqs
}

// https://en.wikipedia.org/wiki/Letter_frequency
// Guesstimate space at 20% and other at 5%, leaving 75% letters.
const ENGLISH_FREQS: [f32; 28] = [
    8.2 * 0.75 / 100.0,   // A
    1.5 * 0.75 / 100.0,   // B
    2.8 * 0.75 / 100.0,   // C
    4.3 * 0.75 / 100.0,   // D
    12.7 * 0.75 / 100.0,  // E
    2.2 * 0.75 / 100.0,   // F
    2.0 * 0.75 / 100.0,   // G
    6.1 * 0.75 / 100.0,   // H
    7.0 * 0.75 / 100.0,   // I
    0.15 * 0.75 / 100.0,  // J
    0.77 * 0.75 / 100.0,  // K
    4.0 * 0.75 / 100.0,   // L
    2.4 * 0.75 / 100.0,   // M
    6.7 * 0.75 / 100.0,   // N
    7.5 * 0.75 / 100.0,   // O
    1.9 * 0.75 / 100.0,   // P
    0.095 * 0.75 / 100.0, // Q
    6.0 * 0.75 / 100.0,   // R
    6.3 * 0.75 / 100.0,   // S
    9.1 * 0.75 / 100.0,   // T
    2.8 * 0.75 / 100.0,   // U
    0.98 * 0.75 / 100.0,  // V
    2.4 * 0.75 / 100.0,   // W
    0.15 * 0.75 / 100.0,  // X
    2.0 * 0.75 / 100.0,   // Y
    0.074 * 0.75 / 100.0, // Z
    20.0 / 100.0,         // space
    5.0 / 100.0,          // other
];

// Diffence between candidate and reference using chi-squared.
// https://en.wikipedia.org/wiki/Chi-squared_test#Applications
// Convert to u32 as f32 does not implement std:cmp::Ord.
fn eng_freq_badness(text: &str) -> u32 {
    let freqs = cat_freqs(text);
    (zip(freqs, ENGLISH_FREQS)
        .map(|(got, exp)| (got - exp).powf(2.0) / exp)
        .sum::<f32>()
        * 100.0) as u32
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
        // one of the bytes will be >= 128 after XORing
        let ct = b"\x00\x80";
        assert_eq!(sxor_crack(ct), None);
    }

    #[test]
    #[ignore]
    fn debug() {
        let cth = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        let ct = hex::decode(cth).unwrap();
        for key in 0..=255 {
            if let Some(res) = sxor_try(key, &ct) {
                println!("{} {:?}", res.badness, res.pt);
            }
        }
        panic!() // so that the above gets printed out
    }
}
