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
// If no key yields a plaintext that's printable ASCII, return None.
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

// Frequencies of each ASCII letter (case-insensitive) in the given text.
// Also spaces.
fn letter_freqs(text: &str) -> Vec<f32> {
    let unit = 1.0 / text.len() as f32;
    let mut freqs = vec![0.0; 27];
    for c in text.chars() {
        match c {
            'a'..='z' => freqs[c as usize - 'a' as usize] += unit,
            'A'..='Z' => freqs[c as usize - 'A' as usize] += unit,
            ' ' => freqs[26] += unit,
            _ => (),
        }
    }
    freqs
}

// https://en.wikipedia.org/wiki/Letter_frequency
// Add space - English words are 4.7 letters long on average so let's say 25%.
// (Should reduce other percentages to make room, boost that one instead,
// and live with the fact that the vector is not normalized.)
const ENGLISH_FREQS: [f32; 27] = [
    8.2,   // A
    1.5,   // B
    2.8,   // C
    4.3,   // D
    12.7,  // E
    2.2,   // F
    2.0,   // G
    6.1,   // H
    7.0,   // I
    0.15,  // J
    0.77,  // K
    4.0,   // L
    2.4,   // M
    6.7,   // N
    7.5,   // O
    1.9,   // P
    0.095, // Q
    6.0,   // R
    6.3,   // S
    9.1,   // T
    2.8,   // U
    0.98,  // V
    2.4,   // W
    0.15,  // X
    2.0,   // Y
    0.074, // Z
    25.0,  // space
];

// Compute a score for letter counts similarity to English text.
//
// Use the scalar product of the vectors as the score.
// It's higher when:
// - the vectors are nearly colinear (that is, similar weights distribution),
// - the proportion of letters (and space) in the text is higher.
fn eng_freq_score(text: &str) -> f32 {
    let freqs = letter_freqs(text);
    zip(freqs, ENGLISH_FREQS).map(|(x, y)| x * y).sum()
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
    //#[ignore]
    fn debug() {
        let cth = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        let ct = hex::decode(cth).unwrap();
        for key in 0..=255 {
            if let Some(res) = sxor_try(key, &ct) {
                println!("{} {:?}", res.score, res.pt);
            }
        }
        assert!(false);
    }
}
