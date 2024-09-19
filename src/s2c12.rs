// use a separate module for privacy
mod oracle {
    use crate::s1c07::aes_128_ecb_encrypt;
    use rand::{thread_rng, Rng};

    pub struct Oracle {
        content: Vec<u8>,
        key: [u8; 16],
    }

    impl Oracle {
        pub fn new(content: &[u8]) -> Self {
            let content = content.to_owned();

            let mut key = [0u8; 16];
            thread_rng().fill(&mut key[..]);

            Self { content, key }
        }

        pub fn process(&self, input: &[u8]) -> Vec<u8> {
            let mut clear = Vec::new();
            clear.extend_from_slice(input);
            clear.extend_from_slice(&self.content);

            // Use random padding; we could use PKCS7 or any other
            // deterministic padding, this is just to illustrate that the
            // attacker doesn't need any knowledge of the padding used.
            let mut padding = [0u8; 16];
            thread_rng().fill(&mut padding[..]);
            let pad_len = 16 - clear.len() % 16;
            clear.extend_from_slice(&padding[..pad_len]);

            aes_128_ecb_encrypt(&self.key, &clear).unwrap()
        }
    }
}

use oracle::Oracle;

// Find the length of the content hidden in the Oracle.
// We need to know that the padding length is between 1 and 16
// (that is, a full block of padding is inserted if the length
// before padding was already a multiple of 16).
// (And contrary to the instructions we assume
// we already know the block length is 16.)
fn attack_len(victim: Oracle) -> usize {
    let base = victim.process(b"").len();
    let mybytes = [0; 16];
    let mut len = 1;
    loop {
        if victim.process(&mybytes[..len]).len() != base {
            break;
        }
        len += 1;
    }

    // Last ciphertext had length base + 16 and cleartext consisted of:
    // mybytes + content + 16 bytes of padding, so
    // len + content_len + 16 = base + 16.
    base - len
}

// Find the content hidden in the Oracle
// victim.content is private and can't be read
pub fn attack(victim: Oracle) -> Vec<u8> {
    let len = attack_len(victim);
    let content = Vec::with_capacity(len);

    while content.len() != len {
        // todo: guess each character
    }

    content
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore]
    fn challenge() {
        let content = b"Rollin' in my 5.0
With my rag-top down so my hair can blow
The girlies on standby waving just to say hi
Did you stop? No, I just drove by
";
        // try it a couple of times to show it works with any key
        for _ in 0..10 {
            let oracle = Oracle::new(content);
            assert_eq!(attack(oracle), content);
        }
    }

    #[test]
    fn len() {
        let content = [0; 33];
        for l in 0..=content.len() {
            let oracle = Oracle::new(&content[..l]);
            assert_eq!(attack_len(oracle), l);
        }
    }
}
