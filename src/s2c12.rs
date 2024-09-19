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
            // attacker doesn't need any knowledge of the padding bytes.
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
// We need to know that the padding length is between 1 and block_size
// (that is, a full block of padding is inserted if the length
// before padding was already a multiple of block_size).
fn attack_len(victim: &Oracle) -> (usize, usize) {
    let base = victim.process(b"").len();
    let mut mybytes = vec![0];
    loop {
        let diff = victim.process(&mybytes).len() - base;
        if diff != 0 {
            // Last ciphertext had length base + diff and cleartext was:
            // mybytes + content + diff bytes of padding, so
            // len + content_len + diff = base + diff.
            return (base - mybytes.len(), diff);
        }
        mybytes.push(0);
    }
}

// Find the content hidden in the Oracle
// victim.content is private and can't be read
pub fn attack(victim: &Oracle) -> Vec<u8> {
    let (len, block_size) = attack_len(victim);
    println!("final length: {}", len);
    let mut content = Vec::with_capacity(len);

    let mut input = Vec::with_capacity(len + block_size);
    while content.len() != len {
        // Left-pad content so that the last bloc is 1 byte short
        let pad_len = block_size - 1 - content.len() % block_size;
        input.clear();
        input.resize(pad_len, 0);

        // Establish a reference where the last byte of the block
        // is the one the next byte to guess from the content.
        let target_len = input.len() + content.len() + 1;
        let target = &victim.process(&input)[..target_len];

        // Append what we already know then
        // try all possible values for the last byte.
        input.extend_from_slice(&content);
        for b in 0u8..=255 {
            input.push(b);
            if victim.process(&input)[..target.len()] == *target {
                content.push(b);
                break;
            }
            input.pop();
        }
    }

    content
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge() {
        let content = b"Rollin' in my 5.0
With my rag-top down so my hair can blow
The girlies on standby waving just to say hi
Did you stop? No, I just drove by
";
        let oracle = Oracle::new(content);
        assert_eq!(attack(&oracle), content);
    }

    #[test]
    fn len() {
        let content = [0; 33];
        for l in 0..=content.len() {
            let oracle = Oracle::new(&content[..l]);
            assert_eq!(attack_len(&oracle), (l, 16));
        }
    }
}
