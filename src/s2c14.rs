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
            let mut rng = thread_rng();
            // random-prefix || attacker-controlled || target-bytes
            let rp_len = rng.gen::<u8>();
            let mut clear: Vec<u8> = (0..rp_len).map(|_| rng.gen()).collect();
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

// Wrap a non-deterministic Oracle into a deterministic one.
//
// Get rid of the random part by using a sentinel consisting of the
// encryption of two blocks of all-0 then all-1.
// Using all-x blocks makes it easy to get the encryption: send
// three blocks' worth of x, we'll get at least two identical blocks of
// ciphertext (this is the same as challenge 8).
// Don't use just one block of all-0 because if the random stuff
// prepended is say a whole number of blocks plus one byte that happens
// to be 0, we'll get confused. The transition from 0 to 1 ensures we
// get the alignment right.
// It is of course possible that the random prefix contains two blocks
// of all-0 then all-1 but that's extremely unlikely so we just ignore
// that possibility.
struct OracleWrapper<'a> {
    oracle: &'a Oracle,
    sentinel: Vec<u8>,
}

fn gcd(a: usize, b: usize) -> usize {
    if a == 0 {
        b
    } else if b == 0 {
        a
    } else if a >= b {
        gcd(a - b, b)
    } else {
        gcd(b - a, a)
    }
}

impl<'a> OracleWrapper<'a> {
    fn new(oracle: &'a Oracle) -> Self {
        // Guess the block size - this might overshoot but that's OK,
        // we'll just be using a sentinel larger than necessary.
        // (10 iterations means roughly 1 in 2^10 chance of getting an extra
        // factor 2, also 1 in 3^10 of getting an extra factor 3, etc.)
        let mut block_size = oracle.process(b"").len();
        for _ in 1..10 {
            block_size = gcd(block_size, oracle.process(b"").len());
        }

        // Compute our sentinel, see the definition of OracleWrapper.
        let mut sentinel = Vec::new();
        for v in 0..=1u8 {
            let blocks = vec![v; 3 * block_size];
            let out = oracle.process(&blocks);
            for i in (0..(out.len() - block_size)).step_by(block_size) {
                let cur_block = &out[i..(i + block_size)];
                let next_block = &out[(i + block_size)..(i + 2 * block_size)];
                if cur_block == next_block {
                    sentinel.extend_from_slice(cur_block);
                    break;
                }
            }
        }

        Self { oracle, sentinel }
    }

    fn process(&self, input: &[u8]) -> Vec<u8> {
        let block_size = self.sentinel.len() / 2;

        let mut ext_input = Vec::new();
        ext_input.extend_from_slice(&vec![0u8; block_size]);
        ext_input.extend_from_slice(&vec![1u8; block_size]);
        ext_input.extend_from_slice(input);

        loop {
            let out = self.oracle.process(&ext_input);
            for i in (0..(out.len() - 2 * block_size)).step_by(block_size) {
                if out[i..(i + 2 * block_size)] == self.sentinel {
                    return out[i + 2 * block_size..].to_owned();
                }
            }
        }
    }
}

// The two functions below are identical copies of those in s2c12,
// except:
// - some types (Oracle vs OracleWrapper)
// - the first line of attack(), wrapping the input Oracle (marked [sic])

// Find the length of the content hidden in the Oracle.
// We need to know that the padding length is between 1 and block_size
// (that is, a full block of padding is inserted if the length
// before padding was already a multiple of block_size).
fn attack_len(victim: &OracleWrapper) -> (usize, usize) {
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
    let victim = OracleWrapper::new(victim); // [sic]
    let (len, block_size) = attack_len(&victim);
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
    use crate::s2c12;

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
    fn oracle_wrapper() {
        let content = b"The quick brown fox jumps over the lazy dog.";
        let oracle = Oracle::new(content);
        let oracle_wrap = OracleWrapper::new(&oracle);
        let oracle_ref = s2c12::Oracle::new(content);

        let input = [b'A'; 17];
        for l in 0..=input.len() {
            let i = &input[..l];
            // We can't compare ciphertexts because the two oracles will use
            // different (random) keys, but the length is a key indicator.
            assert_eq!(oracle_wrap.process(i).len(), oracle_ref.process(i).len())
        }
    }
}
