#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Mode {
    ECB,
    CBC,
}

impl Mode {
    pub fn rand() -> Self {
        match rand::random() {
            false => Mode::ECB,
            true => Mode::CBC,
        }
    }
}

// use a separate module for privacy
mod oracle {
    use super::Mode;
    use crate::s1c07::aes_128_ecb_encrypt;
    use crate::s2c09::pkcs7_pad;
    use crate::s2c10::aes_128_cbc_encrypt;
    use rand::{thread_rng, Rng};

    pub struct Oracle {
        mode: Mode,
    }

    // add 5-10 random bytes at the end of data
    fn add_rand(data: &mut Vec<u8>) {
        let mut rng = thread_rng();
        let add_len = rng.gen_range(5..=10);
        for _ in 0..add_len {
            data.push(rng.gen())
        }
    }

    impl Oracle {
        pub fn new(mode: Mode) -> Self {
            Self { mode }
        }

        pub fn process(&self, input: &[u8]) -> Vec<u8> {
            let mut rng = thread_rng();

            let mut key = [0u8; 16];
            rng.fill(&mut key[..]);

            let mut iv = [0u8; 16];
            rng.fill(&mut iv[..]);

            let mut data = Vec::new();
            add_rand(&mut data);
            data.extend_from_slice(input);
            add_rand(&mut data);
            let data = pkcs7_pad(&data, 16);

            match self.mode {
                Mode::ECB => aes_128_ecb_encrypt(&key, &data).unwrap(),
                Mode::CBC => aes_128_cbc_encrypt(&key, &iv, &data).unwrap(),
            }
        }
    }
}

use crate::s1c08::count_rep16;
use oracle::Oracle;

// guess which mode is used by the Oracle
// victim.mode is private and can't be read
pub fn attack(victim: &Oracle) -> Mode {
    let three_identical_blocks = [0; 48];
    let out = victim.process(&three_identical_blocks);
    let repeated_blocks = count_rep16(&out);

    match repeated_blocks {
        0 => Mode::CBC,
        _ => Mode::ECB,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge() {
        for _ in 0..128 {
            let mode = Mode::rand();
            let oracle = Oracle::new(mode);
            assert_eq!(attack(&oracle), mode);
        }
    }
}
