pub fn find_ecb(cts: &[Vec<u8>]) -> usize {
    todo!("index of ECB-looking ciphertext from {:?}", cts);
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    fn read_lines_hex(filename: &str) -> Vec<Vec<u8>> {
        std::fs::read_to_string(filename)
            .unwrap()
            .lines()
            .map(|l| hex::decode(l).unwrap())
            .collect()
    }

    #[test]
    #[ignore]
    fn challenge() {
        let cts = read_lines_hex("data/08.txt");
        let idx = find_ecb(&cts);
        assert_eq!(idx, 132);
    }
}
