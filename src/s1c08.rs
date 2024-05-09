pub fn find_ecb(cts: &[Vec<u8>]) -> Option<usize> {
    cts.iter()
        .enumerate()
        .max_by_key(|(_, ct)| count_rep16(ct))
        .map(|(i, _)| i)
}

fn block16(ct: &[u8], i: usize) -> &[u8] {
    &ct[(16 * i)..(16 * i + 16)]
}

fn count_rep16(ct: &[u8]) -> usize {
    (0..(ct.len() / 16))
        .flat_map(|i| (0..i).map(move |j| (i, j)))
        .filter(|(i, j)| block16(ct, *i) == block16(ct, *j))
        .count()
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
    fn challenge() {
        let cts = read_lines_hex("data/08.txt");
        let idx = find_ecb(&cts);
        assert_eq!(idx, Some(132));
    }

    #[test]
    fn empty() {
        let cts = Vec::new();
        let idx = find_ecb(&cts);
        assert_eq!(idx, None);
    }
}
