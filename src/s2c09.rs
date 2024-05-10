pub fn pkcs7_pad(raw: &[u8], block_size: usize) -> Vec<u8> {
    assert!(block_size < 256);

    let last_block_used = raw.len() % block_size;
    let pad_len = block_size - last_block_used;
    let pad_value = pad_len as u8;
    let total_size = raw.len() + pad_len;

    let mut padded = Vec::with_capacity(total_size);
    padded.extend_from_slice(raw);
    padded.resize(total_size, pad_value);
    padded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge() {
        let input = [0; 8];
        let output = [
            vec![8, 8, 8, 8, 8, 8, 8, 8],
            vec![0, 7, 7, 7, 7, 7, 7, 7],
            vec![0, 0, 6, 6, 6, 6, 6, 6],
            vec![0, 0, 0, 5, 5, 5, 5, 5],
            vec![0, 0, 0, 0, 4, 4, 4, 4],
            vec![0, 0, 0, 0, 0, 3, 3, 3],
            vec![0, 0, 0, 0, 0, 0, 2, 2],
            vec![0, 0, 0, 0, 0, 0, 0, 1],
        ];
        for i in 0..8 {
            assert_eq!(pkcs7_pad(&input[0..i], 8), output[i]);
        }

        let in10 = [13; 10];
        let out4 = vec![13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 2, 2];
        let out5 = vec![13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 5, 5, 5, 5, 5];
        let out6 = vec![13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 2, 2];
        assert_eq!(pkcs7_pad(&in10, 4), out4);
        assert_eq!(pkcs7_pad(&in10, 5), out5);
        assert_eq!(pkcs7_pad(&in10, 6), out6);
    }
}
