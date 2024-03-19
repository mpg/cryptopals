use std::iter::zip;

pub fn xor_buf(a: &[u8], b: &[u8]) -> Option<Vec<u8>> {
    if a.len() != b.len() {
        return None;
    }

    Some(zip(a, b).map(|(&x, &y)| x ^ y).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn challenge() {
        let ah = "1c0111001f010100061a024b53535009181c";
        let bh = "686974207468652062756c6c277320657965";
        let ch = "746865206b696420646f6e277420706c6179";

        let a = hex::decode(ah).unwrap();
        let b = hex::decode(bh).unwrap();
        let c = hex::decode(ch).unwrap();

        assert_eq!(xor_buf(&a, &b), Some(c));
    }

    #[test]
    fn errors() {
        assert_eq!(xor_buf("123".as_bytes(), "abcd".as_bytes()), None);
        assert_eq!(xor_buf("1234".as_bytes(), "abc".as_bytes()), None);
    }
}
