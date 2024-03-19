pub fn xor_buf(a: &[u8], b: &[u8]) -> Option<Vec<u8>> {
    todo!("xor {:?} and {:?}", a, b);
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
}
