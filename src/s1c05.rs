pub fn rep_xor(key: &[u8], buf: &[u8]) -> Vec<u8> {
    std::iter::repeat(key)
        .flatten()
        .zip(buf)
        .map(|(k, b)| k ^ b)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn challenge() {
        let pt = b"Burning 'em, if you ain't quick and nimble\n\
                   I go crazy when I hear a cymbal";
        let key = b"ICE";
        let cth = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d\
                   63343c2a26226324272765272a282b2f20430a652e2c652a31\
                   24333a653e2b2027630c692b20283165286326302e27282f";

        let ct = hex::decode(cth).unwrap();

        assert_eq!(rep_xor(key, pt), ct);
    }
}
