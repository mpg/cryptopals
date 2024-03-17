pub fn base64_from_hex(hex: &str) -> Result<String, String> {
    todo!("Convert {hex} to base64");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge() {
        let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let expected = String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
        assert_eq!(base64_from_hex(input), Ok(expected));
    }
}
