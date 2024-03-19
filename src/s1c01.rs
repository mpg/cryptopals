use base64::prelude::*;
use hex;

pub fn base64_from_hex(hex: &str) -> Result<String, hex::FromHexError> {
    let bytes = hex::decode(hex)?;
    Ok(BASE64_STANDARD.encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge() {
        let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let expected =
            String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
        assert_eq!(base64_from_hex(input), Ok(expected));
    }

    #[test]
    fn errors() {
        assert_eq!(base64_from_hex("abc"), Err(hex::FromHexError::OddLength));
        assert_eq!(
            base64_from_hex("abcXef"),
            Err(hex::FromHexError::InvalidHexCharacter { c: 'X', index: 3 })
        );
    }

    fn positive(hex: &str, exp: &str) {
        assert_eq!(base64_from_hex(hex).unwrap(), String::from(exp));
    }

    #[test]
    fn sizes() {
        positive("112233445566", "ESIzRFVm");
        positive("1122334455", "ESIzRFU=");
        positive("11223344", "ESIzRA==");
        positive("112233", "ESIz");
        positive("1122", "ESI=");
        positive("11", "EQ==");
        positive("", "");
    }
}
