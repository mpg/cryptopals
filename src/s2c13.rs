// use a separate module for privacy
mod oracle {
    use crate::s1c07::{aes_128_ecb_decrypt, aes_128_ecb_encrypt};
    use rand::{thread_rng, Rng};

    pub struct Oracle {
        key: [u8; 16],
    }

    impl Oracle {
        #[allow(clippy::new_without_default)]
        pub fn new() -> Self {
            let mut key = [0u8; 16];
            thread_rng().fill(&mut key[..]);

            Self { key }
        }

        // Encode and encrypt profile for this email address
        pub fn encrypted_profile_for(&self, email: &str) -> Vec<u8> {
            // Don't allow direct injection attacks
            if email.contains("&") || email.contains("=") {
                return Vec::new();
            }

            // In real life we map email to UID, but it doesn't matter here
            let uid = thread_rng().gen::<u8>();

            // Encode the user profile
            let profile = format!("email={}&uid={:03}&role=user", email, uid);
            println!("profile to be encrypted: '{}'", profile);

            // Use 0-padding - doesn't matter, just convenient
            let mut clear = profile.as_bytes().to_owned();
            let padded_size = clear.len() % 16 * 16 + 16;
            clear.resize(padded_size, 0);

            aes_128_ecb_encrypt(&self.key, &clear).unwrap()
        }

        // Take an encrypted profile and tell if role is "admin"
        pub fn is_admin(&self, token: &[u8]) -> bool {
            let Some(clear) = aes_128_ecb_decrypt(&self.key, token) else {
                return false;
            };

            let Ok(padded) = String::from_utf8(clear) else {
                return false;
            };

            let profile = padded.trim_end_matches('\0');
            println!("decrypted profile: '{}'", profile);

            profile.ends_with("&role=admin")
        }
    }
}

use oracle::Oracle;

// Forge a token (encrypted profile) with role=admin
pub fn attack(victim: &Oracle) -> Vec<u8> {
    // 0               1               2               3               4
    // 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    // email=xxxxxxxxxxadmin00000000000@example.xxxxxxxxx&uid=123&role=user000000000000
    //                 <---- copy ---->                                <---- paste --->
    let email = "xxxxxxxxxxadmin\0\0\0\0\0\0\0\0\0\0\0@example.xxxxxxxxx";
    let mut token = victim.encrypted_profile_for(email);
    token.truncate(0x40);
    token.extend_from_within(0x10..0x20);

    token
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge() {
        let victim = Oracle::new();
        let forged_token = attack(&victim);
        assert!(victim.is_admin(&forged_token));
    }
}
