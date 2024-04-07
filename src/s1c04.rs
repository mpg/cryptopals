use crate::s1c03;
use hex;
use std::fs::read_to_string;

pub fn find_sxor(filename: &str) -> Option<s1c03::SXorCracked> {
    read_to_string(filename)
        .unwrap()
        .lines()
        .filter_map(|l| hex::decode(l).ok())
        .filter_map(|ct| s1c03::sxor_crack(&ct))
        .min_by_key(|c| c.badness)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge() {
        let filename = "data/04.txt";
        let exp_pt = "Now that the party is jumping\n";

        let res = find_sxor(filename).unwrap();
        assert_eq!(res.pt, exp_pt);
    }
}
