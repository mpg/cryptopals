use crate::s1c03;

pub fn find_sxor(filename: &str) -> Option<s1c03::SXorCracked> {
    todo!("find the encrypted line in {}", filename);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge() {
        let filename = "data/04.txt";
        let exp_pt = "Now that the party is jumping";

        let res = find_sxor(filename).unwrap();
        assert_eq!(res.pt, exp_pt);
    }
}
