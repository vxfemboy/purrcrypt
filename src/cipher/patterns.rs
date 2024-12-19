// src/cipher/patterns.rs
use regex::Regex;

#[derive(Copy, Clone, Debug)]
pub enum PatternVariation {
    Complex, // For patterns with three parts
    Special, // For meow and bark patterns with four parts
}

pub struct CipherPattern {
    pub(crate) pattern_type: PatternVariation,
    pub(crate) prefix: String,
    pub(crate) prefix_min: usize,
    #[allow(dead_code)]
    pub(crate) prefix_max: usize,
    pub(crate) middle: String,
    pub(crate) middle_min: usize,
    pub(crate) middle_max: usize,
    pub(crate) suffix: String,
    pub(crate) suffix_min: usize,
    pub(crate) suffix_max: usize,
    pub(crate) regex: Regex,
}

impl CipherPattern {
    pub fn new_complex(
        _base: &str,
        prefix: &str,
        prefix_min: usize,
        prefix_max: usize,
        middle: &str,
        middle_min: usize,
        middle_max: usize,
        suffix: &str,
        suffix_min: usize,
        suffix_max: usize,
    ) -> Self {
        let pattern = format!(
            "^{}{{{}}}{}{{{}}}{}{{{}}}$",
            prefix,
            format!("{},{}", prefix_min, prefix_max),
            middle,
            format!("{},{}", middle_min, middle_max),
            suffix,
            format!("{},{}", suffix_min, suffix_max),
        );

        Self {
            pattern_type: PatternVariation::Complex,
            prefix: prefix.to_string(),
            prefix_min,
            prefix_max,
            middle: middle.to_string(),
            middle_min,
            middle_max,
            suffix: suffix.to_string(),
            suffix_min,
            suffix_max,
            regex: Regex::new(&pattern).unwrap(),
        }
    }

    pub fn new_special(base: &str) -> Self {
        match base {
            "meow" => {
                // meow/meeooww (m-e-o-w) min 1 max 1 "m", min 1 max 10 "e", min 1 max 10 "o", min 1 max 2 "w"
                let pattern = "^m{1}e{1,10}o{1,10}w{1,2}$";
                Self {
                    pattern_type: PatternVariation::Special,
                    prefix: "m".to_string(),
                    prefix_min: 1,
                    prefix_max: 1,
                    middle: "e".to_string(),
                    middle_min: 1,
                    middle_max: 10,
                    suffix: "w".to_string(),
                    suffix_min: 1,
                    suffix_max: 2,
                    regex: Regex::new(pattern).unwrap(),
                }
            }
            "bark" => {
                // bark/baarrk (b-a-r-k) min 1 max 1 "b", min 1 max 10 "a", min 1 max 5 "r", min 1 max 1 "k"
                let pattern = "^b{1}a{1,10}r{1,5}k{1}$";
                Self {
                    pattern_type: PatternVariation::Special,
                    prefix: "b".to_string(),
                    prefix_min: 1,
                    prefix_max: 1,
                    middle: "a".to_string(),
                    middle_min: 1,
                    middle_max: 10,
                    suffix: "k".to_string(),
                    suffix_min: 1,
                    suffix_max: 1,
                    regex: Regex::new(pattern).unwrap(),
                }
            }
            _ => panic!("Unknown special pattern: {}", base),
        }
    }

    pub fn decode_variation(&self, word: &str) -> Option<u8> {
        if !self.regex.is_match(word) {
            return None;
        }

        match self.pattern_type {
            PatternVariation::Complex => {
                let middle_count = word.matches(&self.middle).count();
                let suffix_count = word.matches(&self.suffix).count();

                if middle_count < self.middle_min
                    || middle_count > self.middle_max
                    || suffix_count < self.suffix_min
                    || suffix_count > self.suffix_max
                {
                    return None;
                }

                // Pack into 3 bits
                let middle_bits = (((middle_count - self.middle_min) * 7)
                    / (self.middle_max - self.middle_min + 1))
                    & 0b11;
                let suffix_bits = (((suffix_count - self.suffix_min) * 7)
                    / (self.suffix_max - self.suffix_min + 1))
                    & 0b11;
                Some(((middle_bits as u8) << 1) | (suffix_bits as u8))
            }
            PatternVariation::Special => match self.prefix.as_str() {
                "m" => {
                    // meow pattern
                    let e_count = word.matches("e").count();
                    let o_count = word.matches("o").count();
                    let w_count = word.matches("w").count() - 1;

                    if e_count < 1 || e_count > 10 || o_count < 1 || o_count > 10 || w_count > 1 {
                        return None;
                    }

                    let e_bits = ((e_count - 1) * 7 / 9) & 0b11;
                    let o_bits = ((o_count - 1) * 7 / 9) & 0b11;
                    Some(((e_bits as u8) << 1) | (o_bits as u8))
                }
                "b" => {
                    // bark pattern
                    let a_count = word.matches("a").count();
                    let r_count = word.matches("r").count();

                    if a_count < 1 || a_count > 10 || r_count < 1 || r_count > 5 {
                        return None;
                    }

                    let a_bits = ((a_count - 1) * 7 / 9) & 0b11;
                    let r_bits = ((r_count - 1) * 7 / 4) & 0b11;
                    Some(((a_bits as u8) << 1) | (r_bits as u8))
                }
                _ => None,
            },
        }
    }

    pub fn generate_variation(&self, bits: u8) -> String {
        match self.pattern_type {
            PatternVariation::Complex => {
                let mut result = String::new();
                let middle_bits = (bits >> 1) & 0b11;
                let suffix_bits = bits & 0b1;

                result.push_str(&self.prefix.repeat(self.prefix_min));

                let middle_count = self.middle_min
                    + (middle_bits as usize * (self.middle_max - self.middle_min + 1)) / 7;
                let suffix_count = self.suffix_min
                    + (suffix_bits as usize * (self.suffix_max - self.suffix_min + 1)) / 3;

                result.push_str(&self.middle.repeat(middle_count.min(self.middle_max)));
                result.push_str(&self.suffix.repeat(suffix_count.min(self.suffix_max)));
                result
            }
            PatternVariation::Special => match self.prefix.as_str() {
                "m" => {
                    // meow pattern
                    let e_bits = (bits >> 1) & 0b11;
                    let o_bits = bits & 0b11;
                    let e_count = 1 + (e_bits as usize * 9) / 7;
                    let o_count = 1 + (o_bits as usize * 9) / 7;
                    format!(
                        "m{}{}w",
                        "e".repeat(e_count.min(10)),
                        "o".repeat(o_count.min(10))
                    )
                }
                "b" => {
                    // bark pattern
                    let a_bits = (bits >> 1) & 0b11;
                    let r_bits = bits & 0b11;
                    let a_count = 1 + (a_bits as usize * 9) / 7;
                    let r_count = 1 + (r_bits as usize * 4) / 7;
                    format!(
                        "b{}{}k",
                        "a".repeat(a_count.min(10)),
                        "r".repeat(r_count.min(5))
                    )
                }
                _ => panic!("Unknown special pattern"),
            },
        }
    }
}
