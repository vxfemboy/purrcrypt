// src/cipher/mod.rs
mod patterns;
pub use patterns::{CipherPattern, PatternVariation};
use std::io::{self, Write};

pub enum CipherMode {
    Encrypt,
    Decrypt,
}

pub enum CipherDialect {
    Cat,
    Dog,
}

pub struct AnimalCipher {
    cat_patterns: Vec<CipherPattern>,
    dog_patterns: Vec<CipherPattern>,
    current_dialect: CipherDialect,
}

impl AnimalCipher {
    pub fn new(dialect: CipherDialect) -> Self {
        Self {
            cat_patterns: vec![
                // mew/meeww (m-e-w) min 1 max 1 "m", min 1 max 10 "e", min 1 max 5 "w"
                CipherPattern::new_complex("mew", "m", 1, 1, "e", 1, 10, "w", 1, 5),
                // purr/puurrrr (p-u-rr) min 1 max 1 "p", min 1 max 10 "u", min 2 max 10 "r"
                CipherPattern::new_complex("purr", "p", 1, 1, "u", 1, 10, "r", 2, 10),
                // nya/nyaaa (n-y-a) min 1 max 1 "n", min 1 max 5 "y", min 1 max 10 "a"
                CipherPattern::new_complex("nya", "n", 1, 1, "y", 1, 5, "a", 1, 10),
                // meow/meeooww (m-e-o-w) min 1 max 1 "m", min 1 max 10 "e", min 1 max 10 "o", min 1 max 2 "w"
                CipherPattern::new_special("meow"),
                // mrrp/mrrrrrrrp (m-r-p) min 1 max 2 "m", min 2 max 10 "r", min 1 max 2 "p"
                CipherPattern::new_complex("mrrp", "m", 1, 2, "r", 2, 10, "p", 1, 2),
            ],
            dog_patterns: vec![
                // woof/wooooff (w-o-f) min 1 max 1 "w", min 2 max 10 "o", min 1 max 2 "f"
                CipherPattern::new_complex("woof", "w", 1, 1, "o", 2, 10, "f", 1, 2),
                // bark/baarrk (b-a-r-k) min 1 max 1 "b", min 1 max 10 "a", min 1 max 5 "r", min 1 max 1 "k"
                CipherPattern::new_special("bark"),
                // arf/arrff (a-r-f) min 1 max 5 "a", min 1 max 5 "r", min 1 max 2 "f"
                CipherPattern::new_complex("arf", "a", 1, 5, "r", 1, 5, "f", 1, 2),
                // yip/yiipp (y-i-p) min 1 max 2 "y", min 1 max 10 "i", min 1 max 5 "p"
                CipherPattern::new_complex("yip", "y", 1, 2, "i", 1, 10, "p", 1, 5),
                // wrf/wrrf (w-r-f) min 1 max 2 "w", min 1 max 10 "r", min 1 max 5 "f"
                CipherPattern::new_complex("wrf", "w", 1, 2, "r", 1, 10, "f", 1, 5),
            ],
            current_dialect: dialect,
        }
    }

    pub fn process_data<W: Write>(
        &self,
        data: &[u8],
        writer: &mut W,
        _mode: CipherMode,
    ) -> io::Result<()> {
        for chunk in data.chunks(3) {
            let mut value = 0u32;
            let mut bytes = 0;

            // Pack bytes into a 24-bit buffer
            for &byte in chunk {
                value = (value << 8) | (byte as u32);
                bytes += 1;
            }

            // Process in groups of 6 bits
            let groups = match bytes {
                1 => 2, // 8 bits -> 2 groups
                2 => 3, // 16 bits -> 3 groups
                3 => 4, // 24 bits -> 4 groups
                _ => unreachable!(),
            };

            // Extract 6-bit groups
            for i in 0..groups {
                let shift = (3 - i) * 6;
                let bits = ((value >> shift) & 0b111111) as u8;

                // Convert to pattern and variation
                let pattern_index = ((bits >> 3) & 0b111) as usize % 5;
                let variation = bits & 0b111;

                let patterns = match self.current_dialect {
                    CipherDialect::Cat => &self.cat_patterns,
                    CipherDialect::Dog => &self.dog_patterns,
                };

                let word = patterns[pattern_index].generate_variation(variation);
                write!(writer, "{} ", word)?;
            }
        }

        Ok(())
    }

    pub fn process_string(&self, content: &str, mode: CipherMode) -> io::Result<Vec<u8>> {
        match mode {
            CipherMode::Decrypt => {
                let words = content.split_whitespace();
                let mut bytes = Vec::new();
                let mut value = 0u32;
                let mut bits = 0;

                for word in words {
                    let decoded = self
                        .decode_word_cat(word)
                        .or_else(|| self.decode_word_dog(word))
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("Invalid word in input: {}", word),
                            )
                        })?;

                    // Pack into 6 bits (3 for pattern, 3 for variation)
                    let pattern_bits = ((decoded.0 as u8 & 0b111) << 3) | (decoded.1 & 0b111);
                    value = (value << 6) | (pattern_bits as u32);
                    bits += 6;

                    // Extract complete bytes
                    while bits >= 8 {
                        bits -= 8;
                        let byte = ((value >> bits) & 0xFF) as u8;
                        bytes.push(byte);
                    }
                }

                Ok(bytes)
            }
            CipherMode::Encrypt => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Cannot process string in encrypt mode",
            )),
        }
    }

    fn decode_word_cat(&self, word: &str) -> Option<(usize, u8)> {
        for (index, pattern) in self.cat_patterns.iter().enumerate() {
            if let Some(variation) = pattern.decode_variation(word) {
                return Some((index % 5, variation & 0b111));
            }
        }
        None
    }

    fn decode_word_dog(&self, word: &str) -> Option<(usize, u8)> {
        for (index, pattern) in self.dog_patterns.iter().enumerate() {
            if let Some(variation) = pattern.decode_variation(word) {
                return Some((index % 5, variation & 0b111));
            }
        }
        None
    }
}

// For backwards compatibility
pub type CatCipher = AnimalCipher;
