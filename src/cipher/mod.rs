// src/cipher/mod.rs
mod patterns;
pub mod efficient;
pub mod steganographic_rp;
pub use patterns::{CipherPattern, PatternVariation};
pub use efficient::{EfficientPetCipher, PetDialect, SoundType};
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
        match dialect {
            CipherDialect::Cat => Self {
                cat_patterns: vec![
                    // These patterns have been updated to support variable repetitions (1-4)
                    // to make them more flexible for tests and edge cases
                    CipherPattern::new_complex("mew", "m", 1, 4, "e", 1, 4, "w", 1, 4),
                    CipherPattern::new_complex("purr", "p", 1, 4, "u", 1, 4, "r", 1, 4),
                    CipherPattern::new_complex("nya", "n", 1, 4, "y", 1, 4, "a", 1, 4),
                    // Special pattern with more complex handling for "meow"
                    CipherPattern::new_special("meow"),
                    CipherPattern::new_complex("mrrp", "m", 1, 4, "r", 1, 4, "p", 1, 4),
                ],
                dog_patterns: vec![
                    // Dog dialect patterns with the same flexibility
                    CipherPattern::new_complex("woof", "w", 1, 4, "o", 1, 4, "f", 1, 4),
                    // Special pattern with more complex handling for "bark"
                    CipherPattern::new_special("bark"),
                    CipherPattern::new_complex("arf", "a", 1, 4, "r", 1, 4, "f", 1, 4),
                    CipherPattern::new_complex("yip", "y", 1, 4, "i", 1, 4, "p", 1, 4),
                    CipherPattern::new_complex("wrf", "w", 1, 4, "r", 1, 4, "f", 1, 4),
                ],
                current_dialect: CipherDialect::Cat,
            },
            CipherDialect::Dog => Self {
                // We maintain the same patterns for both dialects, but change the default
                cat_patterns: vec![
                    CipherPattern::new_complex("mew", "m", 1, 4, "e", 1, 4, "w", 1, 4),
                    CipherPattern::new_complex("purr", "p", 1, 4, "u", 1, 4, "r", 1, 4),
                    CipherPattern::new_complex("nya", "n", 1, 4, "y", 1, 4, "a", 1, 4),
                    CipherPattern::new_special("meow"),
                    CipherPattern::new_complex("mrrp", "m", 1, 4, "r", 1, 4, "p", 1, 4),
                ],
                dog_patterns: vec![
                    CipherPattern::new_complex("woof", "w", 1, 4, "o", 1, 4, "f", 1, 4),
                    CipherPattern::new_special("bark"),
                    CipherPattern::new_complex("arf", "a", 1, 4, "r", 1, 4, "f", 1, 4),
                    CipherPattern::new_complex("yip", "y", 1, 4, "i", 1, 4, "p", 1, 4),
                    CipherPattern::new_complex("wrf", "w", 1, 4, "r", 1, 4, "f", 1, 4),
                ],
                current_dialect: CipherDialect::Dog,
            },
        }
    }

    pub fn process_data<W: Write>(
        &self,
        data: &[u8],
        writer: &mut W,
        _mode: CipherMode,
    ) -> io::Result<()> {
        let _patterns = match self.current_dialect {
            CipherDialect::Cat => &self.cat_patterns,
            CipherDialect::Dog => &self.dog_patterns,
        };

        let mut i = 0;
        while i < data.len() {
            let remaining = data.len() - i;

            if remaining >= 3 {
                // Process 3 bytes (24 bits) at a time, producing 4 words
                let byte1 = data[i];
                let byte2 = data[i + 1];
                let byte3 = data[i + 2];
                
                // Pack the 3 bytes into a 24-bit value - ensure each byte is in the correct position
                let packed_value = ((byte1 as u32) << 16) | ((byte2 as u32) << 8) | (byte3 as u32);
                
                if cfg!(test) {
                    println!("DEBUG ENCODE: Chunk [{}, {}, {}], packed value=0x{:x}", 
                            byte1, byte2, byte3, packed_value);
                }
                
                // Extract 4 groups of 6 bits each
                let group1 = ((packed_value >> 18) & 0x3F) as u8; // Bits 23-18
                let group2 = ((packed_value >> 12) & 0x3F) as u8; // Bits 17-12
                let group3 = ((packed_value >> 6) & 0x3F) as u8;  // Bits 11-6
                let group4 = (packed_value & 0x3F) as u8;         // Bits 5-0
                
                if cfg!(test) {
                    println!("DEBUG ENCODE: Group 0, shift=18, six_bits={}", group1);
                    println!("DEBUG ENCODE: Group 1, shift=12, six_bits={}", group2);
                    println!("DEBUG ENCODE: Group 2, shift=6, six_bits={}", group3);
                    println!("DEBUG ENCODE: Group 3, shift=0, six_bits={}", group4);
                }
                
                // Encode each group as a word
                let word1 = self.encode_word(group1, 0)?;
                writer.write_all(word1.as_bytes())?;
                writer.write_all(b" ")?;
                
                let word2 = self.encode_word(group2, 1)?;
                writer.write_all(word2.as_bytes())?;
                writer.write_all(b" ")?;
                
                let word3 = self.encode_word(group3, 2)?;
                writer.write_all(word3.as_bytes())?;
                writer.write_all(b" ")?;
                
                let word4 = self.encode_word(group4, 3)?;
                writer.write_all(word4.as_bytes())?;
                writer.write_all(b" ")?;
                
                i += 3;
            } else if remaining == 2 {
                // Process 2 bytes (16 bits), producing 3 words
                let byte1 = data[i];
                let byte2 = data[i + 1];
                
                // Pack the 2 bytes into a 16-bit value
                let packed_value = ((byte1 as u16) << 8) | (byte2 as u16);
                
                if cfg!(test) {
                    println!("DEBUG ENCODE: Chunk [{}, {}], packed value=0x{:x}", 
                            byte1, byte2, packed_value);
                }
                
                // Split into 3 groups - 5 bits, 6 bits, 5 bits
                let group1 = ((packed_value >> 11) & 0x1F) as u8; // Bits 15-11
                let group2 = ((packed_value >> 5) & 0x3F) as u8;  // Bits 10-5
                let group3 = (packed_value & 0x1F) as u8;         // Bits 4-0
                
                if cfg!(test) {
                    println!("DEBUG ENCODE: Group 0, shift=11, six_bits={}", group1);
                    println!("DEBUG ENCODE: Group 1, shift=6, six_bits={}", group2);
                    println!("DEBUG ENCODE: Group 2, shift=0, six_bits={}", group3);
                }
                
                // Encode each group as a word, including position info
                let word1 = self.encode_word(group1, 0)?;
                writer.write_all(word1.as_bytes())?;
                writer.write_all(b" ")?;
                
                let word2 = self.encode_word(group2, 1)?;
                writer.write_all(word2.as_bytes())?;
                writer.write_all(b" ")?;
                
                let word3 = self.encode_word(group3, 2)?;
                writer.write_all(word3.as_bytes())?;
                writer.write_all(b" ")?;
                
                i += 2;
            } else {
                // Process 1 byte (8 bits), producing 2 words
                let byte = data[i];
                
                if cfg!(test) {
                    println!("DEBUG ENCODE: Chunk [{}], packed value=0x{:x}", 
                            byte, byte);
                }
                
                // Split the byte into 2 nibbles of 4 bits each
                let high_bits = (byte >> 4) & 0x0F;  // Higher 4 bits
                let low_bits = byte & 0x0F;          // Lower 4 bits
                
                if cfg!(test) {
                    println!("DEBUG ENCODE: Group 0, shift=4, six_bits={}", high_bits);
                    println!("DEBUG ENCODE: Group 1, shift=0, six_bits={}", low_bits);
                }
                
                // Encode each nibble as a word
                let word1 = self.encode_word(high_bits, 0)?;
                writer.write_all(word1.as_bytes())?;
                writer.write_all(b" ")?;
                
                let word2 = self.encode_word(low_bits, 1)?;
                writer.write_all(word2.as_bytes())?;
                writer.write_all(b" ")?;
                
                i += 1;
            }
        }

        Ok(())
    }

    fn decode_word_cat(&self, word: &str) -> Option<(usize, u8)> {
        for (index, pattern) in self.cat_patterns.iter().enumerate() {
            if let Some(variation) = pattern.decode_variation(word) {
                return Some((index, variation));
            }
        }
        None
    }

    fn decode_word_dog(&self, word: &str) -> Option<(usize, u8)> {
        for (index, pattern) in self.dog_patterns.iter().enumerate() {
            if let Some(variation) = pattern.decode_variation(word) {
                return Some((index, variation));
            }
        }
        None
    }

    pub fn process_string(&self, content: &str, mode: CipherMode) -> io::Result<Vec<u8>> {
        let mut result = Vec::new();
        
        // For decryption, trim trailing spaces and split by spaces to get words
        match mode {
            CipherMode::Decrypt => {
                let words: Vec<&str> = content.trim_end().split(' ').collect();
                let mut i = 0;
                
                while i < words.len() {
                    let remaining = words.len() - i;
                    
                    // Check if we have 4 words - handle as 3 bytes (24 bits)
                    if remaining >= 4 {
                        if cfg!(test) {
                            println!("DEBUG DECODE: Starting chunk with 4 words, 3 bytes");
                        }
                        
                        let word1 = words[i];
                        let decoded1 = self.decode_word_with_fallback(word1, 0)?;
                        let bits1 = decoded1.1 & 0x3F; // First 6 bits
                        
                        if cfg!(test) {
                            println!("DEBUG DECODE: Word {}, pattern_index={}, six_bits={}", 
                                    word1, decoded1.0, bits1);
                        }
                        
                        let word2 = words[i + 1];
                        let decoded2 = self.decode_word_with_fallback(word2, 1)?;
                        let bits2 = decoded2.1 & 0x3F; // Second 6 bits
                        
                        if cfg!(test) {
                            println!("DEBUG DECODE: Word {}, pattern_index={}, six_bits={}", 
                                    word2, decoded2.0, bits2);
                        }
                        
                        let word3 = words[i + 2];
                        let decoded3 = self.decode_word_with_fallback(word3, 2)?;
                        let bits3 = decoded3.1 & 0x3F; // Third 6 bits
                        
                        if cfg!(test) {
                            println!("DEBUG DECODE: Word {}, pattern_index={}, six_bits={}", 
                                    word3, decoded3.0, bits3);
                        }
                        
                        let word4 = words[i + 3];
                        let decoded4 = self.decode_word_with_fallback(word4, 3)?;
                        let bits4 = decoded4.1 & 0x3F; // Fourth 6 bits
                        
                        if cfg!(test) {
                            println!("DEBUG DECODE: Word {}, pattern_index={}, six_bits={}", 
                                    word4, decoded4.0, bits4);
                        }
                        
                        // Assemble the full 24-bit value
                        let mut value: u32 = 0;
                        value |= (bits1 as u32) << 18;
                        value |= (bits2 as u32) << 12;
                        value |= (bits3 as u32) << 6;
                        value |= bits4 as u32;
                        
                        if cfg!(test) {
                            println!("DEBUG DECODE: Assembled value=0x{:x}", value);
                        }
                        
                        // Extract the 3 bytes
                        let byte1 = ((value >> 16) & 0xFF) as u8;
                        let byte2 = ((value >> 8) & 0xFF) as u8;
                        let byte3 = (value & 0xFF) as u8;
                        
                        if cfg!(test) {
                            println!("DEBUG DECODE: Extracted byte 0 at shift=16: 0x{:x}", byte1);
                            println!("DEBUG DECODE: Extracted byte 1 at shift=8: 0x{:x}", byte2);
                            println!("DEBUG DECODE: Extracted byte 2 at shift=0: 0x{:x}", byte3);
                        }
                        
                        result.push(byte1);
                        result.push(byte2);
                        result.push(byte3);
                        
                        i += 4;
                    } else if remaining >= 3 {
                        // Handle 2 bytes (16 bits) from 3 words
                        if cfg!(test) {
                            println!("DEBUG DECODE: Starting chunk with 3 words, 2 bytes");
                        }
                        
                        let word1 = words[i];
                        let decoded1 = self.decode_word_with_fallback(word1, 0)?;
                        let bits1 = decoded1.1 & 0x1F; // First 5 bits
                        
                        if cfg!(test) {
                            println!("DEBUG DECODE: Word {}, pattern_index={}, six_bits={}", 
                                    word1, decoded1.0, bits1);
                        }
                        
                        let word2 = words[i + 1];
                        let decoded2 = self.decode_word_with_fallback(word2, 1)?;
                        let bits2 = decoded2.1 & 0x3F; // Middle 6 bits
                        
                        if cfg!(test) {
                            println!("DEBUG DECODE: Word {}, pattern_index={}, six_bits={}", 
                                    word2, decoded2.0, bits2);
                        }
                        
                        let word3 = words[i + 2];
                        let decoded3 = self.decode_word_with_fallback(word3, 2)?;
                        let bits3 = decoded3.1 & 0x1F; // Last 5 bits
                        
                        if cfg!(test) {
                            println!("DEBUG DECODE: Word {}, pattern_index={}, six_bits={}", 
                                    word3, decoded3.0, bits3);
                        }
                        
                        // Assemble the full 16-bit value
                        let mut value: u16 = 0;
                        value |= (bits1 as u16) << 11;
                        value |= (bits2 as u16) << 5;
                        value |= bits3 as u16;
                        
                        if cfg!(test) {
                            println!("DEBUG DECODE: Assembled value=0x{:x}", value);
                        }
                        
                        // Extract the 2 bytes
                        let byte1 = ((value >> 8) & 0xFF) as u8;
                        let byte2 = (value & 0xFF) as u8;
                        
                        if cfg!(test) {
                            println!("DEBUG DECODE: Extracted byte 0 at shift=8: 0x{:x}", byte1);
                            println!("DEBUG DECODE: Extracted byte 1 at shift=0: 0x{:x}", byte2);
                        }
                        
                        result.push(byte1);
                        result.push(byte2);
                        
                        i += 3;
                    } else if remaining >= 2 {
                        // Handle 1 byte (8 bits) from 2 words
                        if cfg!(test) {
                            println!("DEBUG DECODE: Starting chunk with 2 words, 1 bytes");
                        }
                        
                        let word1 = words[i];
                        let decoded1 = self.decode_word_with_fallback(word1, 0)?;
                        let high_bits = decoded1.1 & 0x0F; // Higher 4 bits
                        
                        if cfg!(test) {
                            println!("DEBUG DECODE: Word {}, pattern_index={}, six_bits={}", 
                                    word1, decoded1.0, high_bits);
                        }
                        
                        let word2 = words[i + 1];
                        let decoded2 = self.decode_word_with_fallback(word2, 1)?;
                        let low_bits = decoded2.1 & 0x0F; // Lower 4 bits
                        
                        if cfg!(test) {
                            println!("DEBUG DECODE: Word {}, pattern_index={}, six_bits={}", 
                                    word2, decoded2.0, low_bits);
                        }
                        
                        // Combine into a single byte
                        let value = (high_bits << 4) | low_bits;
                        
                        if cfg!(test) {
                            println!("DEBUG DECODE: Assembled value=0x{:x}", value);
                            println!("DEBUG DECODE: Extracted single byte: 0x{:x}", value);
                        }
                        
                        result.push(value);
                        i += 2;
                    } else {
                        break;
                    }
                }
            },
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Only decryption is supported for process_string",
                ));
            }
        }
        
        Ok(result)
    }
    
    fn decode_word_with_fallback(&self, word: &str, expected_position: usize) -> io::Result<(usize, u8)> {
        // Try to decode with current dialect first
        let decoded = match self.current_dialect {
            CipherDialect::Cat => self.decode_word_cat(word),
            CipherDialect::Dog => self.decode_word_dog(word),
        };
        
        if let Some(decoded_value) = decoded {
            // Calculate expected pattern index
            let expected_pattern_index = expected_position % match self.current_dialect {
                CipherDialect::Cat => self.cat_patterns.len(),
                CipherDialect::Dog => self.dog_patterns.len(),
            };
            
            // If the pattern matches expected position, use it directly
            if decoded_value.0 == expected_pattern_index {
                return Ok(decoded_value);
            }
        }
        
        // Try the other dialect as fallback if current didn't match
        let fallback = match self.current_dialect {
            CipherDialect::Cat => self.decode_word_dog(word),
            CipherDialect::Dog => self.decode_word_cat(word),
        };
        
        if let Some(fallback_value) = fallback {
            return Ok(fallback_value);
        }
        
        // If we get here, we couldn't decode the word properly
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Pattern mismatch for word: {}", word)
        ))
    }

    /// Encodes a bit value into a word using the pattern at the specified position
    fn encode_word(&self, bits: u8, position: usize) -> io::Result<String> {
        let patterns = match self.current_dialect {
            CipherDialect::Cat => &self.cat_patterns,
            CipherDialect::Dog => &self.dog_patterns,
        };
        
        if position >= patterns.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Invalid pattern position: {}", position),
            ));
        }
        
        Ok(patterns[position].generate_variation(bits))
    }
}

// For backwards compatibility
pub type CatCipher = AnimalCipher;

#[cfg(test)]
mod tests {
    use super::*;
    

    #[test]
    fn test_basic_encryption_decryption() {
        let cipher = AnimalCipher::new(CipherDialect::Cat);
        let test_data = b"Hello, World!";
        
        // Encrypt
        let mut encrypted = Vec::new();
        cipher.process_data(test_data, &mut encrypted, CipherMode::Encrypt).unwrap();
        let encrypted_str = String::from_utf8(encrypted.clone()).unwrap();
        
        // Decrypt
        let decrypted = cipher.process_string(&encrypted_str, CipherMode::Decrypt).unwrap();
        println!("Original: {:?}, Encrypted: {:?}, Decrypted: {:?}", test_data, encrypted, decrypted);
        assert_eq!(test_data.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_pattern_consistency() {
        let cipher = AnimalCipher::new(CipherDialect::Cat);
        
        // Test all possible 6-bit values
        for value in 0..64u8 {
            let mut encrypted = Vec::new();
            cipher.process_data(&[value], &mut encrypted, CipherMode::Encrypt).unwrap();
            let encrypted_str = String::from_utf8(encrypted.clone()).unwrap();
            
            let decrypted = cipher.process_string(&encrypted_str, CipherMode::Decrypt).unwrap();
            println!("Original: {:?}, Encrypted: {:?}, Decrypted: {:?}", &[value], &encrypted, &decrypted);
            assert_eq!(&[value], decrypted.as_slice(), 
                "Failed for value {}: encrypted as '{}'", value, encrypted_str.trim());
        }
    }

    #[test]
    fn test_multi_byte_encryption() {
        let cipher = AnimalCipher::new(CipherDialect::Cat);
        let test_cases = vec![
            vec![0u8, 1u8, 2u8],
            vec![255u8, 254u8, 253u8],
            vec![128u8, 128u8, 128u8],
            vec![0u8, 255u8, 0u8],
        ];

        for test_case in test_cases {
            let mut encrypted = Vec::new();
            cipher.process_data(&test_case, &mut encrypted, CipherMode::Encrypt).unwrap();
            let encrypted_str = String::from_utf8(encrypted.clone()).unwrap();
            
            let decrypted = cipher.process_string(&encrypted_str, CipherMode::Decrypt).unwrap();
            println!("Original: {:?}, Encrypted: {:?}, Decrypted: {:?}", test_case, &encrypted, &decrypted);
            assert_eq!(test_case.as_slice(), decrypted.as_slice(),
                "Failed for case {:?}: encrypted as '{}'", test_case, encrypted_str.trim());
        }
    }

    #[test]
    fn test_dialect_switching() {
        let cat_cipher = AnimalCipher::new(CipherDialect::Cat);
        let dog_cipher = AnimalCipher::new(CipherDialect::Dog);
        let test_data = b"Test message";

        // Encrypt with cat dialect
        let mut cat_encrypted = Vec::new();
        cat_cipher.process_data(test_data, &mut cat_encrypted, CipherMode::Encrypt).unwrap();
        let cat_str = String::from_utf8(cat_encrypted.clone()).unwrap();

        // Encrypt with dog dialect
        let mut dog_encrypted = Vec::new();
        dog_cipher.process_data(test_data, &mut dog_encrypted, CipherMode::Encrypt).unwrap();
        let dog_str = String::from_utf8(dog_encrypted.clone()).unwrap();

        // They should encrypt to different strings
        assert_ne!(cat_str, dog_str, "Cat and dog dialects produced identical output");

        // But both should decrypt correctly
        let cat_decrypted = cat_cipher.process_string(&cat_str, CipherMode::Decrypt).unwrap();
        let dog_decrypted = dog_cipher.process_string(&dog_str, CipherMode::Decrypt).unwrap();

        println!("Original: {:?}, Encrypted: {:?}, Decrypted: {:?}", test_data, &cat_encrypted, &cat_decrypted);
        println!("Original: {:?}, Encrypted: {:?}, Decrypted: {:?}", test_data, &dog_encrypted, &dog_decrypted);

        assert_eq!(test_data.as_slice(), cat_decrypted.as_slice());
        assert_eq!(test_data.as_slice(), dog_decrypted.as_slice());
    }

    #[test]
    fn test_edge_cases() {
        let cipher = AnimalCipher::new(CipherDialect::Cat);
        
        // Test empty input
        let mut encrypted = Vec::new();
        cipher.process_data(&[], &mut encrypted, CipherMode::Encrypt).unwrap();
        assert!(encrypted.is_empty());

        // Test single byte
        let mut encrypted = Vec::new();
        cipher.process_data(&[42], &mut encrypted, CipherMode::Encrypt).unwrap();
        let encrypted_str = String::from_utf8(encrypted.clone()).unwrap();
        let decrypted = cipher.process_string(&encrypted_str, CipherMode::Decrypt).unwrap();
        println!("Original: {:?}, Encrypted: {:?}, Decrypted: {:?}", &[42], &encrypted, &decrypted);
        assert_eq!(&[42], decrypted.as_slice());

        // Test two bytes
        let mut encrypted = Vec::new();
        cipher.process_data(&[0xAA, 0x55], &mut encrypted, CipherMode::Encrypt).unwrap();
        let encrypted_str = String::from_utf8(encrypted.clone()).unwrap();
        let decrypted = cipher.process_string(&encrypted_str, CipherMode::Decrypt).unwrap();
        println!("Original: {:?}, Encrypted: {:?}, Decrypted: {:?}", &[0xAA, 0x55], &encrypted, &decrypted);
        assert_eq!(&[0xAA, 0x55], decrypted.as_slice());
    }
}

