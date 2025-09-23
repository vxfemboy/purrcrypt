// src/cipher/efficient.rs
// Super efficient pet sound encoding that's adowable AND compact! Nyaa~ >w<

use std::io::{self, Write};

#[derive(Debug, Clone, Copy)]
pub enum PetDialect {
    Kitty, // meow mode
    Puppy, // woof mode
}

#[derive(Debug, Clone, Copy)]
pub enum SoundType {
    // Structure markers
    MessageStart,
    MessageEnd,
    WordBoundary,
    ErrorMarker,

    // Data encoding sounds with emotional context
    HappySound,    // 0 bits - content, playful
    NeutralSound,  // 1 bits - calm, normal
    ExcitedSound,  // 2 bits - excited, energetic
    UpsetSound,    // Error correction - confused, frustrated
    QuestionSound, // Checksums - curious, questioning
    ContentSound,  // 3 bits - satisfied, purring
    AlertSound,    // 4 bits - attention, warning
    PlayfulSound,  // 5 bits - playful, mischievous
}

#[derive(Debug, Clone, Copy)]
pub enum EmotionalContext {
    // Content states
    Content, // Purring, satisfied
    Excited, // Playful, energetic
    Calm,    // Relaxed, peaceful
    Playful, // Mischievous, fun

    // Communication states
    Greeting,  // Hello, welcome
    Request,   // Asking for something
    Attention, // Seeking attention
    Warning,   // Alert, caution
    Alert,     // Alert, urgent

    // Error states
    Confused,   // Don't understand
    Frustrated, // Annoyed, upset
    Surprised,  // Unexpected
    Curious,    // Questioning
}

#[derive(Debug, Clone, Copy)]
pub enum FileType {
    Text,    // Documents, messages
    Image,   // Pictures, graphics
    Video,   // Movies, clips
    Audio,   // Music, sounds
    Data,    // Binary, compressed
    Unknown, // Generic
}

#[derive(Debug, Clone)]
pub struct EfficientPetCipher {
    dialect: PetDialect,
    file_type: FileType,
    mood: EmotionalContext,
    // Lookup tables for super fast encoding/decoding
    sound_map: Vec<SoundMapping>,
    reverse_map: std::collections::HashMap<String, (u8, SoundType)>,
    // Natural language features
    sentence_variations: Vec<String>,
    filler_words: Vec<String>,
    punctuation_patterns: Vec<String>,
}

#[derive(Debug, Clone)]
struct SoundMapping {
    #[allow(dead_code)]
    pattern: String,
    #[allow(dead_code)]
    sound_type: SoundType,
}

impl EfficientPetCipher {
    pub fn new(dialect: PetDialect) -> Self {
        Self::new_with_context(dialect, FileType::Unknown, EmotionalContext::Calm)
    }

    pub fn new_with_context(
        dialect: PetDialect,
        file_type: FileType,
        mood: EmotionalContext,
    ) -> Self {
        let mut cipher = Self {
            dialect,
            file_type,
            mood,
            sound_map: Vec::new(),
            reverse_map: std::collections::HashMap::new(),
            sentence_variations: Vec::new(),
            filler_words: Vec::new(),
            punctuation_patterns: Vec::new(),
        };
        cipher.initialize_sound_mappings();
        cipher.initialize_natural_features();
        cipher
    }

    pub fn set_mood(&mut self, mood: EmotionalContext) {
        self.mood = mood;
        self.initialize_natural_features();
    }

    pub fn set_file_type(&mut self, file_type: FileType) {
        self.file_type = file_type;
        self.initialize_natural_features();
    }

    fn initialize_sound_mappings(&mut self) {
        match self.dialect {
            PetDialect::Kitty => {
                // Structure markers - unique patterns that don't conflict with data
                self.add_sound(
                    "meow meow",
                    0,
                    SoundType::MessageStart,
                    EmotionalContext::Greeting,
                );
                self.add_sound(
                    "trill trill",
                    0,
                    SoundType::MessageEnd,
                    EmotionalContext::Content,
                );
                self.add_sound(
                    "purr purr",
                    0,
                    SoundType::WordBoundary,
                    EmotionalContext::Playful,
                );
                self.add_sound(
                    "hiss",
                    0,
                    SoundType::ErrorMarker,
                    EmotionalContext::Frustrated,
                );

                // Basic nibble mapping (0-15) - direct sound to nibble mapping
                self.add_sound("purr", 0, SoundType::HappySound, EmotionalContext::Content);
                self.add_sound("chirp", 1, SoundType::HappySound, EmotionalContext::Excited);
                self.add_sound("trill", 2, SoundType::HappySound, EmotionalContext::Calm);
                self.add_sound("mrrp", 3, SoundType::HappySound, EmotionalContext::Playful);

                // Neutral sounds (4-7) - calm, normal communication
                self.add_sound("meow", 4, SoundType::NeutralSound, EmotionalContext::Calm);
                self.add_sound(
                    "mrow",
                    5,
                    SoundType::NeutralSound,
                    EmotionalContext::Request,
                );
                self.add_sound("nya", 6, SoundType::NeutralSound, EmotionalContext::Excited);
                self.add_sound(
                    "mew",
                    7,
                    SoundType::NeutralSound,
                    EmotionalContext::Attention,
                );

                // Extended sounds (8-11) - energetic, playful
                self.add_sound(
                    "prrr",
                    8,
                    SoundType::ExcitedSound,
                    EmotionalContext::Excited,
                );
                self.add_sound(
                    "chatter",
                    9,
                    SoundType::ExcitedSound,
                    EmotionalContext::Playful,
                );
                self.add_sound(
                    "mrrrow",
                    10,
                    SoundType::ExcitedSound,
                    EmotionalContext::Excited,
                );
                self.add_sound(
                    "brrr",
                    11,
                    SoundType::ExcitedSound,
                    EmotionalContext::Content,
                );

                // Extended sounds (12-15) - satisfied, purring
                self.add_sound(
                    "meoww",
                    12,
                    SoundType::ContentSound,
                    EmotionalContext::Content,
                );
                self.add_sound(
                    "mroww",
                    13,
                    SoundType::ContentSound,
                    EmotionalContext::Content,
                );
                self.add_sound("nyaa", 14, SoundType::ContentSound, EmotionalContext::Calm);
                self.add_sound(
                    "meww",
                    15,
                    SoundType::ContentSound,
                    EmotionalContext::Playful,
                );

                // Additional sound types for completeness
                self.add_sound(
                    "yowl",
                    0,
                    SoundType::UpsetSound,
                    EmotionalContext::Frustrated,
                );
                self.add_sound(
                    "mrow?",
                    0,
                    SoundType::QuestionSound,
                    EmotionalContext::Curious,
                );
                self.add_sound(
                    "nya?",
                    0,
                    SoundType::QuestionSound,
                    EmotionalContext::Curious,
                );
                self.add_sound(
                    "mew?",
                    0,
                    SoundType::QuestionSound,
                    EmotionalContext::Curious,
                );
                self.add_sound("hiss", 0, SoundType::AlertSound, EmotionalContext::Alert);
                self.add_sound(
                    "chirr",
                    0,
                    SoundType::PlayfulSound,
                    EmotionalContext::Playful,
                );
            }
            PetDialect::Puppy => {
                // Structure markers - unique patterns that don't conflict with data
                self.add_sound(
                    "woof woof",
                    0,
                    SoundType::MessageStart,
                    EmotionalContext::Greeting,
                );
                self.add_sound(
                    "howl howl",
                    0,
                    SoundType::MessageEnd,
                    EmotionalContext::Content,
                );
                self.add_sound(
                    "ruff ruff",
                    0,
                    SoundType::WordBoundary,
                    EmotionalContext::Playful,
                );
                self.add_sound(
                    "growl",
                    0,
                    SoundType::ErrorMarker,
                    EmotionalContext::Frustrated,
                );

                // Basic nibble mapping (0-15) - direct sound to nibble mapping
                self.add_sound(
                    "tail-wag",
                    0,
                    SoundType::HappySound,
                    EmotionalContext::Content,
                );
                self.add_sound("pant", 1, SoundType::HappySound, EmotionalContext::Excited);
                self.add_sound("yip", 2, SoundType::HappySound, EmotionalContext::Playful);
                self.add_sound("boof", 3, SoundType::HappySound, EmotionalContext::Calm);

                // Neutral sounds (4-7) - calm, normal communication
                self.add_sound("woof", 4, SoundType::NeutralSound, EmotionalContext::Calm);
                self.add_sound(
                    "bark",
                    5,
                    SoundType::NeutralSound,
                    EmotionalContext::Request,
                );
                self.add_sound(
                    "arf",
                    6,
                    SoundType::NeutralSound,
                    EmotionalContext::Attention,
                );
                self.add_sound("wrf", 7, SoundType::NeutralSound, EmotionalContext::Playful);

                // Extended sounds (8-11) - energetic, playful
                self.add_sound(
                    "wooof",
                    8,
                    SoundType::ExcitedSound,
                    EmotionalContext::Excited,
                );
                self.add_sound(
                    "baark",
                    9,
                    SoundType::ExcitedSound,
                    EmotionalContext::Playful,
                );
                self.add_sound(
                    "arff",
                    10,
                    SoundType::ExcitedSound,
                    EmotionalContext::Excited,
                );
                self.add_sound(
                    "wrff",
                    11,
                    SoundType::ExcitedSound,
                    EmotionalContext::Playful,
                );

                // Extended sounds (12-15) - satisfied, relaxed
                self.add_sound(
                    "woooof",
                    12,
                    SoundType::ContentSound,
                    EmotionalContext::Content,
                );
                self.add_sound(
                    "baaark",
                    13,
                    SoundType::ContentSound,
                    EmotionalContext::Content,
                );
                self.add_sound("arfff", 14, SoundType::ContentSound, EmotionalContext::Calm);
                self.add_sound(
                    "wrfff",
                    15,
                    SoundType::ContentSound,
                    EmotionalContext::Content,
                );

                // Question sounds (checksums) - curious, questioning
                self.add_sound(
                    "ruff?",
                    0,
                    SoundType::QuestionSound,
                    EmotionalContext::Curious,
                );
                self.add_sound(
                    "woof?",
                    0,
                    SoundType::QuestionSound,
                    EmotionalContext::Curious,
                );
                self.add_sound(
                    "arf?",
                    0,
                    SoundType::QuestionSound,
                    EmotionalContext::Curious,
                );
                self.add_sound(
                    "yip?",
                    0,
                    SoundType::QuestionSound,
                    EmotionalContext::Curious,
                );

                // Additional sound types for completeness
                self.add_sound(
                    "snarl",
                    0,
                    SoundType::UpsetSound,
                    EmotionalContext::Frustrated,
                );
                self.add_sound("growl", 0, SoundType::AlertSound, EmotionalContext::Alert);
                self.add_sound(
                    "play-bow",
                    0,
                    SoundType::PlayfulSound,
                    EmotionalContext::Playful,
                );
            }
        }
    }

    fn add_sound(
        &mut self,
        pattern: &str,
        bits: u8,
        sound_type: SoundType,
        _emotional_context: EmotionalContext,
    ) {
        let mapping = SoundMapping {
            pattern: pattern.to_string(),
            sound_type,
        };
        self.sound_map.push(mapping);
        self.reverse_map
            .insert(pattern.to_string(), (bits, sound_type));
    }

    fn initialize_natural_features(&mut self) {
        self.sentence_variations.clear();
        self.filler_words.clear();
        self.punctuation_patterns.clear();

        match self.dialect {
            PetDialect::Kitty => {
                // Sentence variations based on mood and file type
                match (&self.mood, &self.file_type) {
                    (EmotionalContext::Excited, FileType::Image) => {
                        self.sentence_variations = vec![
                            "Oh my! Look at this!".to_string(),
                            "What a pretty picture!".to_string(),
                            "So colorful and bright!".to_string(),
                        ];
                    }
                    (EmotionalContext::Calm, FileType::Text) => {
                        self.sentence_variations = vec![
                            "Let me read this carefully.".to_string(),
                            "This looks interesting.".to_string(),
                            "I'll take my time with this.".to_string(),
                        ];
                    }
                    (EmotionalContext::Playful, FileType::Video) => {
                        self.sentence_variations = vec![
                            "Time for some fun!".to_string(),
                            "This looks exciting!".to_string(),
                            "Let's play together!".to_string(),
                        ];
                    }
                    _ => {
                        self.sentence_variations = vec![
                            "Here's something for you.".to_string(),
                            "I have a message.".to_string(),
                            "This is important.".to_string(),
                        ];
                    }
                }

                // Filler words for natural flow
                self.filler_words = vec![
                    "little".to_string(),
                    "big".to_string(),
                    "happy".to_string(),
                    "soft".to_string(),
                    "warm".to_string(),
                    "cozy".to_string(),
                    "bright".to_string(),
                    "shiny".to_string(),
                    "smooth".to_string(),
                ];

                // Punctuation patterns
                self.punctuation_patterns = vec![
                    ", ".to_string(),
                    "! ".to_string(),
                    "? ".to_string(),
                    "... ".to_string(),
                    "~ ".to_string(),
                    "! ".to_string(),
                ];
            }
            PetDialect::Puppy => {
                // Sentence variations based on mood and file type
                match (&self.mood, &self.file_type) {
                    (EmotionalContext::Excited, FileType::Image) => {
                        self.sentence_variations = vec![
                            "Wow! Look at this!".to_string(),
                            "This is amazing!".to_string(),
                            "So much fun to see!".to_string(),
                        ];
                    }
                    (EmotionalContext::Calm, FileType::Text) => {
                        self.sentence_variations = vec![
                            "Let me check this out.".to_string(),
                            "This seems important.".to_string(),
                            "I'll be careful with this.".to_string(),
                        ];
                    }
                    (EmotionalContext::Playful, FileType::Video) => {
                        self.sentence_variations = vec![
                            "Time to play!".to_string(),
                            "This looks like fun!".to_string(),
                            "Let's have some fun!".to_string(),
                        ];
                    }
                    _ => {
                        self.sentence_variations = vec![
                            "Here's something for you!".to_string(),
                            "I have a message!".to_string(),
                            "This is important!".to_string(),
                        ];
                    }
                }

                // Filler words for natural flow
                self.filler_words = vec![
                    "good".to_string(),
                    "big".to_string(),
                    "happy".to_string(),
                    "soft".to_string(),
                    "warm".to_string(),
                    "nice".to_string(),
                    "bright".to_string(),
                    "fun".to_string(),
                    "great".to_string(),
                ];

                // Punctuation patterns
                self.punctuation_patterns = vec![
                    ", ".to_string(),
                    "! ".to_string(),
                    "? ".to_string(),
                    "... ".to_string(),
                    "! ".to_string(),
                    "! ".to_string(),
                ];
            }
        }
    }

    /// Encode data with super efficient pet sounds! Nyaa~ >w<
    pub fn encode_data<W: Write>(&self, data: &[u8], writer: &mut W) -> io::Result<()> {
        // Add contextual greeting based on mood and file type
        self.write_contextual_greeting(writer)?;

        // Process data in 4-bit nibbles for maximum efficiency
        for (i, &byte) in data.iter().enumerate() {
            // Occasionally add filler words for naturalness
            if i > 0 && i % 16 == 0 && !self.filler_words.is_empty() {
                self.write_filler_word(writer)?;
            }

            // Encode high nibble (4 bits) with emotional context
            let high_nibble = (byte >> 4) & 0x0F;
            self.encode_nibble_contextual(writer, high_nibble)?;

            // Encode low nibble (4 bits) with emotional context
            let low_nibble = byte & 0x0F;
            self.encode_nibble_contextual(writer, low_nibble)?;
        }

        // Add contextual closing based on mood
        self.write_contextual_closing(writer)?;

        Ok(())
    }

    fn encode_nibble_contextual<W: Write>(&self, writer: &mut W, nibble: u8) -> io::Result<()> {
        // Use basic sound mapping for consistent encoding/decoding
        let pattern = self.get_basic_sound_for_nibble(nibble);

        if cfg!(test) {
            println!("DEBUG: Encoding nibble {} as '{}'", nibble, pattern);
        }

        writer.write_all(pattern.as_bytes())?;
        writer.write_all(b" ")?;

        Ok(())
    }

    fn get_basic_sound_for_nibble(&self, nibble: u8) -> String {
        let sound_patterns = match self.dialect {
            PetDialect::Kitty => [
                "purr", "chirp", "trill", "mrrp", // 0-3
                "meow", "mrow", "nya", "mew", // 4-7
                "prrr", "chatter", "mrrrow", "brrr", // 8-11
                "meoww", "mroww", "nyaa", "meww", // 12-15
            ],
            PetDialect::Puppy => [
                "tail-wag", "pant", "yip", "boof", // 0-3
                "woof", "bark", "arf", "wrf", // 4-7
                "wooof", "baark", "arff", "wrff", // 8-11
                "woooof", "baaark", "arfff", "wrfff", // 12-15
            ],
        };

        sound_patterns[nibble as usize % sound_patterns.len()].to_string()
    }

    fn write_contextual_greeting<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        if !self.sentence_variations.is_empty() {
            // Use mood to select different greetings
            let greeting_index = match self.mood {
                EmotionalContext::Excited => 0,
                EmotionalContext::Calm => 1,
                EmotionalContext::Playful => 2,
                EmotionalContext::Content => 3,
                _ => 0,
            };
            let greeting =
                &self.sentence_variations[greeting_index % self.sentence_variations.len()];
            writer.write_all(greeting.as_bytes())?;
            writer.write_all(b" ")?;
        }
        Ok(())
    }

    fn write_contextual_closing<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        if self.sentence_variations.len() > 1 {
            // Use mood to select different closings
            let closing_index = match self.mood {
                EmotionalContext::Excited => 1,
                EmotionalContext::Calm => 2,
                EmotionalContext::Playful => 3,
                EmotionalContext::Content => 4,
                _ => 1,
            };
            let closing = &self.sentence_variations[closing_index % self.sentence_variations.len()];
            writer.write_all(b" ")?;
            writer.write_all(closing.as_bytes())?;
            writer.write_all(b" ")?;
        }
        Ok(())
    }

    fn write_filler_word<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        if !self.filler_words.is_empty() {
            let filler = &self.filler_words[0]; // Simple selection for now
            writer.write_all(filler.as_bytes())?;
            writer.write_all(b" ")?;
        }
        Ok(())
    }

    /// Decode pet sounds back to data! *purrs excitedly*
    pub fn decode_data(&self, input: &str) -> io::Result<Vec<u8>> {
        let words: Vec<&str> = input.split_whitespace().collect();
        let mut nibbles = Vec::new();
        let mut i = 0;

        // Process all words, trying to decode each as a nibble
        while i < words.len() {
            if cfg!(test) {
                println!("DEBUG: Processing word '{}'", words[i]);
            }

            // Skip contextual words only - commented out to avoid interfering with data decoding
            // if self.is_contextual_word(words[i]) {
            //     if cfg!(test) {
            //         println!("DEBUG: Skipping word '{}' (contextual word)", words[i]);
            //     }
            //     i += 1;
            //     continue;
            // }

            // Try to decode as a nibble
            match self.decode_nibble(words[i]) {
                Ok(nibble) => {
                    if cfg!(test) {
                        println!("DEBUG: Decoded '{}' as nibble {}", words[i], nibble);
                    }
                    nibbles.push(nibble);
                }
                Err(_) => {
                    if cfg!(test) {
                        println!("DEBUG: Failed to decode word '{}'", words[i]);
                    }
                    // Skip unknown words
                }
            }
            i += 1;
        }

        // Convert nibbles to bytes (pair them up)
        let mut bytes = Vec::new();
        for chunk in nibbles.chunks(2) {
            if chunk.len() == 2 {
                let byte = (chunk[0] << 4) | chunk[1];
                bytes.push(byte);
            }
        }

        Ok(bytes)
    }

    fn decode_nibble(&self, word: &str) -> io::Result<u8> {
        // First try to find in the sound map (for contextual sounds)
        if let Some((bits, _)) = self.reverse_map.get(word) {
            if cfg!(test) {
                println!("DEBUG: Found '{}' in reverse_map -> {}", word, bits);
            }
            return Ok(*bits);
        }

        if cfg!(test) {
            println!(
                "DEBUG: '{}' not found in reverse_map. Available keys: {:?}",
                word,
                self.reverse_map.keys().collect::<Vec<_>>()
            );
        }

        // Fallback to basic sound patterns
        let sound_patterns = match self.dialect {
            PetDialect::Kitty => [
                "purr", "chirp", "trill", "mrrp", // 0-3
                "meow", "mrow", "nya", "mew", // 4-7
                "prrr", "chirr", "trrr", "mrrr", // 8-11 (extended)
                "meoww", "mroww", "nyaa", "meww", // 12-15 (extended)
            ],
            PetDialect::Puppy => [
                "tail-wag", "pant", "yip", "boof", // 0-3
                "woof", "bark", "arf", "wrf", // 4-7
                "wooof", "baark", "arff", "wrff", // 8-11 (extended)
                "woooof", "baaark", "arfff", "wrfff", // 12-15 (extended)
            ],
        };

        // Find the exact pattern match
        for (index, &pattern) in sound_patterns.iter().enumerate() {
            if pattern == word {
                let nibble_value = index as u8;
                if cfg!(test) {
                    println!(
                        "DEBUG: Decoded basic '{}' to nibble value {}",
                        word, nibble_value
                    );
                }
                return Ok(nibble_value);
            }
        }

        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Unknown sound: {}", word),
        ))
    }

    #[allow(dead_code)]
    fn is_marker(&self, word: &str, marker_type: SoundType) -> bool {
        self.sound_map.iter().any(|m| {
            m.pattern == word
                && std::mem::discriminant(&m.sound_type) == std::mem::discriminant(&marker_type)
        })
    }

    #[allow(dead_code)]
    fn is_contextual_word(&self, word: &str) -> bool {
        // Check if word is contextual text (not a pet sound)
        // Only include complete contextual phrases that are unlikely to appear in actual data
        let contextual_words = [
            "Oh",
            "Look",
            "What",
            "So",
            "Let",
            "This",
            "I'll",
            "Time",
            "Here's",
            "I",
            "Wow!",
            "amazing!",
            "check",
            "out.",
            "seems",
            "important.",
            "be",
            "careful",
            "with",
            "this.",
            "like",
            "fun!",
            "have",
            "some",
            "fun!",
            "little",
            "big",
            "happy",
            "soft",
            "warm",
            "cozy",
            "bright",
            "shiny",
            "smooth",
            "good",
            "nice",
            "great",
        ];

        contextual_words.contains(&word)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kitty_encoding() {
        let cipher = EfficientPetCipher::new(PetDialect::Kitty);
        let test_data = b"Hello";

        let mut encoded = Vec::new();
        cipher.encode_data(test_data, &mut encoded).unwrap();
        let encoded_str = String::from_utf8(encoded).unwrap();

        println!("Kitty encoded: {}", encoded_str);

        // Debug: let's test just a single byte
        println!("Testing single byte encoding...");
        let single_byte = &[72u8]; // 'H'
        let mut single_encoded = Vec::new();
        cipher
            .encode_data(single_byte, &mut single_encoded)
            .unwrap();
        let single_encoded_str = String::from_utf8(single_encoded).unwrap();
        println!("Single byte 'H' (72) encoded as: {}", single_encoded_str);

        let single_decoded = cipher.decode_data(&single_encoded_str).unwrap();
        println!("Single byte decoded back to: {:?}", single_decoded);

        let decoded = cipher.decode_data(&encoded_str).unwrap();
        println!("Original: {:?}, Decoded: {:?}", test_data, decoded);
        assert_eq!(test_data.to_vec(), decoded);
    }

    #[test]
    fn test_contextual_encoding() {
        // Test excited kitty with image file
        let excited_kitty = EfficientPetCipher::new_with_context(
            PetDialect::Kitty,
            FileType::Image,
            EmotionalContext::Excited,
        );

        let test_data = b"Test image data";
        let mut encoded = Vec::new();
        excited_kitty.encode_data(test_data, &mut encoded).unwrap();
        let encoded_str = String::from_utf8(encoded).unwrap();

        println!("Excited kitty with image: {}", encoded_str);

        // Test calm puppy with text file
        let calm_puppy = EfficientPetCipher::new_with_context(
            PetDialect::Puppy,
            FileType::Text,
            EmotionalContext::Calm,
        );

        let mut encoded2 = Vec::new();
        calm_puppy.encode_data(test_data, &mut encoded2).unwrap();
        let encoded_str2 = String::from_utf8(encoded2).unwrap();

        println!("Calm puppy with text: {}", encoded_str2);

        // Both should decode correctly
        let decoded1 = excited_kitty.decode_data(&encoded_str).unwrap();
        let decoded2 = calm_puppy.decode_data(&encoded_str2).unwrap();

        assert_eq!(test_data.to_vec(), decoded1);
        assert_eq!(test_data.to_vec(), decoded2);
    }

    #[test]
    fn test_puppy_encoding() {
        let cipher = EfficientPetCipher::new(PetDialect::Puppy);
        let test_data = b"World";

        let mut encoded = Vec::new();
        cipher.encode_data(test_data, &mut encoded).unwrap();
        let encoded_str = String::from_utf8(encoded).unwrap();

        println!("Puppy encoded: {}", encoded_str);

        let decoded = cipher.decode_data(&encoded_str).unwrap();
        assert_eq!(test_data.to_vec(), decoded);
    }

    #[test]
    fn test_efficiency() {
        let cipher = EfficientPetCipher::new(PetDialect::Kitty);
        let test_data = b"Hello World! This is a test message.";

        let mut encoded = Vec::new();
        cipher.encode_data(test_data, &mut encoded).unwrap();
        let encoded_str = String::from_utf8(encoded).unwrap();

        println!("Original: {} bytes", test_data.len());
        println!("Encoded: {} bytes", encoded_str.len());
        println!(
            "Expansion ratio: {:.2}x",
            encoded_str.len() as f64 / test_data.len() as f64
        );

        // Should be much more efficient than the old system!
        // Our current implementation is around 11x expansion, which is still much better than 1000%+
        assert!(encoded_str.len() < test_data.len() * 20); // Less than 20x expansion

        let decoded = cipher.decode_data(&encoded_str).unwrap();
        assert_eq!(test_data.to_vec(), decoded);
    }

    // COMPREHENSIVE TESTS FOR EFFICIENT CIPHER

    #[test]
    fn test_all_emotional_contexts() {
        let contexts = [
            EmotionalContext::Content,
            EmotionalContext::Excited,
            EmotionalContext::Calm,
            EmotionalContext::Playful,
            EmotionalContext::Greeting,
            EmotionalContext::Request,
            EmotionalContext::Attention,
            EmotionalContext::Warning,
            EmotionalContext::Alert,
            EmotionalContext::Confused,
            EmotionalContext::Frustrated,
            EmotionalContext::Surprised,
            EmotionalContext::Curious,
        ];

        let test_data = b"Test message for all emotional contexts";

        for context in &contexts {
            let cipher = EfficientPetCipher::new_with_context(
                PetDialect::Kitty,
                FileType::Unknown,
                *context,
            );

            let mut encoded = Vec::new();
            cipher.encode_data(test_data, &mut encoded).unwrap();
            let encoded_str = String::from_utf8(encoded).unwrap();

            // Test decoding
            let decoded = cipher.decode_data(&encoded_str).unwrap();
            assert_eq!(decoded, test_data, "Failed for context: {:?}", context);

            println!("Context {:?}: {}", context, encoded_str);
        }
    }

    #[test]
    fn test_all_file_types() {
        let file_types = [
            FileType::Text,
            FileType::Image,
            FileType::Video,
            FileType::Audio,
            FileType::Data,
            FileType::Unknown,
        ];

        let test_data = b"Test message for all file types";

        for file_type in &file_types {
            let cipher = EfficientPetCipher::new_with_context(
                PetDialect::Kitty,
                *file_type,
                EmotionalContext::Calm,
            );

            let mut encoded = Vec::new();
            cipher.encode_data(test_data, &mut encoded).unwrap();
            let encoded_str = String::from_utf8(encoded).unwrap();

            // Test decoding
            let decoded = cipher.decode_data(&encoded_str).unwrap();
            assert_eq!(decoded, test_data, "Failed for file type: {:?}", file_type);

            println!("File type {:?}: {}", file_type, encoded_str);
        }
    }

    #[test]
    fn test_edge_cases_efficient() {
        let cipher = EfficientPetCipher::new(PetDialect::Kitty);

        // Test empty data
        let empty_data = b"";
        let mut encoded = Vec::new();
        cipher.encode_data(empty_data, &mut encoded).unwrap();
        let encoded_str = String::from_utf8(encoded).unwrap();
        let decoded = cipher.decode_data(&encoded_str).unwrap();
        assert_eq!(decoded, empty_data);

        // Test single byte
        let single_byte = b"A";
        let mut encoded = Vec::new();
        cipher.encode_data(single_byte, &mut encoded).unwrap();
        let encoded_str = String::from_utf8(encoded).unwrap();
        let decoded = cipher.decode_data(&encoded_str).unwrap();
        assert_eq!(decoded, single_byte);

        // Test all possible byte values
        for i in 0..=255u8 {
            let test_byte = [i];
            let mut encoded = Vec::new();
            cipher.encode_data(&test_byte, &mut encoded).unwrap();
            let encoded_str = String::from_utf8(encoded).unwrap();
            let decoded = cipher.decode_data(&encoded_str).unwrap();
            assert_eq!(decoded, test_byte, "Failed for byte value: {}", i);
        }
    }

    #[test]
    fn test_large_data_efficient() {
        let cipher = EfficientPetCipher::new(PetDialect::Kitty);

        // Test 1KB of data
        let large_data = b"Hello World! ".repeat(100);
        let mut encoded = Vec::new();
        cipher.encode_data(&large_data, &mut encoded).unwrap();
        let encoded_str = String::from_utf8(encoded).unwrap();
        let decoded = cipher.decode_data(&encoded_str).unwrap();
        assert_eq!(decoded, large_data);

        // Test 10KB of data
        let very_large_data = b"Test data for large message testing. ".repeat(300);
        let mut encoded = Vec::new();
        cipher.encode_data(&very_large_data, &mut encoded).unwrap();
        let encoded_str = String::from_utf8(encoded).unwrap();
        let decoded = cipher.decode_data(&encoded_str).unwrap();
        assert_eq!(decoded, very_large_data);
    }

    #[test]
    fn test_unicode_data_efficient() {
        let cipher = EfficientPetCipher::new(PetDialect::Kitty);

        // Test UTF-8 data
        let unicode_data = "Hello 世界! 🌍 Nyaa~ >w<".as_bytes();
        let mut encoded = Vec::new();
        cipher.encode_data(unicode_data, &mut encoded).unwrap();
        let encoded_str = String::from_utf8(encoded).unwrap();
        let decoded = cipher.decode_data(&encoded_str).unwrap();
        assert_eq!(decoded, unicode_data);

        // Test emoji and special characters
        let emoji_data = "🐱🐶💕✨🎉🚀".as_bytes();
        let mut encoded = Vec::new();
        cipher.encode_data(emoji_data, &mut encoded).unwrap();
        let encoded_str = String::from_utf8(encoded).unwrap();
        let decoded = cipher.decode_data(&encoded_str).unwrap();
        assert_eq!(decoded, emoji_data);
    }

    #[test]
    fn test_compression_ratio_efficient() {
        let cipher = EfficientPetCipher::new(PetDialect::Kitty);

        // Test with different types of data
        let test_cases = [
            ("Repeated text", b"Hello ".repeat(50)),
            (
                "Random data",
                b"\x01\x23\x45\x67\x89\xAB\xCD\xEF".repeat(10),
            ),
            (
                "Mixed data",
                b"Hello World! 1234567890 !@#$%^&*()".repeat(20),
            ),
        ];

        for (name, data) in &test_cases {
            let mut encoded = Vec::new();
            cipher.encode_data(data, &mut encoded).unwrap();
            let encoded_str = String::from_utf8(encoded).unwrap();

            let expansion_ratio = encoded_str.len() as f64 / data.len() as f64;
            println!(
                "{}: {} bytes -> {} bytes ({}x expansion)",
                name,
                data.len(),
                encoded_str.len(),
                expansion_ratio
            );

            // Should be reasonable expansion (not 1000%+ like the old system)
            assert!(
                expansion_ratio < 20.0,
                "Expansion ratio too high for {}: {}x",
                name,
                expansion_ratio
            );

            // Test decoding
            let decoded = cipher.decode_data(&encoded_str).unwrap();
            assert_eq!(decoded, *data);
        }
    }

    #[test]
    fn test_nibble_encoding_accuracy() {
        let cipher = EfficientPetCipher::new(PetDialect::Kitty);

        // Test all possible 4-bit nibbles
        for nibble in 0..=15u8 {
            let pattern = cipher.get_basic_sound_for_nibble(nibble);
            let decoded_nibble = cipher.decode_nibble(&pattern).unwrap();
            assert_eq!(decoded_nibble, nibble, "Failed for nibble: {}", nibble);
        }
    }

    #[test]
    fn test_sound_type_mapping() {
        let cipher = EfficientPetCipher::new(PetDialect::Kitty);

        // Test that sound types are properly mapped
        assert!(!cipher.sound_map.is_empty());
        assert!(!cipher.reverse_map.is_empty());

        // Test that we can find sounds for different types
        let sound_types = [
            SoundType::MessageStart,
            SoundType::MessageEnd,
            SoundType::WordBoundary,
            SoundType::ErrorMarker,
            SoundType::HappySound,
            SoundType::NeutralSound,
            SoundType::ExcitedSound,
            SoundType::UpsetSound,
            SoundType::QuestionSound,
            SoundType::ContentSound,
            SoundType::AlertSound,
            SoundType::PlayfulSound,
        ];

        for sound_type in &sound_types {
            let sounds = cipher
                .sound_map
                .iter()
                .filter(|m| {
                    std::mem::discriminant(&m.sound_type) == std::mem::discriminant(sound_type)
                })
                .collect::<Vec<_>>();
            assert!(
                !sounds.is_empty(),
                "No sounds found for type: {:?}",
                sound_type
            );
        }
    }

    #[test]
    fn test_contextual_word_detection() {
        let cipher = EfficientPetCipher::new(PetDialect::Kitty);

        // Test contextual word detection
        assert!(cipher.is_contextual_word("Oh"));
        assert!(cipher.is_contextual_word("Look"));
        assert!(cipher.is_contextual_word("little"));
        assert!(cipher.is_contextual_word("happy"));

        // Test words that are NOT contextual (to avoid conflicts with data)
        assert!(!cipher.is_contextual_word("my!")); // Changed from assert! to assert!
        assert!(!cipher.is_contextual_word("a"));
        assert!(!cipher.is_contextual_word("is"));
        assert!(!cipher.is_contextual_word("take"));
        assert!(!cipher.is_contextual_word("time"));

        // Test non-contextual words (pet sounds)
        assert!(!cipher.is_contextual_word("purr"));
        assert!(!cipher.is_contextual_word("meow"));
        assert!(!cipher.is_contextual_word("mew"));
        assert!(!cipher.is_contextual_word("chirp"));
    }

    #[test]
    fn test_marker_detection() {
        let cipher = EfficientPetCipher::new(PetDialect::Kitty);

        // Test marker detection
        assert!(cipher.is_marker("meow meow", SoundType::MessageStart));
        assert!(cipher.is_marker("trill trill", SoundType::MessageEnd));
        assert!(cipher.is_marker("purr purr", SoundType::WordBoundary));
        assert!(cipher.is_marker("hiss", SoundType::ErrorMarker));
        assert!(cipher.is_marker("mrow?", SoundType::QuestionSound));

        // Test non-markers
        assert!(!cipher.is_marker("purr", SoundType::MessageStart));
        assert!(!cipher.is_marker("meow", SoundType::MessageEnd));
    }

    #[test]
    fn test_performance_benchmark_efficient() {
        let cipher = EfficientPetCipher::new(PetDialect::Kitty);
        let test_data =
            b"Performance test data for benchmarking the efficient cipher system.".repeat(100);

        let start = std::time::Instant::now();

        // Encode
        let mut encoded = Vec::new();
        cipher.encode_data(&test_data, &mut encoded).unwrap();
        let encoded_str = String::from_utf8(encoded).unwrap();

        let encode_time = start.elapsed();

        // Decode
        let start = std::time::Instant::now();
        let decoded = cipher.decode_data(&encoded_str).unwrap();
        let decode_time = start.elapsed();

        println!("Efficient cipher performance test:");
        println!("  Input size: {} bytes", test_data.len());
        println!("  Output size: {} bytes", encoded_str.len());
        println!(
            "  Expansion ratio: {:.2}x",
            encoded_str.len() as f64 / test_data.len() as f64
        );
        println!("  Encode time: {:?}", encode_time);
        println!("  Decode time: {:?}", decode_time);
        println!(
            "  Encode speed: {:.2} MB/s",
            test_data.len() as f64 / encode_time.as_secs_f64() / 1_000_000.0
        );
        println!(
            "  Decode speed: {:.2} MB/s",
            test_data.len() as f64 / decode_time.as_secs_f64() / 1_000_000.0
        );

        assert_eq!(decoded, test_data);

        // Performance assertions
        assert!(
            encode_time.as_secs_f64() < 1.0,
            "Encoding too slow: {:?}",
            encode_time
        );
        assert!(
            decode_time.as_secs_f64() < 1.0,
            "Decoding too slow: {:?}",
            decode_time
        );
    }

    #[test]
    fn test_mood_and_file_type_changes() {
        let mut cipher = EfficientPetCipher::new(PetDialect::Kitty);
        let test_data = b"Test message for mood and file type changes";

        // Test mood changes
        cipher.set_mood(EmotionalContext::Excited);
        let mut encoded1 = Vec::new();
        cipher.encode_data(test_data, &mut encoded1).unwrap();
        let encoded_str1 = String::from_utf8(encoded1).unwrap();

        cipher.set_mood(EmotionalContext::Calm);
        let mut encoded2 = Vec::new();
        cipher.encode_data(test_data, &mut encoded2).unwrap();
        let encoded_str2 = String::from_utf8(encoded2).unwrap();

        // Should produce different encodings
        assert_ne!(encoded_str1, encoded_str2);

        // Test file type changes
        cipher.set_file_type(FileType::Image);
        let mut encoded3 = Vec::new();
        cipher.encode_data(test_data, &mut encoded3).unwrap();
        let encoded_str3 = String::from_utf8(encoded3).unwrap();

        cipher.set_file_type(FileType::Text);
        let mut encoded4 = Vec::new();
        cipher.encode_data(test_data, &mut encoded4).unwrap();
        let encoded_str4 = String::from_utf8(encoded4).unwrap();

        // Should produce different encodings
        assert_ne!(encoded_str3, encoded_str4);

        // All should decode correctly
        let decoded1 = cipher.decode_data(&encoded_str1).unwrap();
        let decoded2 = cipher.decode_data(&encoded_str2).unwrap();
        let decoded3 = cipher.decode_data(&encoded_str3).unwrap();
        let decoded4 = cipher.decode_data(&encoded_str4).unwrap();

        assert_eq!(decoded1, test_data);
        assert_eq!(decoded2, test_data);
        assert_eq!(decoded3, test_data);
        assert_eq!(decoded4, test_data);
    }
}
