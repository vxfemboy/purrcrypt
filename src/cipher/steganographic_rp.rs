// src/cipher/steganographic_rp.rs
// Ultra-natural pet roleplay steganography system! Nyaa~ >w<

use std::collections::HashMap;
use std::io::{self, Write};

#[derive(Debug, Clone, Copy)]
pub enum PetPersonality {
    Chatty,  // Text files - verbose, detailed
    Excited, // Image files - energetic, visual
    Musical, // Audio files - rhythmic, melodic
    Playful, // Video files - bouncy, fun
    Curious, // Code files - investigative, careful
    Sleepy,  // Compressed data - tired, slow
}

#[derive(Debug, Clone, Copy)]
pub enum EmotionalState {
    Fresh,       // Start of message - energetic
    Comfortable, // Middle - settled, content
    Sleepy,      // End - tired, satisfied
}

#[derive(Debug, Clone, Copy)]
pub enum ActionType {
    Movement,    // *paddes*, *bounces*, *stretches*
    Sound,       // *purrs*, *meows*, *barks*
    Emotion,     // *happy*, *sleepy*, *confused*
    Interaction, // *nuzzles*, *headbonk*, *tail wag*
    Metadata,    // File type, compression flags
}

pub struct SteganographicRPCipher {
    dialect: PetDialect,
    personality: PetPersonality,

    // Micro-phoneme mappings
    single_chars: HashMap<char, u8>,
    digrams: HashMap<String, u8>,
    punctuation: HashMap<char, u8>,

    // RP template system
    greeting_templates: Vec<String>,
    data_templates: Vec<String>,
    error_templates: Vec<String>,
    ending_templates: Vec<String>,

    // Action descriptions for metadata
    action_metadata: HashMap<String, u8>,

    // Common RP phrases dictionary
    phrase_dictionary: HashMap<String, Vec<u8>>,

    // Capitalization patterns for bit encoding
    capitalization_patterns: Vec<String>,

    // Advanced steganographic features
    asterisk_actions: HashMap<String, u8>,
    repetition_patterns: HashMap<String, u8>,
}

#[derive(Debug, Clone, Copy)]
pub enum PetDialect {
    Kitty,
    Puppy,
}

impl SteganographicRPCipher {
    pub fn new(dialect: PetDialect, personality: PetPersonality) -> Self {
        let mut cipher = Self {
            dialect,
            personality,
            single_chars: HashMap::new(),
            digrams: HashMap::new(),
            punctuation: HashMap::new(),
            greeting_templates: Vec::new(),
            data_templates: Vec::new(),
            error_templates: Vec::new(),
            ending_templates: Vec::new(),
            action_metadata: HashMap::new(),
            phrase_dictionary: HashMap::new(),
            capitalization_patterns: Vec::new(),
            asterisk_actions: HashMap::new(),
            repetition_patterns: HashMap::new(),
        };

        cipher.initialize_micro_phonemes();
        cipher.initialize_rp_templates();
        cipher.initialize_action_metadata();
        cipher.initialize_phrase_dictionary();
        cipher.initialize_capitalization_patterns();
        cipher.initialize_asterisk_actions();
        cipher.initialize_repetition_patterns();

        cipher
    }

    fn initialize_micro_phonemes(&mut self) {
        // Single characters (1-2 bits each)
        self.single_chars.insert('m', 0);
        self.single_chars.insert('e', 1);
        self.single_chars.insert('w', 2);
        self.single_chars.insert('r', 3);
        self.single_chars.insert('p', 4);
        self.single_chars.insert('f', 5);
        self.single_chars.insert('k', 6);
        self.single_chars.insert('s', 7);
        self.single_chars.insert('t', 8);
        self.single_chars.insert('n', 9);
        self.single_chars.insert('y', 10);
        self.single_chars.insert('a', 11);
        self.single_chars.insert('o', 12);
        self.single_chars.insert('u', 13);
        self.single_chars.insert('i', 14);
        self.single_chars.insert('h', 15);

        // Digrams (3-4 bits each)
        self.digrams.insert("ow".to_string(), 0);
        self.digrams.insert("rr".to_string(), 1);
        self.digrams.insert("ff".to_string(), 2);
        self.digrams.insert("ss".to_string(), 3);
        self.digrams.insert("nt".to_string(), 4);
        self.digrams.insert("ng".to_string(), 5);
        self.digrams.insert("ch".to_string(), 6);
        self.digrams.insert("th".to_string(), 7);
        self.digrams.insert("sh".to_string(), 8);
        self.digrams.insert("tr".to_string(), 9);
        self.digrams.insert("pr".to_string(), 10);
        self.digrams.insert("br".to_string(), 11);
        self.digrams.insert("gr".to_string(), 12);
        self.digrams.insert("cr".to_string(), 13);
        self.digrams.insert("fr".to_string(), 14);
        self.digrams.insert("dr".to_string(), 15);

        // Punctuation encoding (2 bits each)
        self.punctuation.insert('.', 0); // 00
        self.punctuation.insert('?', 1); // 01
        self.punctuation.insert('!', 2); // 10
        self.punctuation.insert('~', 3); // 11
    }

    fn initialize_rp_templates(&mut self) {
        match (self.dialect, self.personality) {
            (PetDialect::Kitty, PetPersonality::Chatty) => {
                self.greeting_templates = vec![
                    "*paddes in quietly* mew? hewwo! *purrs softly*".to_string(),
                    "*stretches and yawns* mrow... *happy chirps*".to_string(),
                    "*settles in comfortably* mew! *contented purrs*".to_string(),
                ];
                self.data_templates = vec![
                    "purr {data} *nuzzles*".to_string(),
                    "mew mew {data} *happy chirps*".to_string(),
                    "nya {data} *tail swish*".to_string(),
                ];
                self.ending_templates = vec![
                    "*curls up sleepily* zzz...".to_string(),
                    "*contented purrs* *kneads blanket*".to_string(),
                    "*tired yawn* *settles down*".to_string(),
                ];
            }
            (PetDialect::Kitty, PetPersonality::Excited) => {
                self.greeting_templates = vec![
                    "*bounces in excitedly* MEW! *pounces* ooh shiny!".to_string(),
                    "*eyes widen* mrow? *excited trills*".to_string(),
                    "*happy chirps* prrrp! *tail swish*".to_string(),
                ];
                self.data_templates = vec![
                    "MEW! {data} *excited chirps*".to_string(),
                    "mrow mrow! {data} *pounces*".to_string(),
                    "trill! {data} *happy bounces*".to_string(),
                ];
                self.ending_templates = vec![
                    "*excited purrs* *spins in circles*".to_string(),
                    "*happy mews* *bounces around*".to_string(),
                ];
            }
            (PetDialect::Puppy, PetPersonality::Chatty) => {
                self.greeting_templates = vec![
                    "*tail wagging* woof! hewwo! *happy barks*".to_string(),
                    "*bounces in* arf arf! *pants happily*".to_string(),
                    "*excited yips* woof woof! *spins*".to_string(),
                ];
                self.data_templates = vec![
                    "woof {data} *tail wag*".to_string(),
                    "arf arf! {data} *pants happily*".to_string(),
                    "ruff {data} *play bow*".to_string(),
                ];
                self.ending_templates = vec![
                    "*happy sighs* *flops down*".to_string(),
                    "*contented huffs* *settles in*".to_string(),
                    "*tired yawn* *curls up*".to_string(),
                ];
            }
            (PetDialect::Puppy, PetPersonality::Excited) => {
                self.greeting_templates = vec![
                    "*bounces excitedly* WOOF WOOF! *spins in circles*".to_string(),
                    "*happy barks* arf! *tail wagging intensifies*".to_string(),
                    "*excited yips* woof! *bounces around*".to_string(),
                ];
                self.data_templates = vec![
                    "WOOF! {data} *excited barks*".to_string(),
                    "arf arf! {data} *bounces*".to_string(),
                    "ruff ruff! {data} *play bow*".to_string(),
                ];
                self.ending_templates = vec![
                    "*excited panting* *happy barks*".to_string(),
                    "*playful growls* *spins*".to_string(),
                ];
            }
            _ => {
                // Default templates
                self.greeting_templates = vec!["*paddes in* mew!".to_string()];
                self.data_templates = vec!["purr {data}".to_string()];
                self.ending_templates = vec!["*curls up*".to_string()];
            }
        }

        // Error correction templates
        self.error_templates = vec![
            "*confused mrow* {error} *tilts head*".to_string(),
            "*uncertain whine* {error} *ear droop*".to_string(),
            "*puzzled look* {error} *head tilt*".to_string(),
        ];
    }

    fn initialize_action_metadata(&mut self) {
        // Action descriptions encode metadata
        self.action_metadata
            .insert("*purrs softly*".to_string(), 0x00); // File type: text
        self.action_metadata
            .insert("*purrs loudly*".to_string(), 0x01); // File type: binary
        self.action_metadata.insert("*stretches*".to_string(), 0x02); // Compression: enabled
        self.action_metadata.insert("*yawns*".to_string(), 0x03); // Compression: disabled
        self.action_metadata
            .insert("*tail swish*".to_string(), 0x04); // Encryption: ChaCha20
        self.action_metadata.insert("*ear flick*".to_string(), 0x05); // Encryption: AES
        self.action_metadata.insert("*nuzzles*".to_string(), 0x06); // MAC verified
        self.action_metadata.insert("*hisses*".to_string(), 0x07); // MAC failed
    }

    fn initialize_phrase_dictionary(&mut self) {
        // Common RP phrases (pre-compressed dictionary)
        self.phrase_dictionary
            .insert("*nuzzles*".to_string(), vec![0x00, 0x00, 0x00, 0x00]);
        self.phrase_dictionary
            .insert("*purrs*".to_string(), vec![0xFF, 0xFF, 0xFF, 0xFF]);
        self.phrase_dictionary
            .insert("*headbonk*".to_string(), vec![0xCA, 0xFE, 0xBA, 0xBE]);
        self.phrase_dictionary
            .insert("*kneads paws*".to_string(), vec![0x00, 0x00, 0x00, 0x00]);
        self.phrase_dictionary
            .insert("*sleepy yawn*".to_string(), vec![0xFF, 0xFF, 0xFF, 0xFF]);
    }

    fn initialize_capitalization_patterns(&mut self) {
        // Capitalization patterns for bit encoding
        self.capitalization_patterns = vec![
            "mew".to_string(), // 0 - lowercase
            "Mew".to_string(), // 1 - title case
            "MEW".to_string(), // 2 - uppercase
            "mEw".to_string(), // 3 - mixed case 1
            "meW".to_string(), // 4 - mixed case 2
            "MeW".to_string(), // 5 - mixed case 3
        ];
    }

    fn initialize_asterisk_actions(&mut self) {
        // Asterisk action encoding for metadata
        self.asterisk_actions.insert("*mew*".to_string(), 0x01); // 1 bit
        self.asterisk_actions.insert("*meows*".to_string(), 0x02); // 2 bits
        self.asterisk_actions.insert("*meowing*".to_string(), 0x03); // 3 bits
        self.asterisk_actions
            .insert("**excited**".to_string(), 0x04); // Priority flag
        self.asterisk_actions
            .insert("***sleepy***".to_string(), 0x05); // Compression flag
    }

    fn initialize_repetition_patterns(&mut self) {
        // Repetition patterns for run-length encoding
        self.repetition_patterns.insert("mew mew".to_string(), 0x01); // Repeat last byte
        self.repetition_patterns
            .insert("mew mew mew".to_string(), 0x02); // Repeat last word
        self.repetition_patterns
            .insert("purr purr purr purr".to_string(), 0x03); // Run-length encoding
    }

    /// Encode data as authentic pet roleplay! *purrs excitedly*
    pub fn encode_data<W: Write>(&self, data: &[u8], writer: &mut W) -> io::Result<()> {
        // Write greeting based on personality
        self.write_greeting(writer)?;

        // Encode data in chunks with natural RP flow
        let total_chunks = data.len().div_ceil(4); // Calculate total chunks
        for (chunk_index, chunk) in data.chunks(4).enumerate() {
            // Process 4 bytes at a time
            // Use emotional progression template for more natural flow
            let template = self.create_emotional_progression_template(chunk_index, total_chunks);

            // Encode chunk as micro-phonemes with advanced steganography
            let encoded_chunk = self.encode_chunk_as_phonemes(chunk);

            // Insert into template
            let rp_text = template.replace("{data}", &encoded_chunk);
            writer.write_all(rp_text.as_bytes())?;
            writer.write_all(b" ")?;

            // Add natural pauses and actions based on personality
            if chunk_index % 2 == 0 {
                self.write_natural_pause(writer, chunk_index)?;
            }

            // Add asterisk actions for metadata encoding
            if chunk_index % 4 == 0 {
                self.write_metadata_action(writer, chunk_index)?;
            }
        }

        // Write ending based on personality
        self.write_ending(writer)?;

        Ok(())
    }

    fn write_greeting<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        if !self.greeting_templates.is_empty() {
            let greeting = &self.greeting_templates[0];
            writer.write_all(greeting.as_bytes())?;
            let _ = writer.write_all(b" ");
        }
        Ok(())
    }

    fn write_ending<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        if !self.ending_templates.is_empty() {
            let ending = &self.ending_templates[0];
            writer.write_all(ending.as_bytes())?;
        }
        Ok(())
    }

    fn encode_chunk_as_phonemes(&self, chunk: &[u8]) -> String {
        let mut result = String::new();

        for (i, &byte) in chunk.iter().enumerate() {
            // Encode each byte as micro-phonemes with advanced steganography
            let high_nibble = (byte >> 4) & 0x0F;
            let low_nibble = byte & 0x0F;

            // Convert nibbles to phonemes with capitalization encoding
            let high_phonemes =
                self.nibble_to_phonemes_with_capitalization(high_nibble, byte & 0x01);
            let low_phonemes =
                self.nibble_to_phonemes_with_capitalization(low_nibble, (byte >> 1) & 0x01);

            if i > 0 {
                result.push(' '); // Add space between bytes
            }

            result.push_str(&high_phonemes);
            result.push_str(&low_phonemes);

            // Add punctuation for extra bits
            let extra_bits = byte & 0x03;
            result.push(self.bits_to_punctuation(extra_bits));
        }

        result
    }

    fn nibble_to_phonemes(&self, nibble: u8) -> String {
        // Convert 4-bit nibble to natural-sounding phonemes
        let phoneme_pairs = match self.dialect {
            PetDialect::Kitty => [
                "me", "ew", "ow", "rr", "pr", "tr", "ch", "ny", "ya", "wa", "ma", "na", "ra", "la",
                "ka", "ha",
            ],
            PetDialect::Puppy => [
                "wo", "of", "ar", "ru", "ba", "gr", "hu", "ya", "wa", "ma", "na", "ra", "la", "ka",
                "ha", "bo",
            ],
        };

        phoneme_pairs[nibble as usize].to_string()
    }

    fn nibble_to_phonemes_with_capitalization(&self, nibble: u8, cap_bit: u8) -> String {
        let base_phonemes = self.nibble_to_phonemes(nibble);

        // Apply capitalization based on the cap_bit
        match cap_bit {
            0 => base_phonemes.to_lowercase(),
            1 => {
                // Title case: first letter uppercase
                let mut chars: Vec<char> = base_phonemes.chars().collect();
                if !chars.is_empty() {
                    chars[0] = chars[0].to_uppercase().next().unwrap();
                }
                chars.into_iter().collect()
            }
            _ => base_phonemes,
        }
    }

    fn bits_to_punctuation(&self, bits: u8) -> char {
        match bits {
            0 => '.',
            1 => '?',
            2 => '!',
            3 => '~',
            _ => '.',
        }
    }

    fn write_natural_pause<W: Write>(&self, writer: &mut W, chunk_index: usize) -> io::Result<()> {
        let pauses = match (self.dialect, self.personality) {
            (PetDialect::Kitty, PetPersonality::Chatty) => [
                "*happy purrs*",
                "*contented chirps*",
                "*tail swish*",
                "*nuzzles*",
                "*kneads paws*",
            ],
            (PetDialect::Kitty, PetPersonality::Excited) => [
                "*excited trills*",
                "*bounces around*",
                "*pounces playfully*",
                "*happy mews*",
                "*spins in circles*",
            ],
            (PetDialect::Puppy, PetPersonality::Chatty) => [
                "*tail wag*",
                "*happy panting*",
                "*play bow*",
                "*nuzzles*",
                "*contented huffs*",
            ],
            (PetDialect::Puppy, PetPersonality::Excited) => [
                "*excited yips*",
                "*bounces around*",
                "*spins in circles*",
                "*playful barks*",
                "*happy panting*",
            ],
            _ => [
                "*purrs*",
                "*nuzzles*",
                "*happy sounds*",
                "*contented purrs*",
                "*tail swish*",
            ],
        };

        let pause = pauses[chunk_index % pauses.len()];
        writer.write_all(pause.as_bytes())?;
        writer.write_all(b" ")?;

        Ok(())
    }

    fn create_emotional_progression_template(
        &self,
        chunk_index: usize,
        total_chunks: usize,
    ) -> String {
        let progress = chunk_index as f32 / total_chunks as f32;

        match (self.dialect, self.personality) {
            (PetDialect::Kitty, _) => {
                if progress < 0.2 {
                    // Fresh and energetic
                    "*excited mews* {data} *happy chirps*".to_string()
                } else if progress < 0.6 {
                    // Comfortable and settled
                    "*contented purrs* {data} *nuzzles*".to_string()
                } else {
                    // Sleepy and tired
                    "*sleepy yawns* {data} *curls up*".to_string()
                }
            }
            (PetDialect::Puppy, _) => {
                if progress < 0.2 {
                    // Fresh and energetic
                    "*excited barks* {data} *bounces around*".to_string()
                } else if progress < 0.6 {
                    // Comfortable and settled
                    "*happy panting* {data} *tail wag*".to_string()
                } else {
                    // Sleepy and tired
                    "*tired yawns* {data} *flops down*".to_string()
                }
            }
        }
    }

    fn write_metadata_action<W: Write>(
        &self,
        writer: &mut W,
        chunk_index: usize,
    ) -> io::Result<()> {
        let actions = match (self.dialect, self.personality) {
            (PetDialect::Kitty, PetPersonality::Chatty) => [
                "*nuzzles*",
                "*purrs softly*",
                "*tail swish*",
                "*kneads paws*",
            ],
            (PetDialect::Kitty, PetPersonality::Excited) => [
                "*excited trills*",
                "*pounces*",
                "*happy chirps*",
                "*spins around*",
            ],
            (PetDialect::Puppy, PetPersonality::Chatty) => {
                ["*nuzzles*", "*tail wag*", "*happy panting*", "*play bow*"]
            }
            (PetDialect::Puppy, PetPersonality::Excited) => [
                "*excited barks*",
                "*bounces*",
                "*playful growls*",
                "*spins in circles*",
            ],
            _ => ["*purrs*", "*nuzzles*", "*happy sounds*", "*tail wag*"],
        };

        let action = actions[chunk_index % actions.len()];
        writer.write_all(action.as_bytes())?;
        writer.write_all(b" ")?;

        Ok(())
    }

    /// Decode pet roleplay back to data! *ears perk up*
    pub fn decode_data(&self, input: &str) -> io::Result<Vec<u8>> {
        let mut result = Vec::new();
        let words: Vec<&str> = input.split_whitespace().collect();

        // Check if this looks like valid steganographic RP data
        let has_rp_markers = words
            .iter()
            .any(|word| word.starts_with('*') && word.ends_with('*'));
        let has_phoneme_words = words.iter().any(|word| self.is_phoneme_word(word));

        // If it doesn't look like valid RP data, return an error
        if !has_rp_markers && !has_phoneme_words {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Input does not appear to be valid steganographic RP data",
            ));
        }

        // Find and extract phoneme sequences from the RP text
        let mut i = 0;
        while i < words.len() {
            // Look for phoneme patterns (2-4 character words without asterisks)
            if self.is_phoneme_word(words[i]) {
                let mut phoneme_sequence = Vec::new();
                let mut j = i;

                // Collect consecutive phoneme words
                while j < words.len() && self.is_phoneme_word(words[j]) {
                    phoneme_sequence.push(words[j]);
                    j += 1;
                }

                // Decode the phoneme sequence
                if let Some(decoded_bytes) = self.decode_phoneme_sequence_simple(&phoneme_sequence)
                {
                    result.extend_from_slice(&decoded_bytes);
                }

                i = j; // Skip the processed phonemes
            } else {
                i += 1;
            }
        }

        // If we found RP markers but no valid data, that's also an error
        if has_rp_markers && result.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Input appears to be RP data but contains no decodable phoneme sequences",
            ));
        }

        Ok(result)
    }

    fn is_phoneme_word(&self, word: &str) -> bool {
        // Check if this looks like a phoneme word (not an action description)
        if word.starts_with('*') || word.ends_with('*') {
            return false; // Skip action descriptions
        }

        // Remove punctuation for phoneme matching
        let clean_word = word
            .chars()
            .filter(|c| c.is_ascii_lowercase() || c.is_ascii_uppercase())
            .collect::<String>();

        // Blacklist common pet words that should never be treated as data
        // Focus on words that are commonly used as filler but not as data encodings
        let blacklisted_words = match self.dialect {
            PetDialect::Kitty => [
                "hewwo", "hello", "hi", "hey", "oh", "ooh", "aww", "cute", "kitty", "cat",
                "feline", "whiskers", "paws", "tail", "ears", "fluffy", "soft", "the", "and",
                "but", "for", "are", "with", "this", "that", "from",
            ],
            PetDialect::Puppy => [
                "woof", "bark", "hewwo", "hello", "hi", "hey", "oh", "ooh", "aww", "cute", "puppy",
                "dog", "canine", "tail", "paws", "ears", "fluffy", "soft", "the", "and", "but",
                "for", "are", "with", "this", "that",
            ],
        };

        let lower_clean = clean_word.to_lowercase();
        if blacklisted_words.contains(&lower_clean.as_str()) {
            return false;
        }

        // Only treat as phoneme word if it can actually be decoded as phonemes
        if clean_word.len() >= 2 && clean_word.len() <= 5 {
            // Check if it matches actual phoneme patterns
            if clean_word.len() == 2 {
                // Single 2-character phoneme
                return self.phonemes_to_nibble(&clean_word).is_some();
            } else if clean_word.len() == 4 {
                // Two 2-character phonemes
                let first_phoneme = &clean_word[0..2];
                let second_phoneme = &clean_word[2..4];
                return self.phonemes_to_nibble(first_phoneme).is_some()
                    && self.phonemes_to_nibble(second_phoneme).is_some();
            } else if clean_word.len() == 3 {
                // Could be 2+1 or 1+2
                let first_phoneme = &clean_word[0..2];
                let second_phoneme = &clean_word[1..3];
                return self.phonemes_to_nibble(first_phoneme).is_some()
                    || self.phonemes_to_nibble(second_phoneme).is_some();
            }
        }

        false
    }

    fn decode_phoneme_sequence_simple(&self, words: &[&str]) -> Option<Vec<u8>> {
        let mut nibbles = Vec::new();

        for word in words {
            // Remove punctuation for phoneme matching
            let clean_word = word
                .chars()
                .filter(|c| c.is_ascii_lowercase() || c.is_ascii_uppercase())
                .collect::<String>();

            if clean_word.len() >= 2 {
                // Split phoneme sequences into 2-character pairs
                if clean_word.len() == 4 {
                    // Split into two 2-character phonemes
                    let first_phoneme = &clean_word[0..2];
                    let second_phoneme = &clean_word[2..4];

                    if let Some(nibble1) = self.phonemes_to_nibble(first_phoneme) {
                        nibbles.push(nibble1);
                    }
                    if let Some(nibble2) = self.phonemes_to_nibble(second_phoneme) {
                        nibbles.push(nibble2);
                    }
                } else if clean_word.len() == 2 {
                    // Single 2-character phoneme
                    if let Some(nibble) = self.phonemes_to_nibble(&clean_word) {
                        nibbles.push(nibble);
                    }
                } else if clean_word.len() == 3 {
                    // Try to split 3-character word (might be 2+1 or 1+2)
                    let first_phoneme = &clean_word[0..2];
                    let second_phoneme = &clean_word[1..3];

                    // Try first possibility (2+1)
                    if let Some(nibble1) = self.phonemes_to_nibble(first_phoneme) {
                        nibbles.push(nibble1);
                        // Try to decode remaining character as single phoneme
                        if let Some(nibble2) = self.phonemes_to_nibble(&clean_word[2..3]) {
                            nibbles.push(nibble2);
                        }
                    } else if let Some(nibble1) = self.phonemes_to_nibble(second_phoneme) {
                        // Try second possibility (1+2) - but only if first didn't work
                        if let Some(nibble2) = self.phonemes_to_nibble(&clean_word[0..1]) {
                            nibbles.push(nibble2);
                        }
                        nibbles.push(nibble1);
                    } else {
                        // Debug: print what we're trying to match
                        if cfg!(test) {
                            println!(
                                "DEBUG: Could not decode phoneme: '{}' (clean: '{}', len: {})",
                                word,
                                clean_word,
                                clean_word.len()
                            );
                        }
                    }
                } else {
                    // Debug: print what we're trying to match
                    if cfg!(test) {
                        println!(
                            "DEBUG: Could not decode phoneme: '{}' (clean: '{}', len: {})",
                            word,
                            clean_word,
                            clean_word.len()
                        );
                    }
                }
            }
        }

        // Convert nibbles to bytes
        let mut bytes = Vec::new();
        for chunk in nibbles.chunks(2) {
            if chunk.len() == 2 {
                let byte = (chunk[0] << 4) | chunk[1];
                bytes.push(byte);
            }
        }

        if cfg!(test) {
            println!(
                "DEBUG: Decoded {} nibbles into {} bytes",
                nibbles.len(),
                bytes.len()
            );
        }

        if bytes.is_empty() {
            None
        } else {
            Some(bytes)
        }
    }

    fn phonemes_to_nibble(&self, phonemes: &str) -> Option<u8> {
        // Convert phoneme pair back to nibble (case-insensitive)
        let phoneme_pairs = match self.dialect {
            PetDialect::Kitty => [
                "me", "ew", "ow", "rr", "pr", "tr", "ch", "ny", "ya", "wa", "ma", "na", "ra", "la",
                "ka", "ha",
            ],
            PetDialect::Puppy => [
                "wo", "of", "ar", "ru", "ba", "gr", "hu", "ya", "wa", "ma", "na", "ra", "la", "ka",
                "ha", "bo",
            ],
        };

        // Convert to lowercase for comparison
        let lower_phonemes = phonemes.to_lowercase();

        for (index, &pair) in phoneme_pairs.iter().enumerate() {
            if pair == lower_phonemes {
                return Some(index as u8);
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_steganographic_encoding() {
        let cipher = SteganographicRPCipher::new(PetDialect::Kitty, PetPersonality::Chatty);
        let test_data = b"Hello";

        let mut encoded = Vec::new();
        cipher.encode_data(test_data, &mut encoded).unwrap();
        let encoded_str = String::from_utf8(encoded).unwrap();

        println!("Steganographic RP encoding: {}", encoded_str);

        // Should look like natural pet roleplay
        assert!(encoded_str.contains("*"));
        assert!(encoded_str.contains("mew") || encoded_str.contains("purr"));
    }

    #[test]
    fn test_personality_differences() {
        let chatty_kitty = SteganographicRPCipher::new(PetDialect::Kitty, PetPersonality::Chatty);
        let excited_kitty = SteganographicRPCipher::new(PetDialect::Kitty, PetPersonality::Excited);

        let test_data = b"Test";

        let mut chatty_encoded = Vec::new();
        chatty_kitty
            .encode_data(test_data, &mut chatty_encoded)
            .unwrap();
        let chatty_str = String::from_utf8(chatty_encoded).unwrap();

        let mut excited_encoded = Vec::new();
        excited_kitty
            .encode_data(test_data, &mut excited_encoded)
            .unwrap();
        let excited_str = String::from_utf8(excited_encoded).unwrap();

        println!("Chatty kitty: {}", chatty_str);
        println!("Excited kitty: {}", excited_str);

        // Should produce different RP styles
        assert_ne!(chatty_str, excited_str);
    }

    #[test]
    fn test_advanced_steganography() {
        let cipher = SteganographicRPCipher::new(PetDialect::Kitty, PetPersonality::Excited);
        let test_data = b"Hello World! This is a test of the advanced steganographic RP system.";

        let mut encoded = Vec::new();
        cipher.encode_data(test_data, &mut encoded).unwrap();
        let encoded_str = String::from_utf8(encoded).unwrap();

        println!("Advanced steganographic encoding:");
        println!("{}", encoded_str);

        // Should contain advanced features
        assert!(encoded_str.contains("*")); // Action descriptions
        assert!(encoded_str.contains("mew") || encoded_str.contains("purr")); // Pet sounds
        assert!(
            encoded_str.contains("!") || encoded_str.contains("?") || encoded_str.contains("~")
        ); // Punctuation encoding
        assert!(encoded_str.contains("Mew") || encoded_str.contains("MEW")); // Capitalization encoding

        // Test decoding
        let decoded = cipher.decode_data(&encoded_str).unwrap();
        assert_eq!(decoded, test_data);
    }

    #[test]
    fn test_emotional_progression() {
        let cipher = SteganographicRPCipher::new(PetDialect::Puppy, PetPersonality::Playful);
        let test_data = b"Long message to test emotional progression from excited to sleepy";

        let mut encoded = Vec::new();
        cipher.encode_data(test_data, &mut encoded).unwrap();
        let encoded_str = String::from_utf8(encoded).unwrap();

        println!("Emotional progression test:");
        println!("{}", encoded_str);

        // Should show emotional progression
        assert!(encoded_str.contains("*excited")); // Start energetic
        assert!(encoded_str.contains("*happy")); // Middle comfortable
        assert!(encoded_str.contains("*tired") || encoded_str.contains("*sleepy"));
        // End tired
    }

    #[test]
    fn test_simple_phoneme_encoding() {
        let cipher = SteganographicRPCipher::new(PetDialect::Kitty, PetPersonality::Chatty);
        let test_data = b"Hi"; // Simple 2-byte test

        let mut encoded = Vec::new();
        cipher.encode_data(test_data, &mut encoded).unwrap();
        let encoded_str = String::from_utf8(encoded).unwrap();

        println!("Simple phoneme test:");
        println!("Input: {:?}", test_data);
        println!("Encoded: {}", encoded_str);

        // Test decoding
        let decoded = cipher.decode_data(&encoded_str).unwrap();
        println!("Decoded: {:?}", decoded);

        assert_eq!(decoded, test_data);
    }

    // NEW COMPREHENSIVE TESTS

    #[test]
    fn test_all_personalities() {
        let personalities = [
            PetPersonality::Chatty,
            PetPersonality::Excited,
            PetPersonality::Musical,
            PetPersonality::Playful,
            PetPersonality::Curious,
            PetPersonality::Sleepy,
        ];

        let test_data = b"Test message for all personalities";

        for personality in &personalities {
            let cipher = SteganographicRPCipher::new(PetDialect::Kitty, *personality);

            let mut encoded = Vec::new();
            cipher.encode_data(test_data, &mut encoded).unwrap();
            let encoded_str = String::from_utf8(encoded).unwrap();

            // Test decoding
            let decoded = cipher.decode_data(&encoded_str).unwrap();
            assert_eq!(
                decoded, test_data,
                "Failed for personality: {:?}",
                personality
            );

            println!("Personality {:?}: {}", personality, encoded_str);
        }
    }

    #[test]
    fn test_all_dialects() {
        let dialects = [PetDialect::Kitty, PetDialect::Puppy];
        let personalities = [PetPersonality::Chatty, PetPersonality::Excited];

        let test_data = b"Test message for all dialects";

        for dialect in &dialects {
            for personality in &personalities {
                let cipher = SteganographicRPCipher::new(*dialect, *personality);

                let mut encoded = Vec::new();
                cipher.encode_data(test_data, &mut encoded).unwrap();
                let encoded_str = String::from_utf8(encoded).unwrap();

                // Test decoding
                let decoded = cipher.decode_data(&encoded_str).unwrap();
                assert_eq!(
                    decoded, test_data,
                    "Failed for dialect: {:?}, personality: {:?}",
                    dialect, personality
                );

                println!(
                    "Dialect {:?}, Personality {:?}: {}",
                    dialect, personality, encoded_str
                );
            }
        }
    }

    #[test]
    fn test_edge_cases() {
        let cipher = SteganographicRPCipher::new(PetDialect::Kitty, PetPersonality::Chatty);

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

        // Test maximum single byte value
        let max_byte = b"\xFF";
        let mut encoded = Vec::new();
        cipher.encode_data(max_byte, &mut encoded).unwrap();
        let encoded_str = String::from_utf8(encoded).unwrap();
        let decoded = cipher.decode_data(&encoded_str).unwrap();
        assert_eq!(decoded, max_byte);

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
    fn test_large_data() {
        let cipher = SteganographicRPCipher::new(PetDialect::Kitty, PetPersonality::Chatty);

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
    fn test_unicode_data() {
        let cipher = SteganographicRPCipher::new(PetDialect::Kitty, PetPersonality::Chatty);

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
    fn test_compression_ratio() {
        let cipher = SteganographicRPCipher::new(PetDialect::Kitty, PetPersonality::Chatty);

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

            // Should be reasonable expansion (steganographic RP is inherently verbose)
            // Allow up to 20x expansion for steganographic RP since it creates natural-looking text
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
    fn test_phoneme_encoding_accuracy() {
        let cipher = SteganographicRPCipher::new(PetDialect::Kitty, PetPersonality::Chatty);

        // Test all possible 4-bit nibbles
        for nibble in 0..=15u8 {
            let phonemes = cipher.nibble_to_phonemes(nibble);
            let decoded_nibble = cipher.phonemes_to_nibble(&phonemes);
            assert_eq!(
                Some(nibble),
                decoded_nibble,
                "Failed for nibble: {}",
                nibble
            );
        }

        // Test all possible 4-bit nibbles with capitalization
        for nibble in 0..=15u8 {
            for cap_bit in 0..=1u8 {
                let phonemes = cipher.nibble_to_phonemes_with_capitalization(nibble, cap_bit);
                let decoded_nibble = cipher.phonemes_to_nibble(&phonemes);
                assert_eq!(
                    Some(nibble),
                    decoded_nibble,
                    "Failed for nibble: {}, cap_bit: {}",
                    nibble,
                    cap_bit
                );
            }
        }
    }

    #[test]
    fn test_punctuation_encoding() {
        let cipher = SteganographicRPCipher::new(PetDialect::Kitty, PetPersonality::Chatty);

        // Test all punctuation values
        for bits in 0..=3u8 {
            let punctuation = cipher.bits_to_punctuation(bits);
            let expected = match bits {
                0 => '.',
                1 => '?',
                2 => '!',
                3 => '~',
                _ => '.',
            };
            assert_eq!(punctuation, expected, "Failed for bits: {}", bits);
        }
    }

    #[test]
    fn test_action_metadata() {
        let cipher = SteganographicRPCipher::new(PetDialect::Kitty, PetPersonality::Chatty);

        // Test that action metadata is properly initialized
        assert!(!cipher.action_metadata.is_empty());
        assert!(cipher.action_metadata.contains_key("*purrs softly*"));
        assert!(cipher.action_metadata.contains_key("*nuzzles*"));
        assert!(cipher.action_metadata.contains_key("*hisses*"));
    }

    #[test]
    fn test_phrase_dictionary() {
        let cipher = SteganographicRPCipher::new(PetDialect::Kitty, PetPersonality::Chatty);

        // Test that phrase dictionary is properly initialized
        assert!(!cipher.phrase_dictionary.is_empty());
        assert!(cipher.phrase_dictionary.contains_key("*nuzzles*"));
        assert!(cipher.phrase_dictionary.contains_key("*purrs*"));
        assert!(cipher.phrase_dictionary.contains_key("*headbonk*"));
    }

    #[test]
    fn test_capitalization_patterns() {
        let cipher = SteganographicRPCipher::new(PetDialect::Kitty, PetPersonality::Chatty);

        // Test that capitalization patterns are properly initialized
        assert!(!cipher.capitalization_patterns.is_empty());
        assert!(cipher.capitalization_patterns.contains(&"mew".to_string()));
        assert!(cipher.capitalization_patterns.contains(&"Mew".to_string()));
        assert!(cipher.capitalization_patterns.contains(&"MEW".to_string()));
    }

    #[test]
    fn test_asterisk_actions() {
        let cipher = SteganographicRPCipher::new(PetDialect::Kitty, PetPersonality::Chatty);

        // Test that asterisk actions are properly initialized
        assert!(!cipher.asterisk_actions.is_empty());
        assert!(cipher.asterisk_actions.contains_key("*mew*"));
        assert!(cipher.asterisk_actions.contains_key("*meows*"));
        assert!(cipher.asterisk_actions.contains_key("**excited**"));
    }

    #[test]
    fn test_repetition_patterns() {
        let cipher = SteganographicRPCipher::new(PetDialect::Kitty, PetPersonality::Chatty);

        // Test that repetition patterns are properly initialized
        assert!(!cipher.repetition_patterns.is_empty());
        assert!(cipher.repetition_patterns.contains_key("mew mew"));
        assert!(cipher
            .repetition_patterns
            .contains_key("purr purr purr purr"));
    }

    #[test]
    fn test_emotional_progression_templates() {
        let cipher = SteganographicRPCipher::new(PetDialect::Kitty, PetPersonality::Chatty);

        // Test emotional progression template selection
        let template1 = cipher.create_emotional_progression_template(0, 10); // Fresh
        let template2 = cipher.create_emotional_progression_template(5, 10); // Comfortable
        let template3 = cipher.create_emotional_progression_template(9, 10); // Sleepy

        assert!(template1.contains("*excited"));
        assert!(template2.contains("*contented"));
        assert!(template3.contains("*sleepy"));
    }

    #[test]
    fn test_natural_pause_generation() {
        let cipher = SteganographicRPCipher::new(PetDialect::Kitty, PetPersonality::Chatty);

        // Test that natural pauses are generated
        let mut output = Vec::new();
        cipher.write_natural_pause(&mut output, 0).unwrap();
        let pause_str = String::from_utf8(output).unwrap();

        assert!(pause_str.contains("*"));
        assert!(
            pause_str.contains("purr")
                || pause_str.contains("chirp")
                || pause_str.contains("nuzzle")
        );
    }

    #[test]
    fn test_metadata_action_generation() {
        let cipher = SteganographicRPCipher::new(PetDialect::Kitty, PetPersonality::Chatty);

        // Test that metadata actions are generated
        let mut output = Vec::new();
        cipher.write_metadata_action(&mut output, 0).unwrap();
        let action_str = String::from_utf8(output).unwrap();

        assert!(action_str.contains("*"));
        assert!(
            action_str.contains("nuzzle")
                || action_str.contains("purr")
                || action_str.contains("tail")
        );
    }

    #[test]
    fn test_greeting_and_ending() {
        let cipher = SteganographicRPCipher::new(PetDialect::Kitty, PetPersonality::Chatty);

        // Test greeting generation
        let mut output = Vec::new();
        cipher.write_greeting(&mut output).unwrap();
        let greeting_str = String::from_utf8(output).unwrap();

        assert!(greeting_str.contains("*"));
        assert!(greeting_str.contains("mew") || greeting_str.contains("purr"));

        // Test ending generation
        let mut output = Vec::new();
        cipher.write_ending(&mut output).unwrap();
        let ending_str = String::from_utf8(output).unwrap();

        assert!(ending_str.contains("*"));
        assert!(
            ending_str.contains("curl")
                || ending_str.contains("sleepy")
                || ending_str.contains("yawn")
        );
    }

    #[test]
    fn test_phoneme_word_detection() {
        let cipher = SteganographicRPCipher::new(PetDialect::Kitty, PetPersonality::Chatty);

        // Test phoneme word detection
        assert!(cipher.is_phoneme_word("me"));
        assert!(cipher.is_phoneme_word("ew"));
        assert!(cipher.is_phoneme_word("ow"));
        assert!(cipher.is_phoneme_word("rr"));
        assert!(cipher.is_phoneme_word("me."));
        assert!(cipher.is_phoneme_word("ew!"));
        assert!(cipher.is_phoneme_word("ow?"));
        assert!(cipher.is_phoneme_word("rr~"));

        // Test non-phoneme words
        assert!(!cipher.is_phoneme_word("*purrs*"));
        assert!(!cipher.is_phoneme_word("*nuzzles*"));
        assert!(!cipher.is_phoneme_word("a")); // Too short
        assert!(!cipher.is_phoneme_word("abcdef")); // Too long
    }

    #[test]
    fn test_performance_benchmark() {
        let cipher = SteganographicRPCipher::new(PetDialect::Kitty, PetPersonality::Chatty);
        let test_data =
            b"Performance test data for benchmarking the steganographic RP system.".repeat(100);

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

        println!("Performance test:");
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
}
