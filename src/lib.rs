// src/lib.rs
pub mod cipher;
pub mod config;
pub mod crypto;
pub mod debug;
pub mod keys;
pub mod keystore;

// Re-export our new fluffy features! Nyaa~ >w<
pub use crypto::post_quantum::{HybridKeyPair, SecureMessage, PostQuantumError};
pub use crypto::efficient_compression::{SmartCompressor, StreamingCompressor, CompressionError};
pub use cipher::efficient::{EfficientPetCipher, PetDialect, SoundType, EmotionalContext, FileType};
pub use cipher::steganographic_rp::{SteganographicRPCipher, PetPersonality, EmotionalState, ActionType};
