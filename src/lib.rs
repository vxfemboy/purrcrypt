// src/lib.rs
pub mod cipher;
pub mod config;
pub mod crypto;
pub mod debug;
pub mod keys;
pub mod keystore;

// Re-export our new fluffy features! Nyaa~ >w<
pub use cipher::efficient::{
    EfficientPetCipher, EmotionalContext, FileType, PetDialect, SoundType,
};
pub use cipher::steganographic_rp::{
    ActionType, EmotionalState, PetPersonality, SteganographicRPCipher,
};
pub use crypto::efficient_compression::{CompressionError, SmartCompressor, StreamingCompressor};
pub use crypto::post_quantum::{HybridKeyPair, PostQuantumError, SecureMessage};
