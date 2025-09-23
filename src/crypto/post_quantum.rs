// src/crypto/post_quantum.rs
// Post-quantum cryptography for our fluffy security! Nyaa~ >w<

use k256::{
    ecdh::{diffie_hellman, EphemeralSecret},
    PublicKey as EcdhPublicKey, SecretKey as EcdhSecretKey,
};
use k256::elliptic_curve::rand_core::OsRng;
use pqcrypto_kyber::kyber512::{
    keypair as kyber_keypair, 
    encapsulate as kyber_encapsulate, 
    decapsulate as kyber_decapsulate,
    PublicKey as Kyber512PublicKey, 
    SecretKey as Kyber512SecretKey, 
    Ciphertext as Kyber512Ciphertext,
};
use pqcrypto_traits::kem::{Ciphertext, SharedSecret, PublicKey, SecretKey};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, aead::{Aead, KeyInit}};
use hkdf::Hkdf;
use sha2::Sha256;
use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PostQuantumError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("Key error: {0}")]
    Key(#[from] crate::keys::KeyError),
    #[error("Kyber error: {0}")]
    Kyber(String),
    #[error("ChaCha20-Poly1305 error: {0}")]
    ChaCha20Poly1305(String),
    #[error("Key derivation error: {0}")]
    KeyDerivation(String),
    #[error("MAC verification failed")]
    MacVerificationFailed,
}

/// Hybrid key pair combining ECDH and Kyber for maximum security! *purrs proudly*
#[derive(Clone)]
pub struct HybridKeyPair {
    pub ecdh_public: EcdhPublicKey,
    pub ecdh_secret: EcdhSecretKey,
    pub kyber_public: Kyber512PublicKey,
    pub kyber_secret: Kyber512SecretKey,
}

impl HybridKeyPair {
    /// Generate a new hybrid key pair! *bounces excitedly*
    pub fn new() -> Result<Self, PostQuantumError> {
        // Generate ECDH key pair
        let ecdh_secret = EcdhSecretKey::random(&mut OsRng);
        let scalar = ecdh_secret.to_nonzero_scalar();
        let ecdh_public = EcdhPublicKey::from_secret_scalar(&scalar);
        
        // Generate Kyber key pair
        let (kyber_public, kyber_secret) = kyber_keypair();
        
        Ok(Self {
            ecdh_public,
            ecdh_secret,
            kyber_public,
            kyber_secret,
        })
    }
    
    /// Load key pair from files
    pub fn load(ecdh_pub_path: &str, ecdh_sec_path: &str, kyber_pub_path: &str, kyber_sec_path: &str) -> Result<Self, PostQuantumError> {
        // Load ECDH keys (reuse existing logic)
        let ecdh_public = crate::keys::KeyPair::load_public_key(&std::path::Path::new(ecdh_pub_path))?;
        let ecdh_keypair = crate::keys::KeyPair::load_keypair(
            &std::path::Path::new(ecdh_pub_path),
            &std::path::Path::new(ecdh_sec_path)
        )?;
        
        // Load Kyber keys from serialized files
        let kyber_public_bytes = std::fs::read(kyber_pub_path)
            .map_err(|e| PostQuantumError::Io(e))?;
        let kyber_secret_bytes = std::fs::read(kyber_sec_path)
            .map_err(|e| PostQuantumError::Io(e))?;
        
        // Deserialize Kyber keys
        let kyber_public = Kyber512PublicKey::from_bytes(&kyber_public_bytes)
            .map_err(|e| PostQuantumError::Kyber(format!("Failed to deserialize Kyber public key: {}", e)))?;
        let kyber_secret = Kyber512SecretKey::from_bytes(&kyber_secret_bytes)
            .map_err(|e| PostQuantumError::Kyber(format!("Failed to deserialize Kyber secret key: {}", e)))?;
        
        Ok(Self {
            ecdh_public,
            ecdh_secret: ecdh_keypair.secret_key,
            kyber_public,
            kyber_secret,
        })
    }
    
    /// Save key pair to files
    pub fn save(&self, ecdh_pub_path: &str, ecdh_sec_path: &str, kyber_pub_path: &str, kyber_sec_path: &str) -> Result<(), PostQuantumError> {
        // Save ECDH keys (reuse existing logic)
        let ecdh_keypair = crate::keys::KeyPair {
            public_key: self.ecdh_public,
            secret_key: self.ecdh_secret.clone(),
        };
        ecdh_keypair.save_keys(
            &std::path::Path::new(ecdh_pub_path),
            &std::path::Path::new(ecdh_sec_path)
        )?;
        
        // Save Kyber keys by serializing them to bytes
        let kyber_public_bytes = self.kyber_public.as_bytes();
        let kyber_secret_bytes = self.kyber_secret.as_bytes();
        
        std::fs::write(kyber_pub_path, &kyber_public_bytes)?;
        std::fs::write(kyber_sec_path, &kyber_secret_bytes)?;
        
        Ok(())
    }
}

/// Message structure following the cryptographic doom principle! *swishes tail proudly*
pub struct SecureMessage {
    pub version: u8,
    pub kyber_ciphertext: Kyber512Ciphertext,
    pub ecdh_ephemeral_public: EcdhPublicKey,
    pub encrypted_data: Vec<u8>,
    pub mac: [u8; 16], // Poly1305 MAC
}

impl SecureMessage {
    /// Encrypt data with hybrid post-quantum security! Nyaa~ >w<
    pub fn encrypt(
        data: &[u8],
        recipient_ecdh_public: &EcdhPublicKey,
        recipient_kyber_public: &Kyber512PublicKey,
    ) -> Result<Self, PostQuantumError> {
        // Generate ephemeral ECDH key pair
        let ephemeral_secret = EphemeralSecret::random(&mut OsRng);
        let ephemeral_public = EcdhPublicKey::from(&ephemeral_secret);
        
        // Perform ECDH key exchange
        let ecdh_shared_secret = ephemeral_secret.diffie_hellman(recipient_ecdh_public);
        let ecdh_shared_bytes = ecdh_shared_secret.raw_secret_bytes();
        
        // Perform Kyber key encapsulation
        let (kyber_shared_secret, kyber_ciphertext) = kyber_encapsulate(recipient_kyber_public);
        
        // Combine both shared secrets using HKDF
        let combined_secret = [ecdh_shared_bytes.as_slice(), kyber_shared_secret.as_bytes()].concat();
        let hkdf = Hkdf::<Sha256>::new(Some(b"purrcrypt-v2-hybrid"), &combined_secret);
        
        // Derive encryption and MAC keys
        let mut encryption_key = [0u8; 32];
        let mut mac_key = [0u8; 32];
        
        hkdf.expand(b"chacha20-encryption", &mut encryption_key)
            .map_err(|e| PostQuantumError::KeyDerivation(format!("Failed to derive encryption key: {}", e)))?;
        hkdf.expand(b"poly1305-mac", &mut mac_key)
            .map_err(|e| PostQuantumError::KeyDerivation(format!("Failed to derive MAC key: {}", e)))?;
        
        // Encrypt data with ChaCha20-Poly1305
        let cipher = ChaCha20Poly1305::new(&Key::from_slice(&encryption_key));
        let nonce = Nonce::from_slice(&[0u8; 12]); // Use zero nonce for simplicity
        
        let encrypted_data = cipher.encrypt(nonce, data)
            .map_err(|e| PostQuantumError::ChaCha20Poly1305(format!("Encryption failed: {}", e)))?;
        
        // Create message structure for MAC calculation
        let mut mac_data = Vec::new();
        mac_data.push(1u8); // Version
        mac_data.extend_from_slice(kyber_ciphertext.as_bytes());
        mac_data.extend_from_slice(&ephemeral_public.to_sec1_bytes());
        mac_data.extend_from_slice(&encrypted_data);
        
        // Calculate MAC
        let mac_cipher = ChaCha20Poly1305::new(&Key::from_slice(&mac_key));
        let mac_nonce = Nonce::from_slice(&[1u8; 12]); // Different nonce for MAC
        let mac_tag = mac_cipher.encrypt(mac_nonce, mac_data.as_slice())
            .map_err(|e| PostQuantumError::ChaCha20Poly1305(format!("MAC calculation failed: {}", e)))?;
        
        // Extract first 16 bytes as MAC
        let mut mac = [0u8; 16];
        mac.copy_from_slice(&mac_tag[..16]);
        
        Ok(SecureMessage {
            version: 1,
            kyber_ciphertext,
            ecdh_ephemeral_public: ephemeral_public,
            encrypted_data,
            mac,
        })
    }
    
    /// Decrypt data following the doom principle! *ears perk up attentively*
    pub fn decrypt(
        &self,
        recipient_ecdh_secret: &EcdhSecretKey,
        recipient_kyber_secret: &Kyber512SecretKey,
    ) -> Result<Vec<u8>, PostQuantumError> {
        // FIRST: Verify MAC before any cryptographic operations (Doom Principle!)
        let mut mac_data = Vec::new();
        mac_data.push(self.version);
        mac_data.extend_from_slice(self.kyber_ciphertext.as_bytes());
        mac_data.extend_from_slice(&self.ecdh_ephemeral_public.to_sec1_bytes());
        mac_data.extend_from_slice(&self.encrypted_data);
        
        // Derive MAC key (we need to do this to verify MAC)
        // This is safe because we're not using the decrypted data yet
        let ecdh_shared_secret = diffie_hellman(recipient_ecdh_secret.to_nonzero_scalar(), self.ecdh_ephemeral_public.as_affine());
        let ecdh_shared_bytes = ecdh_shared_secret.raw_secret_bytes();
        
        let kyber_shared_secret = kyber_decapsulate(&self.kyber_ciphertext, recipient_kyber_secret);
        
        let combined_secret = [ecdh_shared_bytes.as_slice(), kyber_shared_secret.as_bytes()].concat();
        let hkdf = Hkdf::<Sha256>::new(Some(b"purrcrypt-v2-hybrid"), &combined_secret);
        
        let mut mac_key = [0u8; 32];
        hkdf.expand(b"poly1305-mac", &mut mac_key)
            .map_err(|e| PostQuantumError::KeyDerivation(format!("Failed to derive MAC key: {}", e)))?;
        
        // Verify MAC
        let mac_cipher = ChaCha20Poly1305::new(&Key::from_slice(&mac_key));
        let mac_nonce = Nonce::from_slice(&[1u8; 12]);
        let expected_mac_tag = mac_cipher.encrypt(mac_nonce, mac_data.as_slice())
            .map_err(|e| PostQuantumError::ChaCha20Poly1305(format!("MAC verification failed: {}", e)))?;
        
        let expected_mac = &expected_mac_tag[..16];
        if !constant_time_eq(expected_mac, &self.mac) {
            return Err(PostQuantumError::MacVerificationFailed);
        }
        
        // MAC is valid! Now we can safely decrypt
        let mut encryption_key = [0u8; 32];
        hkdf.expand(b"chacha20-encryption", &mut encryption_key)
            .map_err(|e| PostQuantumError::KeyDerivation(format!("Failed to derive encryption key: {}", e)))?;
        
        let cipher = ChaCha20Poly1305::new(&Key::from_slice(&encryption_key));
        let nonce = Nonce::from_slice(&[0u8; 12]);
        
        let decrypted_data = cipher.decrypt(nonce, self.encrypted_data.as_slice())
            .map_err(|e| PostQuantumError::ChaCha20Poly1305(format!("Decryption failed: {}", e)))?;
        
        Ok(decrypted_data)
    }
    
    /// Serialize message to bytes for storage/transmission
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.push(self.version);
        result.extend_from_slice(self.kyber_ciphertext.as_bytes());
        result.extend_from_slice(&self.ecdh_ephemeral_public.to_sec1_bytes());
        result.extend_from_slice(&(self.encrypted_data.len() as u32).to_le_bytes());
        result.extend_from_slice(&self.encrypted_data);
        result.extend_from_slice(&self.mac);
        result
    }
    
    /// Deserialize message from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, PostQuantumError> {
        if data.len() < 1 + 768 + 33 + 4 + 16 { // Minimum size check
            return Err(PostQuantumError::Io(io::Error::new(io::ErrorKind::InvalidData, "Message too short")));
        }
        
        let mut offset = 0;
        let version = data[offset];
        offset += 1;
        
        let kyber_ciphertext = Kyber512Ciphertext::from_bytes(&data[offset..offset + 768])
            .map_err(|e| PostQuantumError::Kyber(format!("Invalid Kyber ciphertext: {}", e)))?;
        offset += 768;
        
        let ecdh_ephemeral_public = EcdhPublicKey::from_sec1_bytes(&data[offset..offset + 33])
            .map_err(|e| PostQuantumError::Kyber(format!("Invalid ECDH public key: {}", e)))?;
        offset += 33;
        
        let encrypted_data_len = u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]) as usize;
        offset += 4;
        
        if data.len() < offset + encrypted_data_len + 16 {
            return Err(PostQuantumError::Io(io::Error::new(io::ErrorKind::InvalidData, "Invalid message length")));
        }
        
        let encrypted_data = data[offset..offset + encrypted_data_len].to_vec();
        offset += encrypted_data_len;
        
        let mut mac = [0u8; 16];
        mac.copy_from_slice(&data[offset..offset + 16]);
        
        Ok(SecureMessage {
            version,
            kyber_ciphertext,
            ecdh_ephemeral_public,
            encrypted_data,
            mac,
        })
    }
}

/// Constant-time comparison to prevent timing attacks! *purrs securely*
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_key_generation() {
        let _keypair = HybridKeyPair::new().unwrap();
        println!("Generated hybrid key pair successfully!");
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let _sender_keypair = HybridKeyPair::new().unwrap();
        let recipient_keypair = HybridKeyPair::new().unwrap();
        
        let test_data = b"Hello, quantum-resistant world! Nyaa~ >w<";
        
        // Encrypt
        let message = SecureMessage::encrypt(
            test_data,
            &recipient_keypair.ecdh_public,
            &recipient_keypair.kyber_public,
        ).unwrap();
        
        // Decrypt
        let decrypted = message.decrypt(
            &recipient_keypair.ecdh_secret,
            &recipient_keypair.kyber_secret,
        ).unwrap();
        
        assert_eq!(test_data.to_vec(), decrypted);
        println!("Hybrid encryption/decryption successful!");
    }

    #[test]
    fn test_serialization() {
        let _sender_keypair = HybridKeyPair::new().unwrap();
        let recipient_keypair = HybridKeyPair::new().unwrap();
        
        let test_data = b"Serialization test data";
        
        let message = SecureMessage::encrypt(
            test_data,
            &recipient_keypair.ecdh_public,
            &recipient_keypair.kyber_public,
        ).unwrap();
        
        let serialized = message.to_bytes();
        let deserialized = SecureMessage::from_bytes(&serialized).unwrap();
        
        let decrypted = deserialized.decrypt(
            &recipient_keypair.ecdh_secret,
            &recipient_keypair.kyber_secret,
        ).unwrap();
        
        assert_eq!(test_data.to_vec(), decrypted);
        println!("Serialization test successful!");
    }

    #[test]
    fn test_mac_verification() {
        let _sender_keypair = HybridKeyPair::new().unwrap();
        let recipient_keypair = HybridKeyPair::new().unwrap();
        
        let test_data = b"MAC verification test";
        
        let mut message = SecureMessage::encrypt(
            test_data,
            &recipient_keypair.ecdh_public,
            &recipient_keypair.kyber_public,
        ).unwrap();
        
        // Corrupt the MAC
        message.mac[0] ^= 0xFF;
        
        // Decryption should fail
        let result = message.decrypt(
            &recipient_keypair.ecdh_secret,
            &recipient_keypair.kyber_secret,
        );
        
        assert!(result.is_err());
        println!("MAC verification test successful!");
    }

    // COMPREHENSIVE TESTS FOR POST-QUANTUM CRYPTOGRAPHY
    
    #[test]
    fn test_hybrid_key_generation_multiple() {
        // Test generating multiple key pairs
        for i in 0..10 {
            let keypair = HybridKeyPair::new().unwrap();
            println!("Generated hybrid key pair {} successfully!", i + 1);
            
            // Verify keys are different
            let zero_key = [0u8; 33];
            assert_ne!(keypair.ecdh_public.to_sec1_bytes().as_ref(), &zero_key);
            assert_ne!(keypair.kyber_public.as_bytes(), &[0u8; 800]);
        }
    }
    
    #[test]
    fn test_encrypt_decrypt_large_data() {
        let _sender_keypair = HybridKeyPair::new().unwrap();
        let recipient_keypair = HybridKeyPair::new().unwrap();
        
        // Test with large data (1KB)
        let large_data = b"Large data test for post-quantum cryptography. ".repeat(25);
        
        let message = SecureMessage::encrypt(
            &large_data,
            &recipient_keypair.ecdh_public,
            &recipient_keypair.kyber_public,
        ).unwrap();
        
        let decrypted = message.decrypt(
            &recipient_keypair.ecdh_secret,
            &recipient_keypair.kyber_secret,
        ).unwrap();
        
        assert_eq!(large_data, decrypted);
        println!("Large data encryption/decryption successful!");
    }
    
    #[test]
    fn test_encrypt_decrypt_empty_data() {
        let _sender_keypair = HybridKeyPair::new().unwrap();
        let recipient_keypair = HybridKeyPair::new().unwrap();
        
        let empty_data = b"";
        
        let message = SecureMessage::encrypt(
            empty_data,
            &recipient_keypair.ecdh_public,
            &recipient_keypair.kyber_public,
        ).unwrap();
        
        let decrypted = message.decrypt(
            &recipient_keypair.ecdh_secret,
            &recipient_keypair.kyber_secret,
        ).unwrap();
        
        assert_eq!(empty_data.to_vec(), decrypted);
        println!("Empty data encryption/decryption successful!");
    }
    
    #[test]
    fn test_encrypt_decrypt_unicode_data() {
        let _sender_keypair = HybridKeyPair::new().unwrap();
        let recipient_keypair = HybridKeyPair::new().unwrap();
        
        let unicode_data = "Hello 世界! 🌍 Nyaa~ >w< 量子加密测试".as_bytes();
        
        let message = SecureMessage::encrypt(
            unicode_data,
            &recipient_keypair.ecdh_public,
            &recipient_keypair.kyber_public,
        ).unwrap();
        
        let decrypted = message.decrypt(
            &recipient_keypair.ecdh_secret,
            &recipient_keypair.kyber_secret,
        ).unwrap();
        
        assert_eq!(unicode_data, decrypted);
        println!("Unicode data encryption/decryption successful!");
    }
    
    #[test]
    fn test_serialization_roundtrip() {
        let _sender_keypair = HybridKeyPair::new().unwrap();
        let recipient_keypair = HybridKeyPair::new().unwrap();
        
        let test_data = b"Serialization roundtrip test";
        
        let message = SecureMessage::encrypt(
            test_data,
            &recipient_keypair.ecdh_public,
            &recipient_keypair.kyber_public,
        ).unwrap();
        
        // Serialize and deserialize
        let serialized = message.to_bytes();
        let deserialized = SecureMessage::from_bytes(&serialized).unwrap();
        
        // Decrypt the deserialized message
        let decrypted = deserialized.decrypt(
            &recipient_keypair.ecdh_secret,
            &recipient_keypair.kyber_secret,
        ).unwrap();
        
        assert_eq!(test_data.to_vec(), decrypted);
        println!("Serialization roundtrip test successful!");
    }
    
    #[test]
    fn test_different_recipients() {
        let _sender_keypair = HybridKeyPair::new().unwrap();
        let recipient1_keypair = HybridKeyPair::new().unwrap();
        let recipient2_keypair = HybridKeyPair::new().unwrap();
        
        let test_data = b"Message for different recipients";
        
        // Encrypt for recipient 1
        let message1 = SecureMessage::encrypt(
            test_data,
            &recipient1_keypair.ecdh_public,
            &recipient1_keypair.kyber_public,
        ).unwrap();
        
        // Encrypt for recipient 2
        let message2 = SecureMessage::encrypt(
            test_data,
            &recipient2_keypair.ecdh_public,
            &recipient2_keypair.kyber_public,
        ).unwrap();
        
        // Messages should be different
        assert_ne!(message1.to_bytes(), message2.to_bytes());
        
        // Each recipient should be able to decrypt their own message
        let decrypted1 = message1.decrypt(
            &recipient1_keypair.ecdh_secret,
            &recipient1_keypair.kyber_secret,
        ).unwrap();
        
        let decrypted2 = message2.decrypt(
            &recipient2_keypair.ecdh_secret,
            &recipient2_keypair.kyber_secret,
        ).unwrap();
        
        assert_eq!(test_data.to_vec(), decrypted1);
        assert_eq!(test_data.to_vec(), decrypted2);
        
        // Recipients should not be able to decrypt each other's messages
        let result1 = message1.decrypt(
            &recipient2_keypair.ecdh_secret,
            &recipient2_keypair.kyber_secret,
        );
        
        let result2 = message2.decrypt(
            &recipient1_keypair.ecdh_secret,
            &recipient1_keypair.kyber_secret,
        );
        
        assert!(result1.is_err());
        assert!(result2.is_err());
        
        println!("Different recipients test successful!");
    }
    
    #[test]
    fn test_message_corruption() {
        let _sender_keypair = HybridKeyPair::new().unwrap();
        let recipient_keypair = HybridKeyPair::new().unwrap();
        
        let test_data = b"Message corruption test";
        
        let message = SecureMessage::encrypt(
            test_data,
            &recipient_keypair.ecdh_public,
            &recipient_keypair.kyber_public,
        ).unwrap();
        
        let serialized = message.to_bytes();
        
        // Corrupt different parts of the message
        let corruption_tests = [
            ("version", 0),
            ("kyber_ciphertext", 1),
            ("ecdh_public", 1 + 768),
            ("encrypted_data", 1 + 768 + 33 + 4),
            ("mac", serialized.len() - 16),
        ];
        
        for (name, offset) in &corruption_tests {
            let mut corrupted = serialized.clone();
            if *offset < corrupted.len() {
                corrupted[*offset] ^= 0xFF;
                
                let result = SecureMessage::from_bytes(&corrupted);
                if result.is_ok() {
                    // If deserialization succeeds, decryption should fail
                    let corrupted_message = result.unwrap();
                    let decrypt_result = corrupted_message.decrypt(
                        &recipient_keypair.ecdh_secret,
                        &recipient_keypair.kyber_secret,
                    );
                    assert!(decrypt_result.is_err(), "Corruption of {} should cause decryption failure", name);
                }
            }
        }
        
        println!("Message corruption test successful!");
    }
    
    #[test]
    fn test_performance_benchmark() {
        let _sender_keypair = HybridKeyPair::new().unwrap();
        let recipient_keypair = HybridKeyPair::new().unwrap();
        
        let test_data = b"Performance benchmark test data for post-quantum cryptography. ".repeat(100);
        
        let start = std::time::Instant::now();
        
        // Encrypt
        let message = SecureMessage::encrypt(
            &test_data,
            &recipient_keypair.ecdh_public,
            &recipient_keypair.kyber_public,
        ).unwrap();
        
        let encrypt_time = start.elapsed();
        
        // Decrypt
        let start = std::time::Instant::now();
        let decrypted = message.decrypt(
            &recipient_keypair.ecdh_secret,
            &recipient_keypair.kyber_secret,
        ).unwrap();
        
        let decrypt_time = start.elapsed();
        
        println!("Post-quantum cryptography performance test:");
        println!("  Input size: {} bytes", test_data.len());
        println!("  Encrypt time: {:?}", encrypt_time);
        println!("  Decrypt time: {:?}", decrypt_time);
        println!("  Encrypt speed: {:.2} MB/s", test_data.len() as f64 / encrypt_time.as_secs_f64() / 1_000_000.0);
        println!("  Decrypt speed: {:.2} MB/s", test_data.len() as f64 / decrypt_time.as_secs_f64() / 1_000_000.0);
        
        assert_eq!(test_data.to_vec(), decrypted);
        
        // Performance assertions (post-quantum crypto is slower than classical)
        assert!(encrypt_time.as_secs_f64() < 5.0, "Encryption too slow: {:?}", encrypt_time);
        assert!(decrypt_time.as_secs_f64() < 5.0, "Decryption too slow: {:?}", decrypt_time);
    }
    
    #[test]
    fn test_key_serialization() {
        let keypair = HybridKeyPair::new().unwrap();
        
        // Test saving and loading keys
        let temp_dir = std::env::temp_dir();
        let ecdh_pub_path = temp_dir.join("test_ecdh_public.pem");
        let ecdh_sec_path = temp_dir.join("test_ecdh_secret.pem");
        let kyber_pub_path = temp_dir.join("test_kyber_public.bin");
        let kyber_sec_path = temp_dir.join("test_kyber_secret.bin");
        
        // Save keys
        keypair.save(
            ecdh_pub_path.to_str().unwrap(),
            ecdh_sec_path.to_str().unwrap(),
            kyber_pub_path.to_str().unwrap(),
            kyber_sec_path.to_str().unwrap(),
        ).unwrap();
        
        // Load keys
        let loaded_keypair = HybridKeyPair::load(
            ecdh_pub_path.to_str().unwrap(),
            ecdh_sec_path.to_str().unwrap(),
            kyber_pub_path.to_str().unwrap(),
            kyber_sec_path.to_str().unwrap(),
        ).unwrap();
        
        // Test that loaded keys work
        let test_data = b"Key serialization test";
        let message = SecureMessage::encrypt(
            test_data,
            &loaded_keypair.ecdh_public,
            &loaded_keypair.kyber_public,
        ).unwrap();
        
        let decrypted = message.decrypt(
            &loaded_keypair.ecdh_secret,
            &loaded_keypair.kyber_secret,
        ).unwrap();
        
        assert_eq!(test_data.to_vec(), decrypted);
        
        // Clean up
        let _ = std::fs::remove_file(ecdh_pub_path);
        let _ = std::fs::remove_file(ecdh_sec_path);
        let _ = std::fs::remove_file(kyber_pub_path);
        let _ = std::fs::remove_file(kyber_sec_path);
        
        println!("Key serialization test successful!");
    }
    
    #[test]
    fn test_constant_time_comparison() {
        // Test constant time comparison function
        let a = b"test data";
        let b = b"test data";
        let c = b"different";
        
        assert!(constant_time_eq(a, b));
        assert!(!constant_time_eq(a, c));
        assert!(!constant_time_eq(a, b"short"));
        assert!(!constant_time_eq(b"short", a));
        
        // Test with different lengths
        assert!(!constant_time_eq(b"", b"a"));
        assert!(!constant_time_eq(b"a", b""));
        
        println!("Constant time comparison test successful!");
    }
    
    #[test]
    fn test_message_structure() {
        let _sender_keypair = HybridKeyPair::new().unwrap();
        let recipient_keypair = HybridKeyPair::new().unwrap();
        
        let test_data = b"Message structure test";
        
        let message = SecureMessage::encrypt(
            test_data,
            &recipient_keypair.ecdh_public,
            &recipient_keypair.kyber_public,
        ).unwrap();
        
        // Test message structure
        assert_eq!(message.version, 1);
        assert_eq!(message.kyber_ciphertext.as_bytes().len(), 768);
        assert_eq!(message.ecdh_ephemeral_public.to_sec1_bytes().len(), 33);
        assert_eq!(message.mac.len(), 16);
        assert!(!message.encrypted_data.is_empty());
        
        // Test serialization structure
        let serialized = message.to_bytes();
        assert!(serialized.len() > 800); // Should be larger than just the components
        
        println!("Message structure test successful!");
    }
}