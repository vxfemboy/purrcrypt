// src/keys.rs
use crate::debug;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use k256::elliptic_curve::rand_core::OsRng;
use k256::{
    ecdh::{diffie_hellman, EphemeralSecret},
    sha2, PublicKey, SecretKey,
};
use std::fs;
use std::path::Path;
use thiserror::Error;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[derive(Error, Debug)]
pub enum KeyError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid key format: {0}")]
    InvalidKey(String),
    #[error("Encryption error: {0}")]
    EncryptionError(String),
    #[error("Decryption error: {0}")]
    DecryptionError(String),
}

pub struct KeyPair {
    pub secret_key: SecretKey,
    pub public_key: PublicKey,
}

impl Default for KeyPair {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyPair {
    pub fn new() -> Self {
        let secret_key = SecretKey::random(&mut OsRng);
        let scalar = secret_key.to_nonzero_scalar();
        let public_key = PublicKey::from_secret_scalar(&scalar);

        Self {
            secret_key,
            public_key,
        }
    }

    pub fn save_keys(&self, pub_path: &Path, secret_path: &Path) -> Result<(), KeyError> {
        // Save public key in compressed format
        let pub_bytes = self.public_key.to_sec1_bytes();
        let encoded_pub = BASE64.encode(&pub_bytes);
        fs::write(pub_path, encoded_pub)?;

        #[cfg(unix)]
        fs::set_permissions(pub_path, fs::Permissions::from_mode(0o644))?;

        #[cfg(windows)]
        {
            let mut perms = fs::metadata(pub_path)?.permissions();
            perms.set_readonly(false);
            fs::set_permissions(pub_path, perms)?;
        }

        // Save private key
        let secret_bytes = self.secret_key.to_bytes();
        let encoded_secret = BASE64.encode(secret_bytes);
        fs::write(secret_path, encoded_secret)?;

        #[cfg(unix)]
        fs::set_permissions(secret_path, fs::Permissions::from_mode(0o600))?;

        #[cfg(windows)]
        {
            let mut perms = fs::metadata(secret_path)?.permissions();
            perms.set_readonly(true);
            fs::set_permissions(secret_path, perms)?;
        }

        Ok(())
    }

    pub fn load_public_key(pub_path: &Path) -> Result<PublicKey, KeyError> {
        let pub_data = fs::read_to_string(pub_path)
            .map_err(|e| KeyError::InvalidKey(format!("Failed to read public key file: {}", e)))?;

        let pub_data = pub_data.trim();
        debug!("Public key length (base64): {}", pub_data.len());

        let pub_bytes = BASE64.decode(pub_data).map_err(|e| {
            KeyError::InvalidKey(format!("Failed to decode public key base64: {}", e))
        })?;
        debug!("Public key length (decoded): {}", pub_bytes.len());

        PublicKey::from_sec1_bytes(&pub_bytes)
            .map_err(|e| KeyError::InvalidKey(format!("Failed to parse public key: {}", e)))
    }

    pub fn load_keypair(pub_path: &Path, secret_path: &Path) -> Result<Self, KeyError> {
        let public_key = Self::load_public_key(pub_path)?;

        let secret_data = fs::read_to_string(secret_path)
            .map_err(|e| KeyError::InvalidKey(format!("Failed to read private key file: {}", e)))?;

        let secret_data = secret_data.trim();
        debug!("Private key length (base64): {}", secret_data.len());

        let secret_bytes = BASE64.decode(secret_data).map_err(|e| {
            KeyError::InvalidKey(format!("Failed to decode private key base64: {}", e))
        })?;
        debug!("Private key length (decoded): {}", secret_bytes.len());

        let secret_key = SecretKey::from_slice(&secret_bytes)
            .map_err(|e| KeyError::InvalidKey(format!("Failed to parse private key: {}", e)))?;

        Ok(Self {
            secret_key,
            public_key,
        })
    }
}

pub fn encrypt_data(data: &[u8], recipient_public_key: &PublicKey) -> Result<Vec<u8>, KeyError> {
    // Generate ephemeral key pair for this message
    let ephemeral_secret = EphemeralSecret::random(&mut OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);

    // Perform ECDH to get shared secret
    let shared_secret = ephemeral_secret.diffie_hellman(recipient_public_key);

    // Properly derive key material using the built-in KDF
    let shared_secret = shared_secret.extract::<sha2::Sha256>(Some(b"purrcrypt-salt"));

    // Derive encryption key
    let mut encryption_key = [0u8; 32];
    shared_secret
        .expand(b"encryption key", &mut encryption_key)
        .map_err(|_| KeyError::EncryptionError("Failed to derive encryption key".to_string()))?;

    // Derive nonce (or use constant nonce as it's a single-use key)
    let mut nonce_bytes = [0u8; 12];
    shared_secret
        .expand(b"nonce", &mut nonce_bytes)
        .map_err(|_| KeyError::EncryptionError("Failed to derive nonce".to_string()))?;

    // Use derived key for AES
    let aes_key = Key::<Aes256Gcm>::from_slice(&encryption_key);
    let cipher = Aes256Gcm::new(aes_key);

    // Use derived nonce
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt the data
    let encrypted_data = cipher
        .encrypt(nonce, data)
        .map_err(|e| KeyError::EncryptionError(format!("AES-GCM encryption failed: {}", e)))?;

    // Combine ephemeral public key (in compressed format) with encrypted data
    let mut result = Vec::new();
    result.extend_from_slice(&ephemeral_public.to_sec1_bytes());
    result.extend_from_slice(&encrypted_data);

    Ok(result)
}

pub fn decrypt_data(encrypted_data: &[u8], secret_key: &SecretKey) -> Result<Vec<u8>, KeyError> {
    // Split input into ephemeral public key and encrypted data
    // For compressed keys, the length is 33 bytes instead of 65
    if encrypted_data.len() <= 33 {
        return Err(KeyError::DecryptionError(
            "Encrypted data too short".to_string(),
        ));
    }

    let (ephemeral_pub_bytes, encrypted) = encrypted_data.split_at(33);
    debug!(
        "Trying to reconstruct key from {} bytes",
        ephemeral_pub_bytes.len()
    );

    // Reconstruct ephemeral public key
    let ephemeral_public = PublicKey::from_sec1_bytes(ephemeral_pub_bytes).map_err(|e| {
        KeyError::DecryptionError(format!("Failed to reconstruct ephemeral public key: {}", e))
    })?;

    // Get the affine point for ECDH
    let point = ephemeral_public.as_affine();

    // Perform ECDH using our private key and the ephemeral public key
    let shared_secret = diffie_hellman(secret_key.to_nonzero_scalar(), point);

    // Properly derive key material using the built-in KDF
    let shared_secret = shared_secret.extract::<sha2::Sha256>(Some(b"purrcrypt-salt"));

    // Derive the same encryption key
    let mut encryption_key = [0u8; 32];
    shared_secret
        .expand(b"encryption key", &mut encryption_key)
        .map_err(|_| KeyError::DecryptionError("Failed to derive encryption key".to_string()))?;

    // Derive the same nonce
    let mut nonce_bytes = [0u8; 12];
    shared_secret
        .expand(b"nonce", &mut nonce_bytes)
        .map_err(|_| KeyError::DecryptionError("Failed to derive nonce".to_string()))?;

    // Derive AES key from the properly derived key material
    let aes_key = Key::<Aes256Gcm>::from_slice(&encryption_key);
    let cipher = Aes256Gcm::new(aes_key);

    // Use the derived nonce
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Decrypt the data
    cipher
        .decrypt(nonce, encrypted)
        .map_err(|e| KeyError::DecryptionError(format!("AES-GCM decryption failed: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        // Generate a test keypair
        let keypair = KeyPair::new();

        // Test data
        let data = b"Hello FBI, i'm a cat";

        // Encrypt data using public key
        let encrypted = encrypt_data(data, &keypair.public_key).expect("Encryption should succeed");

        // Decrypt data using secret key
        let decrypted =
            decrypt_data(&encrypted, &keypair.secret_key).expect("Decryption should succeed");

        // Verify data is the same after round trip
        assert_eq!(data.to_vec(), decrypted);
    }

    #[test]
    fn test_encrypt_decrypt_empty_data() {
        // Generate a test keypair
        let keypair = KeyPair::new();

        // Test with empty data
        let empty_data = b"";

        // Encrypt empty data
        let encrypted = encrypt_data(empty_data, &keypair.public_key)
            .expect("Encryption of empty data should succeed");

        // Decrypt empty data
        let decrypted =
            decrypt_data(&encrypted, &keypair.secret_key).expect("Decryption should succeed");

        // Verify
        assert_eq!(empty_data.to_vec(), decrypted);
    }

    #[test]
    fn test_encrypt_decrypt_large_data() {
        // Generate a test keypair
        let keypair = KeyPair::new();

        // Generate a larger test data (1KB)
        let large_data = vec![0xA5; 1024];

        // Encrypt data using public key
        let encrypted =
            encrypt_data(&large_data, &keypair.public_key).expect("Encryption should succeed");

        // Decrypt data using secret key
        let decrypted =
            decrypt_data(&encrypted, &keypair.secret_key).expect("Decryption should succeed");

        // Verify data is the same after round trip
        assert_eq!(large_data, decrypted);
    }

    #[test]
    fn test_decrypt_invalid_data() {
        // Generate a test keypair
        let keypair = KeyPair::new();

        // Try to decrypt invalid data (too short)
        let result = decrypt_data(b"too short", &keypair.secret_key);
        assert!(result.is_err(), "Decrypting invalid data should fail");

        // Test with corrupted ciphertext
        let data = b"Test message";
        let mut encrypted =
            encrypt_data(data, &keypair.public_key).expect("Encryption should succeed");

        // Corrupt the encrypted data (modify a byte in the ciphertext portion, after the public key)
        if encrypted.len() > 40 {
            encrypted[40] ^= 0xFF;
            let result = decrypt_data(&encrypted, &keypair.secret_key);
            assert!(result.is_err(), "Decrypting corrupted data should fail");
        }
    }

    #[test]
    fn test_different_keypairs() {
        // Generate two different keypairs
        let keypair1 = KeyPair::new();
        let keypair2 = KeyPair::new();

        // Test data
        let data = b"Cross-keypair test";

        // Encrypt with keypair1's public key
        let encrypted =
            encrypt_data(data, &keypair1.public_key).expect("Encryption should succeed");

        // Try to decrypt with keypair2's secret key (should fail)
        let result = decrypt_data(&encrypted, &keypair2.secret_key);

        // This might occasionally succeed due to random chance, but should almost always fail
        // with an error related to authentication or decryption
        if let Ok(decrypted) = result {
            // In the extremely unlikely event it doesn't fail, at least the output should be different
            assert_ne!(
                data.to_vec(),
                decrypted,
                "Decrypted data should not match original"
            );
        }
    }
}
