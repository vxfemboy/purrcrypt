// src/keys.rs
use crate::debug;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use k256::{
    ecdh::{diffie_hellman, EphemeralSecret},
    PublicKey, SecretKey,
};
use rand_core::OsRng;
use std::path::Path;
use std::{fs, os::unix::fs::PermissionsExt};
use thiserror::Error;

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

        // Save private key
        let secret_bytes = self.secret_key.to_bytes();
        let encoded_secret = BASE64.encode(&secret_bytes);
        fs::write(secret_path, encoded_secret)?;

        #[cfg(unix)]
        fs::set_permissions(secret_path, fs::Permissions::from_mode(0o600))?;

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

    // Use shared secret to derive AES key
    let aes_key = Key::<Aes256Gcm>::from_slice(shared_secret.raw_secret_bytes());
    let cipher = Aes256Gcm::new(aes_key);

    // Generate random nonce
    let nonce = Nonce::from_slice(&shared_secret.raw_secret_bytes()[..12]);

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

    // Derive AES key from shared secret
    let secret_bytes = shared_secret.raw_secret_bytes();
    let aes_key = Key::<Aes256Gcm>::from_slice(secret_bytes.as_slice());
    let cipher = Aes256Gcm::new(aes_key);

    // Use same nonce derivation as encryption
    let nonce = Nonce::from_slice(&secret_bytes.as_slice()[..12]);

    // Decrypt the data
    cipher
        .decrypt(nonce, encrypted)
        .map_err(|e| KeyError::DecryptionError(format!("AES-GCM decryption failed: {}", e)))
}
