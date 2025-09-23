// src/crypto.rs
use crate::{
    cipher::{CatCipher, CipherDialect, CipherMode},
    debug,
    keys::{decrypt_data, encrypt_data, KeyError, KeyPair},
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use flate2::{
    read::{ZlibDecoder, ZlibEncoder},
    Compression,
};
use k256::PublicKey;
use std::{
    fs::File,
    io::{self, BufReader, BufWriter, Read},
    path::Path,
};
use thiserror::Error;
use crate::cipher::PetDialect;

// New modules for our fluffy upgrades! Nyaa~ >w<
pub mod post_quantum;
pub mod efficient_compression;



#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("Key error: {0}")]
    Key(#[from] KeyError),
    #[error("Base64 error: {0}")]
    Base64(String),
}

// Debug function to print bytes in hex
fn debug_hex(label: &str, data: &[u8]) {
    let hex: Vec<String> = data.iter().map(|b| format!("{:02x}", b)).collect();
    debug!("{}: {} bytes", label, data.len());
    for chunk in hex.chunks(16) {
        debug!("  {}", chunk.join(" "));
    }
}

pub fn encrypt_file(
    input_filename: &str,
    output_filename: &str,
    recipient_public_key: &PublicKey,
    dialect: CipherDialect,
) -> Result<(), CryptoError> {
    let mut input_file = BufReader::new(File::open(input_filename)?);
    let mut output_file = BufWriter::new(File::create(output_filename)?);
    let cipher = CatCipher::new(dialect);

    // Read input data
    let mut input_data = Vec::new();
    input_file.read_to_end(&mut input_data)?;
    debug_hex("Input data", &input_data);

    // Compress the input data
    let mut compressor = ZlibEncoder::new(&input_data[..], Compression::default());
    let mut compressed_data = Vec::new();
    compressor.read_to_end(&mut compressed_data)?;
    debug_hex("Compressed data", &compressed_data);

    // Encrypt the compressed data using elliptic curve
    let encrypted_data = encrypt_data(&compressed_data, recipient_public_key)?;
    debug_hex("Encrypted data", &encrypted_data);

    // First base64 encode the binary data
    let encoded_data = BASE64.encode(&encrypted_data);
    debug!("Base64 encoded: {}", encoded_data);

    // Then process it with the animal cipher
    cipher.process_data(
        encoded_data.as_bytes(),
        &mut output_file,
        CipherMode::Encrypt,
    )?;

    Ok(())
}

pub fn decrypt_file(
    input_filename: &str,
    output_filename: &str,
    keypair: &KeyPair,
) -> Result<(), CryptoError> {
    let mut input_file = BufReader::new(File::open(input_filename)?);
    let mut output_file = BufWriter::new(File::create(output_filename)?);
    // Use cat dialect for decryption - it will try both patterns automatically
    let cipher = CatCipher::new(CipherDialect::Cat);

    // Read the encoded data
    let mut content = String::new();
    input_file.read_to_string(&mut content)?;
    debug!("Encoded content: {}", content);

    // Decode cipher
    let decoded = cipher.process_string(&content, CipherMode::Decrypt)?;
    debug!(
        "Decoded content (base64): {}",
        String::from_utf8_lossy(&decoded)
    );

    // Decode base64
    let encrypted_data = BASE64
        .decode(&decoded)
        .map_err(|e| CryptoError::Base64(e.to_string()))?;
    debug_hex("Decoded encrypted data", &encrypted_data);

    // Split and show ephemeral key
    if encrypted_data.len() > 65 {
        debug_hex("Ephemeral public key", &encrypted_data[..65]);
        debug_hex("Encrypted content", &encrypted_data[65..]);
    }

    // Decrypt using elliptic curve
    let compressed_data = decrypt_data(&encrypted_data, &keypair.secret_key)?;
    debug_hex("Decrypted data", &compressed_data);

    // Decompress the data
    let mut decompressor = ZlibDecoder::new(&compressed_data[..]);
    io::copy(&mut decompressor, &mut output_file)?;

    Ok(())
}

pub fn generate_keypair(pub_path: &Path, secret_path: &Path) -> Result<(), KeyError> {
    let keypair = KeyPair::new();
    keypair.save_keys(pub_path, secret_path)
}


pub fn load_keypair(pub_path: &Path, secret_path: &Path) -> Result<KeyPair, KeyError> {
    KeyPair::load_keypair(pub_path, secret_path)
}

/// New fluffy encryption function using all our adowable upgrades! Nyaa~ >w<
pub fn encrypt_file_v2(
    input_filename: &str,
    output_filename: &str,
    recipient_ecdh_public: &k256::PublicKey,
    recipient_kyber_public: &pqcrypto_kyber::kyber512::PublicKey,
    dialect: PetDialect,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::crypto::efficient_compression::SmartCompressor;
    use crate::crypto::post_quantum::SecureMessage;
    use crate::cipher::EfficientPetCipher;
    
    // Read input data
    let input_data = std::fs::read(input_filename)?;
    debug_hex("Input data", &input_data);
    
    // Compress data efficiently
    let compressor = SmartCompressor::new();
    let compressed_data = compressor.compress(&input_data)?;
    debug_hex("Compressed data", &compressed_data);
    
    // Encrypt with post-quantum security
    let secure_message = SecureMessage::encrypt(
        &compressed_data,
        recipient_ecdh_public,
        recipient_kyber_public,
    )?;
    debug_hex("Encrypted data", &secure_message.encrypted_data);
    
    // Encode with efficient pet sounds
    let mut output_file = std::fs::File::create(output_filename)?;
    let cipher = EfficientPetCipher::new(dialect);
    
    // Serialize the secure message
    let message_bytes = secure_message.to_bytes();
    cipher.encode_data(&message_bytes, &mut output_file)?;
    
    Ok(())
}

/// New fluffy decryption function! *purrs securely*
pub fn decrypt_file_v2(
    input_filename: &str,
    output_filename: &str,
    recipient_ecdh_secret: &k256::SecretKey,
    recipient_kyber_secret: &pqcrypto_kyber::kyber512::SecretKey,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::crypto::efficient_compression::SmartCompressor;
    use crate::crypto::post_quantum::SecureMessage;
    use crate::cipher::{EfficientPetCipher, PetDialect};
    
    // Read and decode pet sounds
    let input_content = std::fs::read_to_string(input_filename)?;
    let cipher = EfficientPetCipher::new(PetDialect::Kitty); // Try kitty first
    let message_bytes = match cipher.decode_data(&input_content) {
        Ok(data) => data,
        Err(_) => {
            // Try puppy dialect if kitty fails
            let puppy_cipher = EfficientPetCipher::new(PetDialect::Puppy);
            puppy_cipher.decode_data(&input_content)?
        }
    };
    
    // Deserialize secure message
    let secure_message = SecureMessage::from_bytes(&message_bytes)?;
    
    // Decrypt with post-quantum security (follows doom principle!)
    let compressed_data = secure_message.decrypt(recipient_ecdh_secret, recipient_kyber_secret)?;
    debug_hex("Decrypted data", &compressed_data);
    
    // Decompress efficiently
    let compressor = SmartCompressor::new();
    let decompressed_data = compressor.decompress(&compressed_data)?;
    debug_hex("Decompressed data", &decompressed_data);
    
    // Write output
    std::fs::write(output_filename, decompressed_data)?;
    
    Ok(())
}   