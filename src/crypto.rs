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
