use purrcrypt::cipher::steganographic_rp::{SteganographicRPCipher, PetDialect, PetPersonality};
use purrcrypt::cipher::efficient::{EfficientPetCipher, FileType, EmotionalContext, PetDialect as EfficientPetDialect};
use purrcrypt::crypto::post_quantum::{HybridKeyPair, SecureMessage};
use purrcrypt::crypto::efficient_compression::SmartCompressor;

/// Integration test for the complete PurrCrypt system
#[test]
fn test_complete_encryption_pipeline() {
    println!("=== COMPLETE ENCRYPTION PIPELINE TEST ===");
    
    // 1. Generate hybrid key pairs
    println!("1. Generating hybrid key pairs...");
    let _sender_keypair = HybridKeyPair::new().unwrap();
    let recipient_keypair = HybridKeyPair::new().unwrap();
    println!("   ✓ Key pairs generated successfully");
    
    // 2. Prepare test data
    println!("2. Preparing test data...");
    let test_data = "Hello World! This is a comprehensive test of the PurrCrypt system. \
                      It includes steganographic RP encoding, efficient compression, \
                      and post-quantum cryptography. 🐱🐶💕✨🎉🚀".as_bytes();
    println!("   ✓ Test data prepared ({} bytes)", test_data.len());
    
    // 3. Compress data
    println!("3. Compressing data...");
    let compressor = SmartCompressor::new();
    let compressed_data = compressor.compress(test_data).unwrap();
    println!("   ✓ Data compressed ({} bytes -> {} bytes, {:.2}x ratio)", 
             test_data.len(), compressed_data.len(), 
             compressed_data.len() as f64 / test_data.len() as f64);
    
    // 4. Encrypt with post-quantum cryptography
    println!("4. Encrypting with post-quantum cryptography...");
    let encrypted_message = SecureMessage::encrypt(
        &compressed_data,
        &recipient_keypair.ecdh_public,
        &recipient_keypair.kyber_public,
    ).unwrap();
    println!("   ✓ Data encrypted with hybrid post-quantum encryption");
    
    // 5. Encode with steganographic RP
    println!("5. Encoding with steganographic RP...");
    let rp_cipher = SteganographicRPCipher::new(PetDialect::Kitty, PetPersonality::Excited);
    let mut rp_encoded = Vec::new();
    rp_cipher.encode_data(&encrypted_message.to_bytes(), &mut rp_encoded).unwrap();
    let rp_encoded_str = String::from_utf8(rp_encoded).unwrap();
    println!("   ✓ Data encoded as steganographic RP ({} bytes -> {} bytes, {:.2}x ratio)",
             encrypted_message.to_bytes().len(), rp_encoded_str.len(),
             rp_encoded_str.len() as f64 / encrypted_message.to_bytes().len() as f64);
    
    // 6. Decode from steganographic RP
    println!("6. Decoding from steganographic RP...");
    let decoded_bytes = rp_cipher.decode_data(&rp_encoded_str).unwrap();
    println!("   ✓ Data decoded from steganographic RP");
    
    // 7. Deserialize encrypted message
    println!("7. Deserializing encrypted message...");
    let deserialized_message = SecureMessage::from_bytes(&decoded_bytes).unwrap();
    println!("   ✓ Encrypted message deserialized");
    
    // 8. Decrypt with post-quantum cryptography
    println!("8. Decrypting with post-quantum cryptography...");
    let decrypted_data = deserialized_message.decrypt(
        &recipient_keypair.ecdh_secret,
        &recipient_keypair.kyber_secret,
    ).unwrap();
    println!("   ✓ Data decrypted with post-quantum cryptography");
    
    // 9. Decompress data
    println!("9. Decompressing data...");
    let decompressed_data = compressor.decompress(&decrypted_data).unwrap();
    println!("   ✓ Data decompressed");
    
    // 10. Verify data integrity
    println!("10. Verifying data integrity...");
    assert_eq!(test_data, &decompressed_data);
    println!("   ✓ Data integrity verified - original and final data match!");
    
    println!("=== COMPLETE PIPELINE TEST PASSED! ===");
}

/// Integration test for different personality types
#[test]
fn test_personality_integration() {
    println!("=== PERSONALITY INTEGRATION TEST ===");
    
    let test_data = b"Testing different personality types for steganographic RP encoding";
    let personalities = [
        PetPersonality::Chatty,
        PetPersonality::Excited,
        PetPersonality::Musical,
        PetPersonality::Playful,
        PetPersonality::Curious,
        PetPersonality::Sleepy,
    ];
    
    for personality in &personalities {
        println!("Testing personality: {:?}", personality);
        
        let rp_cipher = SteganographicRPCipher::new(PetDialect::Kitty, *personality);
        let mut encoded = Vec::new();
        rp_cipher.encode_data(test_data, &mut encoded).unwrap();
        let encoded_str = String::from_utf8(encoded).unwrap();
        
        let decoded = rp_cipher.decode_data(&encoded_str).unwrap();
        assert_eq!(test_data.to_vec(), decoded);
        
        println!("   ✓ {:?} personality test passed", personality);
    }
    
    println!("=== PERSONALITY INTEGRATION TEST PASSED! ===");
}

/// Integration test for different emotional contexts
#[test]
fn test_emotional_context_integration() {
    println!("=== EMOTIONAL CONTEXT INTEGRATION TEST ===");
    
    let test_data = b"Testing different emotional contexts for efficient cipher encoding";
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
    
    for context in &contexts {
        println!("Testing emotional context: {:?}", context);
        
        let efficient_cipher = EfficientPetCipher::new_with_context(EfficientPetDialect::Kitty, FileType::Unknown, context.clone());
        let mut encoded = Vec::new();
        efficient_cipher.encode_data(test_data, &mut encoded).unwrap();
        let encoded_str = String::from_utf8(encoded).unwrap();
        
        let decoded = efficient_cipher.decode_data(&encoded_str).unwrap();
        assert_eq!(test_data.to_vec(), decoded);
        
        println!("   ✓ {:?} context test passed", context);
    }
    
    println!("=== EMOTIONAL CONTEXT INTEGRATION TEST PASSED! ===");
}

/// Integration test for file type handling
#[test]
fn test_file_type_integration() {
    println!("=== FILE TYPE INTEGRATION TEST ===");
    
    let test_data = b"Testing different file types for efficient cipher encoding";
    let file_types = [
        FileType::Text,
        FileType::Image,
        FileType::Video,
        FileType::Audio,
        FileType::Data,
        FileType::Unknown,
    ];
    
    for file_type in &file_types {
        println!("Testing file type: {:?}", file_type);
        
        let efficient_cipher = EfficientPetCipher::new_with_context(EfficientPetDialect::Kitty, file_type.clone(), EmotionalContext::Calm);
        let mut encoded = Vec::new();
        efficient_cipher.encode_data(test_data, &mut encoded).unwrap();
        let encoded_str = String::from_utf8(encoded).unwrap();
        
        let decoded = efficient_cipher.decode_data(&encoded_str).unwrap();
        assert_eq!(test_data.to_vec(), decoded);
        
        println!("   ✓ {:?} file type test passed", file_type);
    }
    
    println!("=== FILE TYPE INTEGRATION TEST PASSED! ===");
}

/// Integration test for large data handling
#[test]
fn test_large_data_integration() {
    println!("=== LARGE DATA INTEGRATION TEST ===");
    
    // Test with 1MB of data
    let large_data = b"Large data test for PurrCrypt integration. ".repeat(25000);
    println!("Testing with {} bytes of data", large_data.len());
    
    // Test steganographic RP with large data
    let rp_cipher = SteganographicRPCipher::new(PetDialect::Kitty, PetPersonality::Chatty);
    let mut rp_encoded = Vec::new();
    rp_cipher.encode_data(&large_data, &mut rp_encoded).unwrap();
    let rp_encoded_str = String::from_utf8(rp_encoded).unwrap();
    
    let rp_decoded = rp_cipher.decode_data(&rp_encoded_str).unwrap();
    assert_eq!(large_data, rp_decoded);
    println!("   ✓ Steganographic RP large data test passed");
    
    // Test efficient cipher with large data
    let efficient_cipher = EfficientPetCipher::new(EfficientPetDialect::Kitty);
    let mut efficient_encoded = Vec::new();
    efficient_cipher.encode_data(&large_data, &mut efficient_encoded).unwrap();
    let efficient_encoded_str = String::from_utf8(efficient_encoded).unwrap();
    
    let efficient_decoded = efficient_cipher.decode_data(&efficient_encoded_str).unwrap();
    assert_eq!(large_data, efficient_decoded);
    println!("   ✓ Efficient cipher large data test passed");
    
    // Test compression with large data
    let compressor = SmartCompressor::new();
    let compressed = compressor.compress(&large_data).unwrap();
    let decompressed = compressor.decompress(&compressed).unwrap();
    assert_eq!(large_data, decompressed);
    println!("   ✓ Compression large data test passed");
    
    println!("=== LARGE DATA INTEGRATION TEST PASSED! ===");
}

/// Integration test for Unicode data handling
#[test]
fn test_unicode_integration() {
    println!("=== UNICODE INTEGRATION TEST ===");
    
    let unicode_data = "Hello 世界! 🌍 Nyaa~ >w< 量子加密测试 🐱🐶💕✨🎉🚀".as_bytes();
    println!("Testing with Unicode data: {} bytes", unicode_data.len());
    
    // Test steganographic RP with Unicode data
    let rp_cipher = SteganographicRPCipher::new(PetDialect::Kitty, PetPersonality::Chatty);
    let mut rp_encoded = Vec::new();
    rp_cipher.encode_data(unicode_data, &mut rp_encoded).unwrap();
    let rp_encoded_str = String::from_utf8(rp_encoded).unwrap();
    
    let rp_decoded = rp_cipher.decode_data(&rp_encoded_str).unwrap();
    assert_eq!(unicode_data, &rp_decoded);
    println!("   ✓ Steganographic RP Unicode test passed");
    
    // Test efficient cipher with Unicode data
    let efficient_cipher = EfficientPetCipher::new(EfficientPetDialect::Kitty);
    let mut efficient_encoded = Vec::new();
    efficient_cipher.encode_data(unicode_data, &mut efficient_encoded).unwrap();
    let efficient_encoded_str = String::from_utf8(efficient_encoded).unwrap();
    
    let efficient_decoded = efficient_cipher.decode_data(&efficient_encoded_str).unwrap();
    assert_eq!(unicode_data, &efficient_decoded);
    println!("   ✓ Efficient cipher Unicode test passed");
    
    // Test compression with Unicode data
    let compressor = SmartCompressor::new();
    let compressed = compressor.compress(unicode_data).unwrap();
    let decompressed = compressor.decompress(&compressed).unwrap();
    assert_eq!(unicode_data, &decompressed);
    println!("   ✓ Compression Unicode test passed");
    
    println!("=== UNICODE INTEGRATION TEST PASSED! ===");
}

/// Integration test for error handling
#[test]
fn test_error_handling_integration() {
    println!("=== ERROR HANDLING INTEGRATION TEST ===");
    
    // Test with corrupted data
    let _test_data = b"Test data for error handling";
    let rp_cipher = SteganographicRPCipher::new(PetDialect::Kitty, PetPersonality::Chatty);
    
    // Test with invalid RP data
    let invalid_rp_data = "This is not valid steganographic RP data";
    let result = rp_cipher.decode_data(invalid_rp_data);
    assert!(result.is_err());
    println!("   ✓ Invalid RP data handling test passed");
    
    // Test with empty data
    let empty_data = b"";
    let mut encoded = Vec::new();
    rp_cipher.encode_data(empty_data, &mut encoded).unwrap();
    let encoded_str = String::from_utf8(encoded).unwrap();
    let decoded = rp_cipher.decode_data(&encoded_str).unwrap();
    assert_eq!(empty_data.to_vec(), decoded);
    println!("   ✓ Empty data handling test passed");
    
    // Test with single byte data
    let single_byte = b"A";
    let mut encoded = Vec::new();
    rp_cipher.encode_data(single_byte, &mut encoded).unwrap();
    let encoded_str = String::from_utf8(encoded).unwrap();
    let decoded = rp_cipher.decode_data(&encoded_str).unwrap();
    assert_eq!(single_byte.to_vec(), decoded);
    println!("   ✓ Single byte data handling test passed");
    
    println!("=== ERROR HANDLING INTEGRATION TEST PASSED! ===");
}

/// Integration test for performance characteristics
#[test]
fn test_performance_integration() {
    println!("=== PERFORMANCE INTEGRATION TEST ===");
    
    let test_data = b"Performance test data for PurrCrypt integration testing. ".repeat(1000);
    println!("Testing with {} bytes of data", test_data.len());
    
    // Test steganographic RP performance
    let rp_cipher = SteganographicRPCipher::new(PetDialect::Kitty, PetPersonality::Chatty);
    let start = std::time::Instant::now();
    
    let mut rp_encoded = Vec::new();
    rp_cipher.encode_data(&test_data, &mut rp_encoded).unwrap();
    let rp_encoded_str = String::from_utf8(rp_encoded).unwrap();
    let rp_encode_time = start.elapsed();
    
    let start = std::time::Instant::now();
    let rp_decoded = rp_cipher.decode_data(&rp_encoded_str).unwrap();
    let rp_decode_time = start.elapsed();
    
    assert_eq!(test_data.to_vec(), rp_decoded);
    println!("   ✓ Steganographic RP performance test passed");
    println!("     Encode time: {:?}, Decode time: {:?}", rp_encode_time, rp_decode_time);
    println!("     Expansion ratio: {:.2}x", rp_encoded_str.len() as f64 / test_data.len() as f64);
    
    // Test efficient cipher performance
    let efficient_cipher = EfficientPetCipher::new(EfficientPetDialect::Kitty);
    let start = std::time::Instant::now();
    
    let mut efficient_encoded = Vec::new();
    efficient_cipher.encode_data(&test_data, &mut efficient_encoded).unwrap();
    let efficient_encoded_str = String::from_utf8(efficient_encoded).unwrap();
    let efficient_encode_time = start.elapsed();
    
    let start = std::time::Instant::now();
    let efficient_decoded = efficient_cipher.decode_data(&efficient_encoded_str).unwrap();
    let efficient_decode_time = start.elapsed();
    
    assert_eq!(test_data, efficient_decoded);
    println!("   ✓ Efficient cipher performance test passed");
    println!("     Encode time: {:?}, Decode time: {:?}", efficient_encode_time, efficient_decode_time);
    println!("     Expansion ratio: {:.2}x", efficient_encoded_str.len() as f64 / test_data.len() as f64);
    
    // Test compression performance
    let compressor = SmartCompressor::new();
    let start = std::time::Instant::now();
    
    let compressed = compressor.compress(&test_data).unwrap();
    let compress_time = start.elapsed();
    
    let start = std::time::Instant::now();
    let decompressed = compressor.decompress(&compressed).unwrap();
    let decompress_time = start.elapsed();
    
    assert_eq!(test_data, decompressed);
    println!("   ✓ Compression performance test passed");
    println!("     Compress time: {:?}, Decompress time: {:?}", compress_time, decompress_time);
    println!("     Compression ratio: {:.2}x", compressed.len() as f64 / test_data.len() as f64);
    
    println!("=== PERFORMANCE INTEGRATION TEST PASSED! ===");
}

/// Integration test for CLI functionality
#[test]
fn test_cli_integration() {
    println!("=== CLI INTEGRATION TEST ===");
    
    // This test would require the CLI binary to be built
    // For now, we'll test the core functionality that the CLI uses
    
    let test_data = b"CLI integration test data";
    
    // Test key generation
    let keypair = HybridKeyPair::new().unwrap();
    println!("   ✓ Key generation test passed");
    
    // Test encryption/decryption
    let encrypted_message = SecureMessage::encrypt(
        test_data,
        &keypair.ecdh_public,
        &keypair.kyber_public,
    ).unwrap();
    
    let decrypted_data = encrypted_message.decrypt(
        &keypair.ecdh_secret,
        &keypair.kyber_secret,
    ).unwrap();
    
    assert_eq!(test_data.to_vec(), decrypted_data);
    println!("   ✓ Encryption/decryption test passed");
    
    // Test steganographic RP encoding/decoding
    let rp_cipher = SteganographicRPCipher::new(PetDialect::Kitty, PetPersonality::Chatty);
    let mut rp_encoded = Vec::new();
    rp_cipher.encode_data(test_data, &mut rp_encoded).unwrap();
    let rp_encoded_str = String::from_utf8(rp_encoded).unwrap();
    
    let rp_decoded = rp_cipher.decode_data(&rp_encoded_str).unwrap();
    assert_eq!(test_data.to_vec(), rp_decoded);
    println!("   ✓ Steganographic RP encoding/decoding test passed");
    
    println!("=== CLI INTEGRATION TEST PASSED! ===");
}
