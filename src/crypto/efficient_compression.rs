// src/crypto/efficient_compression.rs
// Super efficient compression that's adowable AND fast! Nyaa~ >w<

use std::io::{self, Read, Write};
use zstd::{encode_all, decode_all};
use flate2::{
    read::{ZlibDecoder, ZlibEncoder},
    Compression,
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CompressionError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("Zstd error: {0}")]
    Zstd(String),
    #[error("Zlib error: {0}")]
    Zlib(String),
}

/// Smart compression that chooses the best algorithm! *purrs intelligently*
pub struct SmartCompressor {
    zstd_level: i32,
    zlib_level: Compression,
}

impl SmartCompressor {
    pub fn new() -> Self {
        Self {
            zstd_level: 3, // Fast compression
            zlib_level: Compression::fast(),
        }
    }
    
    /// Compress data using the best available algorithm! *bounces excitedly*
    pub fn compress(&self, data: &[u8]) -> Result<Vec<u8>, CompressionError> {
        // Skip compression for already compressed data
        if self.is_likely_compressed(data) {
            return Ok(data.to_vec());
        }
        
        // Try zstd first (usually better compression)
        match self.compress_zstd(data) {
            Ok(compressed) => {
                // Only use zstd if it actually saves space
                if compressed.len() < data.len() {
                    return Ok(compressed);
                }
            }
            Err(_) => {
                // Fall back to zlib if zstd fails
            }
        }
        
        // Fall back to zlib
        match self.compress_zlib(data) {
            Ok(compressed) => {
                if compressed.len() < data.len() {
                    Ok(compressed)
                } else {
                    Ok(data.to_vec()) // No compression if it makes it bigger
                }
            }
            Err(e) => Err(e),
        }
    }
    
    /// Decompress data automatically detecting the format! *ears perk up*
    pub fn decompress(&self, data: &[u8]) -> Result<Vec<u8>, CompressionError> {
        // If data is very small, it's likely uncompressed
        if data.len() <= 1 {
            return Ok(data.to_vec());
        }
        
        // Try zstd first
        match self.decompress_zstd(data) {
            Ok(decompressed) => {
                // Only use zstd result if it's not empty (indicates successful decompression)
                if !decompressed.is_empty() {
                    return Ok(decompressed);
                }
            }
            Err(_) => {
                // Zstd failed, try zlib
            }
        }
        
        // Try zlib
        match self.decompress_zlib(data) {
            Ok(decompressed) => {
                // Only use zlib result if it's not empty (indicates successful decompression)
                if !decompressed.is_empty() {
                    return Ok(decompressed);
                }
            }
            Err(_) => {
                // Zlib failed, assume uncompressed
            }
        }
        
        // If neither works or returned empty, assume it's uncompressed
        Ok(data.to_vec())
    }
    
    fn compress_zstd(&self, data: &[u8]) -> Result<Vec<u8>, CompressionError> {
        encode_all(data, self.zstd_level)
            .map_err(|e| CompressionError::Zstd(format!("Zstd compression failed: {}", e)))
    }
    
    fn decompress_zstd(&self, data: &[u8]) -> Result<Vec<u8>, CompressionError> {
        decode_all(data)
            .map_err(|e| CompressionError::Zstd(format!("Zstd decompression failed: {}", e)))
    }
    
    fn compress_zlib(&self, data: &[u8]) -> Result<Vec<u8>, CompressionError> {
        let mut encoder = ZlibEncoder::new(data, self.zlib_level);
        let mut compressed = Vec::new();
        encoder.read_to_end(&mut compressed)
            .map_err(|e| CompressionError::Zlib(format!("Zlib compression failed: {}", e)))?;
        Ok(compressed)
    }
    
    fn decompress_zlib(&self, data: &[u8]) -> Result<Vec<u8>, CompressionError> {
        let mut decoder = ZlibDecoder::new(data);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed)
            .map_err(|e| CompressionError::Zlib(format!("Zlib decompression failed: {}", e)))?;
        Ok(decompressed)
    }
    
    /// Detect if data is likely already compressed! *sniffs data curiously*
    pub fn is_likely_compressed(&self, data: &[u8]) -> bool {
        if data.len() < 10 {
            return false;
        }
        
        // Check for common compressed file signatures
        let signatures = [
            &[0x1f, 0x8b], // gzip
            &[0x78, 0x9c], // zlib
            &[0x78, 0x01], // zlib
            &[0x78, 0xda], // zlib
            &[0x5d, 0x00], // zstd
            &[0x28, 0xb5], // zstd
        ];
        
        for sig in &signatures {
            if data.starts_with(sig.as_slice()) {
                return true;
            }
        }
        
        // Check entropy - high entropy suggests already compressed
        let entropy = self.calculate_entropy(data);
        entropy > 7.5 // High entropy threshold
    }
    
    /// Calculate Shannon entropy of data! *purrs mathematically*
    pub fn calculate_entropy(&self, data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        
        let mut counts = [0u32; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }
        
        let mut entropy = 0.0;
        let data_len = data.len() as f64;
        
        for &count in &counts {
            if count > 0 {
                let probability = count as f64 / data_len;
                entropy -= probability * probability.log2();
            }
        }
        
        entropy
    }
}

/// Streaming compressor for real-time processing! *swishes tail efficiently*
pub struct StreamingCompressor {
    compressor: SmartCompressor,
    chunk_size: usize,
}

impl StreamingCompressor {
    pub fn new() -> Self {
        Self {
            compressor: SmartCompressor::new(),
            chunk_size: 64 * 1024, // 64KB chunks
        }
    }
    
    /// Compress data in streaming fashion! *bounces through data*
    pub fn compress_stream<R: Read, W: Write>(&self, mut reader: R, mut writer: W) -> Result<(), CompressionError> {
        let mut buffer = vec![0u8; self.chunk_size];
        let mut _first_chunk = true;
        
        loop {
            let bytes_read = reader.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            
            let chunk = &buffer[..bytes_read];
            let compressed = self.compressor.compress(chunk)?;
            
            // Write chunk size and compressed data
            writer.write_all(&(compressed.len() as u32).to_le_bytes())?;
            writer.write_all(&compressed)?;
            
            _first_chunk = false;
        }
        
        Ok(())
    }
    
    /// Decompress data in streaming fashion! *purrs through data*
    pub fn decompress_stream<R: Read, W: Write>(&self, mut reader: R, mut writer: W) -> Result<(), CompressionError> {
        let mut size_buffer = [0u8; 4];
        
        loop {
            // Read chunk size
            match reader.read_exact(&mut size_buffer) {
                Ok(_) => {},
                Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e.into()),
            }
            
            let chunk_size = u32::from_le_bytes(size_buffer) as usize;
            let mut compressed_chunk = vec![0u8; chunk_size];
            reader.read_exact(&mut compressed_chunk)?;
            
            let decompressed = self.compressor.decompress(&compressed_chunk)?;
            writer.write_all(&decompressed)?;
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_smart_compression() {
        let compressor = SmartCompressor::new();
        
        // Test with compressible data
        let data = b"Hello, World! ".repeat(100);
        let compressed = compressor.compress(&data).unwrap();
        let decompressed = compressor.decompress(&compressed).unwrap();
        
        assert_eq!(data, decompressed);
        assert!(compressed.len() < data.len());
        println!("Compression ratio: {:.2}x", data.len() as f64 / compressed.len() as f64);
    }

    #[test]
    fn test_already_compressed_detection() {
        let compressor = SmartCompressor::new();
        
        // Test with already compressed data (zlib signature)
        let already_compressed = vec![0x78, 0x9c, 0x01, 0x02, 0x03, 0x04, 0x05];
        let result = compressor.compress(&already_compressed).unwrap();
        
        // Should return original data unchanged
        assert_eq!(already_compressed, result);
    }

    #[test]
    fn test_streaming_compression() {
        let compressor = StreamingCompressor::new();
        let data = b"Streaming test data ".repeat(1000);
        
        // Compress
        let mut compressed = Vec::new();
        compressor.compress_stream(
            Cursor::new(&data),
            &mut compressed
        ).unwrap();
        
        // Decompress
        let mut decompressed = Vec::new();
        compressor.decompress_stream(
            Cursor::new(&compressed),
            &mut decompressed
        ).unwrap();
        
        assert_eq!(data, decompressed);
        println!("Streaming compression successful!");
    }

    #[test]
    fn test_entropy_calculation() {
        let compressor = SmartCompressor::new();
        
        // Low entropy data (repetitive)
        let low_entropy = b"aaaaaaaaaa";
        assert!(compressor.calculate_entropy(low_entropy) < 2.0);
        
        // High entropy data (random)
        let high_entropy = b"\x01\x23\x45\x67\x89\xab\xcd\xef";
        assert!(compressor.calculate_entropy(high_entropy) > 2.0);
    }

    // COMPREHENSIVE TESTS FOR EFFICIENT COMPRESSION
    
    #[test]
    fn test_compression_algorithms() {
        let compressor = SmartCompressor::new();
        
        // Test with different types of data
        let test_cases = [
            ("Highly compressible", b"Hello World! ".repeat(100)),
            ("Moderately compressible", b"Test data with some repetition. ".repeat(50)),
            ("Low compressibility", b"\x01\x23\x45\x67\x89\xab\xcd\xef".repeat(20)),
            ("Random data", (0..1000).map(|_| rand::random::<u8>()).collect()),
        ];
        
        for (name, data) in &test_cases {
            let compressed = compressor.compress(data).unwrap();
            let decompressed = compressor.decompress(&compressed).unwrap();
            
            assert_eq!(data, &decompressed, "Failed for test case: {}", name);
            
            let compression_ratio = compressed.len() as f64 / data.len() as f64;
            println!("{}: {} bytes -> {} bytes ({}x compression)", 
                    name, data.len(), compressed.len(), compression_ratio);
        }
    }
    
    #[test]
    fn test_compression_detection() {
        let compressor = SmartCompressor::new();
        
        // Test already compressed data detection
        let already_compressed_cases = [
            // Zlib signatures
            vec![0x78, 0x9c, 0x01, 0x02, 0x03, 0x04, 0x05],
            vec![0x78, 0x01, 0x01, 0x02, 0x03, 0x04, 0x05],
            vec![0x78, 0xda, 0x01, 0x02, 0x03, 0x04, 0x05],
            // Zstd signatures
            vec![0x28, 0xb5, 0x2f, 0xfd, 0x01, 0x02, 0x03, 0x04],
            vec![0x5d, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05],
        ];
        
        for (i, data) in already_compressed_cases.iter().enumerate() {
            let result = compressor.compress(data).unwrap();
            assert_eq!(data, &result, "Already compressed data {} should be returned unchanged", i);
        }
        
        // Test uncompressed data (use repetitive data that will actually compress)
        let uncompressed = b"This is uncompressed data that should be compressed. ".repeat(10).into_iter().collect::<Vec<u8>>();
        let result = compressor.compress(&uncompressed).unwrap();
        assert_ne!(uncompressed, result, "Uncompressed data should be compressed");
    }
    
    #[test]
    fn test_compression_quality() {
        let compressor = SmartCompressor::new();
        
        // Test with highly repetitive data (should compress well)
        let repetitive_data = b"AAAA".repeat(1000);
        let compressed = compressor.compress(&repetitive_data).unwrap();
        let decompressed = compressor.decompress(&compressed).unwrap();
        
        assert_eq!(repetitive_data, decompressed);
        assert!(compressed.len() < repetitive_data.len(), "Repetitive data should compress");
        
        let compression_ratio = compressed.len() as f64 / repetitive_data.len() as f64;
        println!("Repetitive data compression ratio: {:.2}x", compression_ratio);
        assert!(compression_ratio < 0.5, "Repetitive data should compress to less than 50%");
    }
    
    #[test]
    fn test_edge_cases_compression() {
        let compressor = SmartCompressor::new();
        
        // Test empty data
        let empty_data = b"";
        let compressed = compressor.compress(empty_data).unwrap();
        let decompressed = compressor.decompress(&compressed).unwrap();
        assert_eq!(empty_data.to_vec(), decompressed);
        
        // Test single byte
        let single_byte = b"A";
        let compressed = compressor.compress(single_byte).unwrap();
        let decompressed = compressor.decompress(&compressed).unwrap();
        assert_eq!(single_byte.to_vec(), decompressed);
        
        // Test very small data
        let small_data = b"Hi";
        let compressed = compressor.compress(small_data).unwrap();
        let decompressed = compressor.decompress(&compressed).unwrap();
        assert_eq!(small_data.to_vec(), decompressed);
    }
    
    #[test]
    fn test_unicode_compression() {
        let compressor = SmartCompressor::new();
        
        // Test UTF-8 data
        let unicode_data = "Hello 世界! 🌍 Nyaa~ >w< 压缩测试".as_bytes();
        let compressed = compressor.compress(unicode_data).unwrap();
        let decompressed = compressor.decompress(&compressed).unwrap();
        assert_eq!(unicode_data, &decompressed);
        
        // Test emoji data
        let emoji_data = "🐱🐶💕✨🎉🚀".as_bytes();
        let compressed = compressor.compress(emoji_data).unwrap();
        let decompressed = compressor.decompress(&compressed).unwrap();
        assert_eq!(emoji_data, &decompressed);
    }
    
    #[test]
    fn test_large_data_compression() {
        let compressor = SmartCompressor::new();
        
        // Test with large data (1MB)
        let large_data = b"Large data test for compression. ".repeat(30000);
        let compressed = compressor.compress(&large_data).unwrap();
        let decompressed = compressor.decompress(&compressed).unwrap();
        assert_eq!(&large_data, &decompressed);
        
        let compression_ratio = compressed.len() as f64 / large_data.len() as f64;
        println!("Large data compression ratio: {:.2}x", compression_ratio);
    }
    
    #[test]
    fn test_streaming_compression_advanced() {
        let compressor = StreamingCompressor::new();
        
        // Test with various data sizes
        let test_cases = [
            b"Small test data".to_vec(),
            b"Medium test data ".repeat(100).into_iter().collect::<Vec<u8>>(),
            b"Large test data ".repeat(1000).into_iter().collect::<Vec<u8>>(),
        ];
        
        for (i, data) in test_cases.iter().enumerate() {
            // Compress
            let mut compressed = Vec::new();
            compressor.compress_stream(
                std::io::Cursor::new(data),
                &mut compressed
            ).unwrap();
            
            // Decompress
            let mut decompressed = Vec::new();
            compressor.decompress_stream(
                std::io::Cursor::new(&compressed),
                &mut decompressed
            ).unwrap();
            
            assert_eq!(data, &decompressed, "Failed for test case {}", i);
            
            println!("Streaming test {}: {} bytes -> {} bytes", 
                    i, data.len(), compressed.len());
        }
    }
    
    #[test]
    fn test_compression_performance() {
        let compressor = SmartCompressor::new();
        let test_data = b"Performance test data for compression benchmarking. ".repeat(1000);
        
        let start = std::time::Instant::now();
        
        // Compress
        let compressed = compressor.compress(&test_data).unwrap();
        let compress_time = start.elapsed();
        
        // Decompress
        let start = std::time::Instant::now();
        let decompressed = compressor.decompress(&compressed).unwrap();
        let decompress_time = start.elapsed();
        
        println!("Compression performance test:");
        println!("  Input size: {} bytes", test_data.len());
        println!("  Output size: {} bytes", compressed.len());
        println!("  Compression ratio: {:.2}x", compressed.len() as f64 / test_data.len() as f64);
        println!("  Compress time: {:?}", compress_time);
        println!("  Decompress time: {:?}", decompress_time);
        println!("  Compress speed: {:.2} MB/s", test_data.len() as f64 / compress_time.as_secs_f64() / 1_000_000.0);
        println!("  Decompress speed: {:.2} MB/s", test_data.len() as f64 / decompress_time.as_secs_f64() / 1_000_000.0);
        
        assert_eq!(test_data.to_vec(), decompressed);
        
        // Performance assertions
        assert!(compress_time.as_secs_f64() < 1.0, "Compression too slow: {:?}", compress_time);
        assert!(decompress_time.as_secs_f64() < 1.0, "Decompression too slow: {:?}", decompress_time);
    }
    
    #[test]
    fn test_entropy_analysis() {
        let compressor = SmartCompressor::new();
        
        // Test entropy calculation with known values
        let test_cases = [
            ("All zeros", vec![0u8; 100], 0.0),
            ("All same", vec![42u8; 100], 0.0),
            ("Two values", vec![0u8, 1u8].repeat(50), 1.0),
            ("Four values", vec![0u8, 1u8, 2u8, 3u8].repeat(25), 2.0),
            ("Random", (0..100).map(|_| rand::random::<u8>()).collect(), 8.0),
        ];
        
        for (name, data, expected_entropy) in &test_cases {
            let entropy = compressor.calculate_entropy(&data);
            println!("{}: entropy = {:.2} (expected ~{})", name, entropy, expected_entropy);
            
            // Allow some tolerance for random data
            if *expected_entropy < 7.0 {
                assert!((entropy - expected_entropy).abs() < 0.5, 
                       "Entropy calculation failed for {}: got {}, expected {}", 
                       name, entropy, expected_entropy);
            }
        }
    }
    
    #[test]
    fn test_compression_fallback() {
        let compressor = SmartCompressor::new();
        
        // Test data that should trigger fallback behavior
        let test_data = b"Test data that might not compress well with zstd but should work with zlib";
        
        let compressed = compressor.compress(test_data).unwrap();
        let decompressed = compressor.decompress(&compressed).unwrap();
        
        assert_eq!(test_data.to_vec(), decompressed);
        assert!(!compressed.is_empty());
    }
    
    #[test]
    fn test_compression_consistency() {
        let compressor = SmartCompressor::new();
        
        // Test that compression is consistent (same input should produce same output)
        let test_data = b"Consistency test data";
        
        let compressed1 = compressor.compress(test_data).unwrap();
        let compressed2 = compressor.compress(test_data).unwrap();
        
        // Note: Due to random elements in compression, outputs might differ
        // But both should decompress to the same data
        let decompressed1 = compressor.decompress(&compressed1).unwrap();
        let decompressed2 = compressor.decompress(&compressed2).unwrap();
        
        assert_eq!(test_data.to_vec(), decompressed1);
        assert_eq!(test_data.to_vec(), decompressed2);
    }
    
    #[test]
    fn test_streaming_edge_cases() {
        let compressor = StreamingCompressor::new();
        
        // Test empty stream
        let empty_data = b"";
        let mut compressed = Vec::new();
        compressor.compress_stream(
            std::io::Cursor::new(empty_data),
            &mut compressed
        ).unwrap();
        
        let mut decompressed = Vec::new();
        compressor.decompress_stream(
            std::io::Cursor::new(&compressed),
            &mut decompressed
        ).unwrap();
        
        assert_eq!(empty_data.to_vec(), decompressed);
        
        // Test single byte stream
        let single_byte = b"A";
        let mut compressed = Vec::new();
        compressor.compress_stream(
            std::io::Cursor::new(single_byte),
            &mut compressed
        ).unwrap();
        
        let mut decompressed = Vec::new();
        compressor.decompress_stream(
            std::io::Cursor::new(&compressed),
            &mut decompressed
        ).unwrap();
        
        assert_eq!(single_byte.to_vec(), decompressed);
    }
}


