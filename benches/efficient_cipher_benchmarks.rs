use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use std::hint::black_box;
use purrcrypt::cipher::efficient::{EfficientPetCipher, PetDialect, FileType, EmotionalContext};

fn bench_encoding(c: &mut Criterion) {
    let mut group = c.benchmark_group("efficient_cipher_encoding");
    
    let test_data_sizes = [100, 1000, 10000, 100000];
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
    
    for size in test_data_sizes {
        let data = vec![0x42u8; size];
        
        for context in &contexts {
            let cipher = EfficientPetCipher::new_with_context(PetDialect::Kitty, FileType::Unknown, *context);
            
            group.bench_with_input(
                BenchmarkId::new("encode", format!("{}_bytes_{:?}", size, context)),
                &data,
                |b, data| {
                    b.iter(|| {
                        let mut output = Vec::new();
                        cipher.encode_data(black_box(data), &mut output).unwrap();
                        black_box(output)
                    })
                },
            );
        }
    }
    
    group.finish();
}

fn bench_decoding(c: &mut Criterion) {
    let mut group = c.benchmark_group("efficient_cipher_decoding");
    
    let test_data_sizes = [100, 1000, 10000, 100000];
    let contexts = [
        EmotionalContext::Content,
        EmotionalContext::Excited,
        EmotionalContext::Calm,
        EmotionalContext::Playful,
    ];
    
    for size in test_data_sizes {
        let data = vec![0x42u8; size];
        
        for context in &contexts {
            let cipher = EfficientPetCipher::new_with_context(PetDialect::Kitty, FileType::Unknown, *context);
            
            // Pre-encode the data
            let mut encoded = Vec::new();
            cipher.encode_data(&data, &mut encoded).unwrap();
            let encoded_str = String::from_utf8(encoded).unwrap();
            
            group.bench_with_input(
                BenchmarkId::new("decode", format!("{}_bytes_{:?}", size, context)),
                &encoded_str,
                |b, encoded_str| {
                    b.iter(|| {
                        cipher.decode_data(black_box(encoded_str)).unwrap()
                    })
                },
            );
        }
    }
    
    group.finish();
}

fn bench_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("efficient_cipher_roundtrip");
    
    let test_data_sizes = [100, 1000, 10000, 100000];
    let contexts = [
        EmotionalContext::Content,
        EmotionalContext::Excited,
        EmotionalContext::Calm,
        EmotionalContext::Playful,
    ];
    
    for size in test_data_sizes {
        let data = vec![0x42u8; size];
        
        for context in &contexts {
            let cipher = EfficientPetCipher::new_with_context(PetDialect::Kitty, FileType::Unknown, *context);
            
            group.bench_with_input(
                BenchmarkId::new("roundtrip", format!("{}_bytes_{:?}", size, context)),
                &data,
                |b, data| {
                    b.iter(|| {
                        let mut encoded = Vec::new();
                        cipher.encode_data(black_box(data), &mut encoded).unwrap();
                        let encoded_str = String::from_utf8(encoded).unwrap();
                        let decoded = cipher.decode_data(&encoded_str).unwrap();
                        black_box(decoded)
                    })
                },
            );
        }
    }
    
    group.finish();
}

fn bench_file_type_encoding(c: &mut Criterion) {
    let mut group = c.benchmark_group("efficient_cipher_file_type_encoding");
    
    let data = vec![0x42u8; 1000];
    let file_types = [
        FileType::Text,
        FileType::Image,
        FileType::Video,
        FileType::Audio,
        FileType::Data,
        FileType::Unknown,
    ];
    
    for file_type in &file_types {
        let cipher = EfficientPetCipher::new_with_context(PetDialect::Kitty, *file_type, EmotionalContext::Calm);
        
        group.bench_with_input(
            BenchmarkId::new("encode", format!("{:?}", file_type)),
            &data,
            |b, data| {
                b.iter(|| {
                    let mut output = Vec::new();
                    cipher.encode_data(black_box(data), &mut output).unwrap();
                    black_box(output)
                })
            },
        );
    }
    
    group.finish();
}

fn bench_dialect_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("efficient_cipher_dialect_comparison");
    
    let data = vec![0x42u8; 1000];
    let dialects = [PetDialect::Kitty, PetDialect::Puppy];
    let contexts = [EmotionalContext::Content, EmotionalContext::Excited];
    
    for dialect in &dialects {
        for context in &contexts {
            let cipher = EfficientPetCipher::new_with_context(*dialect, FileType::Unknown, *context);
            
            group.bench_with_input(
                BenchmarkId::new("encode", format!("{:?}_{:?}", dialect, context)),
                &data,
                |b, data| {
                    b.iter(|| {
                        let mut output = Vec::new();
                        cipher.encode_data(black_box(data), &mut output).unwrap();
                        black_box(output)
                    })
                },
            );
        }
    }
    
    group.finish();
}

fn bench_compression_ratio(c: &mut Criterion) {
    let mut group = c.benchmark_group("efficient_cipher_compression_ratio");
    
    let test_cases = [
        ("repetitive", vec![0x41u8; 1000]),
        ("alternating", (0..1000).map(|i| if i % 2 == 0 { 0x41 } else { 0x42 }).collect()),
        ("random", (0..1000).map(|_| rand::random::<u8>()).collect()),
        ("text", b"Hello World! This is a test message for compression ratio testing. ".repeat(20).into_iter().collect::<Vec<u8>>()),
    ];
    
    for (name, data) in test_cases {
        let cipher = EfficientPetCipher::new(PetDialect::Kitty);
        
        group.bench_with_input(
            BenchmarkId::new("compression_ratio", name),
            &data,
            |b, data| {
                b.iter(|| {
                    let mut encoded = Vec::new();
                    cipher.encode_data(black_box(data), &mut encoded).unwrap();
                    let encoded_str = String::from_utf8(encoded).unwrap();
                    let ratio = encoded_str.len() as f64 / data.len() as f64;
                    black_box(ratio)
                })
            },
        );
    }
    
    group.finish();
}

criterion_group!(
    benches,
    bench_encoding,
    bench_decoding,
    bench_roundtrip,
    bench_file_type_encoding,
    bench_dialect_comparison,
    bench_compression_ratio
);
criterion_main!(benches);


