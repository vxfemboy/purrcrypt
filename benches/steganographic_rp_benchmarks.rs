use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use std::hint::black_box;
use purrcrypt::cipher::steganographic_rp::{SteganographicRPCipher, PetDialect, PetPersonality};

fn bench_encoding(c: &mut Criterion) {
    let mut group = c.benchmark_group("steganographic_rp_encoding");
    
    let test_data_sizes = [100, 1000, 10000, 100000];
    let personalities = [
        PetPersonality::Chatty,
        PetPersonality::Excited,
        PetPersonality::Musical,
        PetPersonality::Playful,
        PetPersonality::Curious,
        PetPersonality::Sleepy,
    ];
    
    for size in test_data_sizes {
        let data = vec![0x42u8; size];
        
        for personality in &personalities {
            let cipher = SteganographicRPCipher::new(PetDialect::Kitty, *personality);
            
            group.bench_with_input(
                BenchmarkId::new("encode", format!("{}_bytes_{:?}", size, personality)),
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
    let mut group = c.benchmark_group("steganographic_rp_decoding");
    
    let test_data_sizes = [100, 1000, 10000, 100000];
    let personalities = [
        PetPersonality::Chatty,
        PetPersonality::Excited,
        PetPersonality::Musical,
        PetPersonality::Playful,
        PetPersonality::Curious,
        PetPersonality::Sleepy,
    ];
    
    for size in test_data_sizes {
        let data = vec![0x42u8; size];
        
        for personality in &personalities {
            let cipher = SteganographicRPCipher::new(PetDialect::Kitty, *personality);
            
            // Pre-encode the data
            let mut encoded = Vec::new();
            cipher.encode_data(&data, &mut encoded).unwrap();
            let encoded_str = String::from_utf8(encoded).unwrap();
            
            group.bench_with_input(
                BenchmarkId::new("decode", format!("{}_bytes_{:?}", size, personality)),
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
    let mut group = c.benchmark_group("steganographic_rp_roundtrip");
    
    let test_data_sizes = [100, 1000, 10000, 100000];
    let personalities = [
        PetPersonality::Chatty,
        PetPersonality::Excited,
        PetPersonality::Musical,
        PetPersonality::Playful,
        PetPersonality::Curious,
        PetPersonality::Sleepy,
    ];
    
    for size in test_data_sizes {
        let data = vec![0x42u8; size];
        
        for personality in &personalities {
            let cipher = SteganographicRPCipher::new(PetDialect::Kitty, *personality);
            
            group.bench_with_input(
                BenchmarkId::new("roundtrip", format!("{}_bytes_{:?}", size, personality)),
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

fn bench_compression_ratio(c: &mut Criterion) {
    let mut group = c.benchmark_group("steganographic_rp_compression_ratio");
    
    let test_cases = [
        ("repetitive", vec![0x41u8; 1000]),
        ("alternating", (0..1000).map(|i| if i % 2 == 0 { 0x41 } else { 0x42 }).collect()),
        ("random", (0..1000).map(|_| rand::random::<u8>()).collect()),
        ("text", b"Hello World! This is a test message for compression ratio testing. ".repeat(20).into_iter().collect::<Vec<u8>>()),
    ];
    
    for (name, data) in test_cases {
        let cipher = SteganographicRPCipher::new(PetDialect::Kitty, PetPersonality::Chatty);
        
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

fn bench_dialect_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("steganographic_rp_dialect_comparison");
    
    let data = vec![0x42u8; 1000];
    let dialects = [PetDialect::Kitty, PetDialect::Puppy];
    let personalities = [PetPersonality::Chatty, PetPersonality::Excited];
    
    for dialect in &dialects {
        for personality in &personalities {
            let cipher = SteganographicRPCipher::new(*dialect, *personality);
            
            group.bench_with_input(
                BenchmarkId::new("encode", format!("{:?}_{:?}", dialect, personality)),
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

criterion_group!(
    benches,
    bench_encoding,
    bench_decoding,
    bench_roundtrip,
    bench_compression_ratio,
    bench_dialect_comparison
);
criterion_main!(benches);
