use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use purrcrypt::crypto::efficient_compression::{SmartCompressor, StreamingCompressor};
use std::hint::black_box;

fn bench_compression(c: &mut Criterion) {
    let mut group = c.benchmark_group("compression");

    let test_data_sizes = [100, 1000, 10000, 100000, 1000000];
    let compressor = SmartCompressor::new();

    for size in test_data_sizes {
        let data = vec![0x42u8; size];

        group.bench_with_input(
            BenchmarkId::new("compress", format!("{}_bytes", size)),
            &data,
            |b, data| b.iter(|| compressor.compress(black_box(data)).unwrap()),
        );
    }

    group.finish();
}

fn bench_decompression(c: &mut Criterion) {
    let mut group = c.benchmark_group("decompression");

    let test_data_sizes = [100, 1000, 10000, 100000, 1000000];
    let compressor = SmartCompressor::new();

    for size in test_data_sizes {
        let data = vec![0x42u8; size];

        // Pre-compress the data
        let compressed = compressor.compress(&data).unwrap();

        group.bench_with_input(
            BenchmarkId::new("decompress", format!("{}_bytes", size)),
            &compressed,
            |b, compressed| b.iter(|| compressor.decompress(black_box(compressed)).unwrap()),
        );
    }

    group.finish();
}

fn bench_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("compression_roundtrip");

    let test_data_sizes = [100, 1000, 10000, 100000, 1000000];
    let compressor = SmartCompressor::new();

    for size in test_data_sizes {
        let data = vec![0x42u8; size];

        group.bench_with_input(
            BenchmarkId::new("roundtrip", format!("{}_bytes", size)),
            &data,
            |b, data| {
                b.iter(|| {
                    let compressed = compressor.compress(black_box(data)).unwrap();
                    compressor.decompress(&compressed).unwrap()
                })
            },
        );
    }

    group.finish();
}

fn bench_compression_quality(c: &mut Criterion) {
    let mut group = c.benchmark_group("compression_quality");

    let test_cases = [
        ("highly_compressible", vec![0x41u8; 10000]),
        (
            "moderately_compressible",
            (0..10000)
                .map(|i| if i % 2 == 0 { 0x41 } else { 0x42 })
                .collect(),
        ),
        (
            "low_compressibility",
            (0..10000).map(|_| rand::random::<u8>()).collect(),
        ),
        (
            "text_data",
            b"Hello World! This is a test message for compression quality testing. "
                .repeat(200)
                .into_iter()
                .collect::<Vec<u8>>(),
        ),
        (
            "repeated_patterns",
            [0x41u8, 0x42u8, 0x43u8].repeat(3333),
        ),
    ];

    let compressor = SmartCompressor::new();

    for (name, data) in test_cases {
        group.bench_with_input(BenchmarkId::new("compress", name), &data, |b, data| {
            b.iter(|| {
                let compressed = compressor.compress(black_box(data)).unwrap();
                let ratio = compressed.len() as f64 / data.len() as f64;
                black_box(ratio)
            })
        });
    }

    group.finish();
}

fn bench_streaming_compression(c: &mut Criterion) {
    let mut group = c.benchmark_group("streaming_compression");

    let test_data_sizes = [100, 1000, 10000, 100000, 1000000];
    let compressor = StreamingCompressor::new();

    for size in test_data_sizes {
        let data = vec![0x42u8; size];

        group.bench_with_input(
            BenchmarkId::new("compress_stream", format!("{}_bytes", size)),
            &data,
            |b, data| {
                b.iter(|| {
                    let mut output = Vec::new();
                    compressor
                        .compress_stream(std::io::Cursor::new(black_box(data)), &mut output)
                        .unwrap();
                    black_box(output)
                })
            },
        );
    }

    group.finish();
}

fn bench_streaming_decompression(c: &mut Criterion) {
    let mut group = c.benchmark_group("streaming_decompression");

    let test_data_sizes = [100, 1000, 10000, 100000, 1000000];
    let compressor = StreamingCompressor::new();

    for size in test_data_sizes {
        let data = vec![0x42u8; size];

        // Pre-compress the data
        let mut compressed = Vec::new();
        compressor
            .compress_stream(std::io::Cursor::new(&data), &mut compressed)
            .unwrap();

        group.bench_with_input(
            BenchmarkId::new("decompress_stream", format!("{}_bytes", size)),
            &compressed,
            |b, compressed| {
                b.iter(|| {
                    let mut output = Vec::new();
                    compressor
                        .decompress_stream(std::io::Cursor::new(black_box(compressed)), &mut output)
                        .unwrap();
                    black_box(output)
                })
            },
        );
    }

    group.finish();
}

fn bench_entropy_calculation(c: &mut Criterion) {
    let mut group = c.benchmark_group("entropy_calculation");

    let test_cases = [
        ("low_entropy", vec![0x41u8; 10000]),
        (
            "medium_entropy",
            (0..10000)
                .map(|i| if i % 2 == 0 { 0x41 } else { 0x42 })
                .collect(),
        ),
        (
            "high_entropy",
            (0..10000).map(|_| rand::random::<u8>()).collect(),
        ),
        (
            "mixed_entropy",
            [0x41u8, 0x42u8, 0x43u8, 0x44u8].repeat(2500),
        ),
    ];

    let compressor = SmartCompressor::new();

    for (name, data) in test_cases {
        group.bench_with_input(BenchmarkId::new("entropy", name), &data, |b, data| {
            b.iter(|| compressor.calculate_entropy(black_box(data)))
        });
    }

    group.finish();
}

fn bench_compression_detection(c: &mut Criterion) {
    let mut group = c.benchmark_group("compression_detection");

    let test_cases = [
        ("uncompressed", vec![0x42u8; 1000]),
        (
            "zlib_signature",
            vec![0x78, 0x9c, 0x01, 0x02, 0x03, 0x04, 0x05],
        ),
        (
            "zstd_signature",
            vec![0x28, 0xb5, 0x2f, 0xfd, 0x01, 0x02, 0x03, 0x04],
        ),
        ("mixed_data", [0x41u8, 0x42u8, 0x43u8].repeat(333)),
    ];

    let compressor = SmartCompressor::new();

    for (name, data) in test_cases {
        group.bench_with_input(BenchmarkId::new("detect", name), &data, |b, data| {
            b.iter(|| compressor.is_likely_compressed(black_box(data)))
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_compression,
    bench_decompression,
    bench_roundtrip,
    bench_compression_quality,
    bench_streaming_compression,
    bench_streaming_decompression,
    bench_entropy_calculation,
    bench_compression_detection
);
criterion_main!(benches);
