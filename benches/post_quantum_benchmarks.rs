use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use purrcrypt::crypto::post_quantum::{HybridKeyPair, SecureMessage};
use std::hint::black_box;

fn bench_key_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("post_quantum_key_generation");

    group.bench_function("hybrid_keypair_generation", |b| {
        b.iter(|| HybridKeyPair::new().unwrap())
    });

    group.finish();
}

fn bench_encryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("post_quantum_encryption");

    let test_data_sizes = [100, 1000, 10000, 100000];
    let _sender_keypair = HybridKeyPair::new().unwrap();
    let recipient_keypair = HybridKeyPair::new().unwrap();

    for size in test_data_sizes {
        let data = vec![0x42u8; size];

        group.bench_with_input(
            BenchmarkId::new("encrypt", format!("{}_bytes", size)),
            &data,
            |b, data| {
                b.iter(|| {
                    SecureMessage::encrypt(
                        black_box(data),
                        &recipient_keypair.ecdh_public,
                        &recipient_keypair.kyber_public,
                    )
                    .unwrap()
                })
            },
        );
    }

    group.finish();
}

fn bench_decryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("post_quantum_decryption");

    let test_data_sizes = [100, 1000, 10000, 100000];
    let _sender_keypair = HybridKeyPair::new().unwrap();
    let recipient_keypair = HybridKeyPair::new().unwrap();

    for size in test_data_sizes {
        let data = vec![0x42u8; size];

        // Pre-encrypt the data
        let message = SecureMessage::encrypt(
            &data,
            &recipient_keypair.ecdh_public,
            &recipient_keypair.kyber_public,
        )
        .unwrap();

        group.bench_with_input(
            BenchmarkId::new("decrypt", format!("{}_bytes", size)),
            &message,
            |b, message| {
                b.iter(|| {
                    message
                        .decrypt(
                            &recipient_keypair.ecdh_secret,
                            &recipient_keypair.kyber_secret,
                        )
                        .unwrap()
                })
            },
        );
    }

    group.finish();
}

fn bench_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("post_quantum_roundtrip");

    let test_data_sizes = [100, 1000, 10000, 100000];
    let _sender_keypair = HybridKeyPair::new().unwrap();
    let recipient_keypair = HybridKeyPair::new().unwrap();

    for size in test_data_sizes {
        let data = vec![0x42u8; size];

        group.bench_with_input(
            BenchmarkId::new("roundtrip", format!("{}_bytes", size)),
            &data,
            |b, data| {
                b.iter(|| {
                    let message = SecureMessage::encrypt(
                        black_box(data),
                        &recipient_keypair.ecdh_public,
                        &recipient_keypair.kyber_public,
                    )
                    .unwrap();
                    message
                        .decrypt(
                            &recipient_keypair.ecdh_secret,
                            &recipient_keypair.kyber_secret,
                        )
                        .unwrap()
                })
            },
        );
    }

    group.finish();
}

fn bench_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("post_quantum_serialization");

    let _sender_keypair = HybridKeyPair::new().unwrap();
    let recipient_keypair = HybridKeyPair::new().unwrap();
    let data = vec![0x42u8; 1000];

    let message = SecureMessage::encrypt(
        &data,
        &recipient_keypair.ecdh_public,
        &recipient_keypair.kyber_public,
    )
    .unwrap();

    group.bench_function("serialize", |b| b.iter(|| message.to_bytes()));

    let serialized = message.to_bytes();

    group.bench_function("deserialize", |b| {
        b.iter(|| SecureMessage::from_bytes(black_box(&serialized)).unwrap())
    });

    group.finish();
}

fn bench_mac_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("post_quantum_mac_verification");

    let _sender_keypair = HybridKeyPair::new().unwrap();
    let recipient_keypair = HybridKeyPair::new().unwrap();
    let data = vec![0x42u8; 1000];

    let message = SecureMessage::encrypt(
        &data,
        &recipient_keypair.ecdh_public,
        &recipient_keypair.kyber_public,
    )
    .unwrap();

    group.bench_function("mac_verification", |b| {
        b.iter(|| {
            message
                .decrypt(
                    &recipient_keypair.ecdh_secret,
                    &recipient_keypair.kyber_secret,
                )
                .unwrap()
        })
    });

    group.finish();
}

fn bench_different_recipients(c: &mut Criterion) {
    let mut group = c.benchmark_group("post_quantum_different_recipients");

    let _sender_keypair = HybridKeyPair::new().unwrap();
    let recipient1_keypair = HybridKeyPair::new().unwrap();
    let recipient2_keypair = HybridKeyPair::new().unwrap();
    let data = vec![0x42u8; 1000];

    group.bench_function("encrypt_recipient1", |b| {
        b.iter(|| {
            SecureMessage::encrypt(
                black_box(&data),
                &recipient1_keypair.ecdh_public,
                &recipient1_keypair.kyber_public,
            )
            .unwrap()
        })
    });

    group.bench_function("encrypt_recipient2", |b| {
        b.iter(|| {
            SecureMessage::encrypt(
                black_box(&data),
                &recipient2_keypair.ecdh_public,
                &recipient2_keypair.kyber_public,
            )
            .unwrap()
        })
    });

    group.finish();
}

fn bench_large_data(c: &mut Criterion) {
    let mut group = c.benchmark_group("post_quantum_large_data");

    let test_data_sizes = [100000, 1000000, 10000000]; // 100KB, 1MB, 10MB
    let _sender_keypair = HybridKeyPair::new().unwrap();
    let recipient_keypair = HybridKeyPair::new().unwrap();

    for size in test_data_sizes {
        let data = vec![0x42u8; size];

        group.bench_with_input(
            BenchmarkId::new("encrypt_large", format!("{}_bytes", size)),
            &data,
            |b, data| {
                b.iter(|| {
                    SecureMessage::encrypt(
                        black_box(data),
                        &recipient_keypair.ecdh_public,
                        &recipient_keypair.kyber_public,
                    )
                    .unwrap()
                })
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_key_generation,
    bench_encryption,
    bench_decryption,
    bench_roundtrip,
    bench_serialization,
    bench_mac_verification,
    bench_different_recipients,
    bench_large_data
);
criterion_main!(benches);
