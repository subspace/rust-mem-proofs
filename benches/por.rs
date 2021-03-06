/// Proof of replication
use criterion::criterion_group;
use criterion::criterion_main;
use criterion::Criterion;
use rand::Rng;
use rust_mem_proofs::por;
use rust_mem_proofs::Piece;
use rust_mem_proofs::PIECE_SIZE;
use std::iter::FromIterator;
use test_data::PIECE;

pub fn criterion_benchmark(c: &mut Criterion) {
    {
        let iv = [1, 2, 3];
        let sbox = por::SBoxDirect::new();
        let sbox_inverse = por::SBoxInverse::new();

        {
            let mut piece = PIECE;
            let mut piece_1 = PIECE;
            let mut piece_2 = PIECE;
            let mut piece_3 = PIECE;
            let mut piece_4 = PIECE;
            let mut piece_5 = PIECE;
            let mut piece_6 = PIECE;
            let mut piece_7 = PIECE;
            let mut piece_8 = PIECE;
            let mut piece_9 = PIECE;
            let mut piece_10 = PIECE;
            let mut piece_11 = PIECE;
            let mut piece_12 = PIECE;
            let mut piece_13 = PIECE;
            let mut piece_14 = PIECE;
            let mut piece_15 = PIECE;
            let mut piece_16 = PIECE;
            let mut group = c.benchmark_group("Memory-bound-single");
            group.sample_size(10);

            for &iterations in &[13_000_usize] {
                group.bench_function(format!("Prove-{}-iterations-1x", iterations), |b| {
                    b.iter(|| {
                        por::encode_simple(criterion::black_box(&mut piece), iv, iterations, &sbox);
                    })
                });

                group.bench_function(format!("Prove-{}-iterations-4x", iterations), |b| {
                    let ivs = [
                        [1, 1 + 1, 1 + 2],
                        [2, 2 + 1, 2 + 2],
                        [3, 3 + 1, 3 + 2],
                        [4, 4 + 1, 4 + 2],
                    ];
                    b.iter(|| {
                        por::encode_pipelined_x4(
                            criterion::black_box([
                                &mut piece_1,
                                &mut piece_2,
                                &mut piece_3,
                                &mut piece_4,
                            ]),
                            ivs,
                            iterations,
                            &sbox,
                        );
                    })
                });

                group.bench_function(format!("Prove-{}-iterations-8x", iterations), |b| {
                    let ivs = [
                        [1, 1 + 1, 1 + 2],
                        [2, 2 + 1, 2 + 2],
                        [3, 3 + 1, 3 + 2],
                        [4, 4 + 1, 4 + 2],
                        [5, 5 + 1, 5 + 2],
                        [6, 6 + 1, 6 + 2],
                        [7, 7 + 1, 7 + 2],
                        [8, 8 + 1, 8 + 2],
                    ];
                    b.iter(|| {
                        por::encode_pipelined_x8(
                            criterion::black_box([
                                &mut piece_1,
                                &mut piece_2,
                                &mut piece_3,
                                &mut piece_4,
                                &mut piece_5,
                                &mut piece_6,
                                &mut piece_7,
                                &mut piece_8,
                            ]),
                            ivs,
                            iterations,
                            &sbox,
                        );
                    })
                });

                group.bench_function(format!("Prove-{}-iterations-16x", iterations), |b| {
                    let ivs = [
                        [1, 1 + 1, 1 + 2],
                        [2, 2 + 1, 2 + 2],
                        [3, 3 + 1, 3 + 2],
                        [4, 4 + 1, 4 + 2],
                        [5, 5 + 1, 5 + 2],
                        [6, 6 + 1, 6 + 2],
                        [7, 7 + 1, 7 + 2],
                        [8, 8 + 1, 8 + 2],
                        [9, 9 + 1, 9 + 2],
                        [10, 10 + 1, 10 + 2],
                        [11, 11 + 1, 11 + 2],
                        [12, 12 + 1, 12 + 2],
                        [13, 13 + 1, 13 + 2],
                        [14, 14 + 1, 14 + 2],
                        [15, 15 + 1, 15 + 2],
                        [16, 16 + 1, 16 + 2],
                    ];
                    b.iter(|| {
                        por::encode_pipelined_x16(
                            criterion::black_box([
                                &mut piece_1,
                                &mut piece_2,
                                &mut piece_3,
                                &mut piece_4,
                                &mut piece_5,
                                &mut piece_6,
                                &mut piece_7,
                                &mut piece_8,
                                &mut piece_9,
                                &mut piece_10,
                                &mut piece_11,
                                &mut piece_12,
                                &mut piece_13,
                                &mut piece_14,
                                &mut piece_15,
                                &mut piece_16,
                            ]),
                            ivs,
                            iterations,
                            &sbox,
                        );
                    })
                });

                group.bench_function(format!("Verify-{}-iterations-simple", iterations), |b| {
                    b.iter(|| {
                        por::decode_simple(
                            criterion::black_box(&mut piece),
                            iv,
                            iterations,
                            &sbox_inverse,
                        );
                    })
                });

                group.bench_function(format!("Verify-{}-iterations-pipelined", iterations), |b| {
                    b.iter(|| {
                        por::decode_pipelined(
                            criterion::black_box(&mut piece),
                            iv,
                            iterations,
                            &sbox_inverse,
                        );
                    })
                });
            }

            group.finish();
        }

        {
            let pieces: Vec<Piece> = (0..=255_usize).map(|_| PIECE).collect();
            let ivs: Vec<[u8; 3]> = (0..=255_u8).map(|i| [i, i + 1, i + 2]).collect();
            let mut group = c.benchmark_group("Memory-bound-parallel");
            group.sample_size(10);

            for &iterations in &[13_000_usize] {
                group.bench_function(
                    format!("Prove-{}-iterations-pipelined-x8", iterations),
                    |b| {
                        b.iter(|| {
                            let mut pieces = pieces.clone();
                            por::encode_pipelined_x8_parallel(
                                criterion::black_box(&mut pieces),
                                &ivs,
                                iterations,
                                &sbox,
                            );
                        })
                    },
                );

                for &concurrency in &[8, 16, 32, 64] {
                    group.bench_function(
                        format!(
                            "Prove-{}-iterations-{}-concurrency",
                            iterations, concurrency
                        ),
                        |b| {
                            b.iter(|| {
                                let mut pieces = pieces.clone();
                                por::encode_simple_parallel(
                                    criterion::black_box(&mut pieces),
                                    iv,
                                    iterations,
                                    &sbox,
                                    concurrency,
                                );
                            })
                        },
                    );

                    group.bench_function(
                        format!(
                            "Verify-{}-iterations-{}-concurrency",
                            iterations, concurrency
                        ),
                        |b| {
                            b.iter(|| {
                                let mut pieces = pieces.clone();
                                por::decode_simple_parallel(
                                    criterion::black_box(&mut pieces),
                                    iv,
                                    iterations,
                                    &sbox_inverse,
                                    concurrency,
                                );
                            })
                        },
                    );
                }
            }

            group.finish();
        }

        {
            let mut pieces = Vec::from_iter((0..32).map(|_| {
                let mut piece = [0u8; PIECE_SIZE];
                rand::thread_rng().fill(&mut piece[..]);
                piece
            }));

            let mut group = c.benchmark_group("Memory-bound-throughput");
            group.sample_size(10);

            for &iterations in &[1_000_usize] {
                group.bench_function(format!("Prove-{}-iterations-single", iterations), |b| {
                    b.iter(|| {
                        for piece in pieces.iter_mut() {
                            por::encode_simple(criterion::black_box(piece), iv, iterations, &sbox);
                        }
                    })
                });

                group.bench_function(format!("Prove-{}-iterations-parallel", iterations), |b| {
                    b.iter(|| {
                        por::encode_simple_parallel(
                            criterion::black_box(&mut pieces),
                            iv,
                            iterations,
                            &sbox,
                            1,
                        );
                    })
                });
            }

            group.finish();
        }
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

mod test_data {
    use rust_mem_proofs::Piece;

    pub const PIECE: Piece = [
        0x58, 0xd5, 0xf1, 0x25, 0xa9, 0x78, 0xb0, 0xac, 0x2e, 0x07, 0x3c, 0xc9, 0xad, 0xab, 0x6f,
        0x75, 0xb0, 0xf3, 0xa7, 0x04, 0xf1, 0x0f, 0xa9, 0x37, 0x17, 0x5e, 0x65, 0x25, 0x2e, 0x01,
        0x0e, 0x06, 0x8b, 0x96, 0x24, 0xed, 0x5d, 0x54, 0xdc, 0x10, 0x67, 0x86, 0xd3, 0x30, 0x54,
        0x4b, 0xc6, 0x89, 0xd1, 0x2f, 0x02, 0xf0, 0x95, 0xf8, 0x24, 0x60, 0x8d, 0xb5, 0x55, 0xc1,
        0xf7, 0x98, 0x5c, 0x24, 0x62, 0x74, 0x3c, 0x48, 0x62, 0xbb, 0x2c, 0xcc, 0x5c, 0x21, 0x33,
        0x90, 0x6b, 0xc1, 0x60, 0x14, 0x3b, 0x15, 0x61, 0x20, 0xc9, 0x32, 0x1c, 0x1b, 0x4d, 0xfd,
        0xc5, 0x29, 0xe7, 0x9a, 0x5c, 0xa6, 0x83, 0x5c, 0x82, 0xbf, 0xc0, 0x33, 0x3a, 0x14, 0xf7,
        0xd6, 0x4b, 0x86, 0x5d, 0xb4, 0x48, 0xde, 0x50, 0x00, 0x61, 0xb9, 0x81, 0x28, 0x3e, 0x04,
        0x48, 0xf4, 0x13, 0x1e, 0xeb, 0x8a, 0xc2, 0x7e, 0x72, 0xb2, 0x4d, 0x20, 0x8b, 0x5f, 0xab,
        0x9f, 0x6d, 0x3d, 0xce, 0x68, 0x6f, 0x56, 0xa8, 0x42, 0xb8, 0xca, 0xe4, 0x09, 0x2d, 0x66,
        0x0e, 0xbf, 0x5a, 0x06, 0x43, 0x13, 0x1d, 0xe8, 0x80, 0x8d, 0xce, 0xfb, 0x5b, 0xcf, 0x65,
        0xf6, 0x96, 0x84, 0x4d, 0xcf, 0x9d, 0xce, 0x92, 0x7a, 0xd9, 0xb1, 0xb3, 0xcc, 0x92, 0x3a,
        0x31, 0x47, 0x39, 0x24, 0xf4, 0x3d, 0x28, 0x4b, 0x8e, 0x45, 0xf8, 0xa3, 0x6c, 0x44, 0xdf,
        0x5c, 0x6e, 0x09, 0xc1, 0x0c, 0xbb, 0xaf, 0x1d, 0x27, 0x39, 0x39, 0x5f, 0xd9, 0x98, 0x22,
        0x46, 0x69, 0xa1, 0x56, 0x13, 0xe0, 0x14, 0x21, 0xe9, 0xbe, 0xc3, 0x23, 0x49, 0x7a, 0x67,
        0x9a, 0x4f, 0x2b, 0x1f, 0x70, 0x35, 0x67, 0x22, 0x0f, 0x42, 0xbe, 0xe0, 0x06, 0x24, 0xbf,
        0xe3, 0x17, 0xea, 0x91, 0x8f, 0x66, 0x44, 0x02, 0x9d, 0xd4, 0xe5, 0xeb, 0x7e, 0xc5, 0x7b,
        0xa6, 0x63, 0x8e, 0x97, 0x48, 0xa3, 0xe6, 0x0b, 0x25, 0x49, 0x4a, 0xbd, 0xa5, 0x07, 0x5c,
        0xd0, 0xb4, 0xba, 0x14, 0xe4, 0xf9, 0xa2, 0x7a, 0xfa, 0xe7, 0xae, 0x80, 0xf4, 0x65, 0xc8,
        0xe1, 0xeb, 0x35, 0xb6, 0x50, 0xab, 0x84, 0x08, 0xbe, 0x4d, 0xcf, 0xa0, 0x24, 0x11, 0x40,
        0x94, 0x84, 0x44, 0x33, 0x1c, 0x8d, 0x29, 0xc7, 0x52, 0xe0, 0x07, 0x7c, 0x9d, 0x05, 0x7c,
        0xd4, 0xbb, 0xe6, 0x49, 0xea, 0xf2, 0x21, 0x62, 0x0e, 0x6a, 0xb6, 0x63, 0x89, 0x8e, 0xd5,
        0xab, 0x24, 0x60, 0x12, 0xa3, 0x20, 0x4f, 0x26, 0x68, 0xbb, 0x52, 0x7c, 0x0c, 0xac, 0x03,
        0x2c, 0xf3, 0x11, 0xd1, 0xc3, 0xf1, 0x2b, 0xd1, 0xf6, 0x34, 0x61, 0x0d, 0x12, 0x3b, 0x07,
        0x10, 0xed, 0x67, 0x14, 0x2f, 0x0e, 0x5d, 0x19, 0xa1, 0x5e, 0x1b, 0xb2, 0xeb, 0x58, 0x9e,
        0xea, 0xf2, 0xd4, 0x86, 0xc7, 0x1d, 0x5f, 0x21, 0x47, 0xa1, 0x07, 0x2d, 0xa9, 0x36, 0x3a,
        0x22, 0x41, 0xf7, 0x53, 0x41, 0xf0, 0x10, 0xa9, 0x5a, 0x8c, 0x2c, 0xfd, 0xde, 0x83, 0xb9,
        0x3e, 0xcd, 0xaa, 0x79, 0x22, 0xca, 0x21, 0x82, 0xe4, 0xfb, 0xfc, 0x30, 0xc4, 0x01, 0x9c,
        0x40, 0x2b, 0xcf, 0x95, 0x54, 0xfd, 0x43, 0x8d, 0x54, 0x39, 0xcd, 0x68, 0x5d, 0x8d, 0xc4,
        0x37, 0x25, 0x5b, 0x4d, 0xc8, 0xac, 0x2d, 0x44, 0xe8, 0x90, 0x43, 0xe0, 0x51, 0x68, 0x53,
        0x4b, 0x4a, 0x74, 0xf2, 0xfa, 0xf0, 0x69, 0x35, 0x86, 0x00, 0xae, 0x91, 0x53, 0xd4, 0xb9,
        0x3a, 0x4d, 0x47, 0xee, 0xbe, 0x89, 0x53, 0xe3, 0x4c, 0xf3, 0x53, 0x9e, 0x76, 0x1d, 0xfd,
        0xe9, 0xa3, 0x37, 0x99, 0x5a, 0x32, 0x06, 0xa0, 0xd0, 0xc8, 0xd7, 0x04, 0x66, 0x41, 0x9b,
        0x65, 0x15, 0x0d, 0x4e, 0x29, 0x1c, 0x8d, 0x32, 0x72, 0x38, 0xec, 0x20, 0x1f, 0xce, 0xcd,
        0x60, 0x80, 0xa1, 0x57, 0x30, 0xca, 0xaf, 0xaf, 0xb3, 0x84, 0x32, 0xe5, 0x30, 0xe2, 0x65,
        0xf6, 0x5b, 0x08, 0x00, 0xfe, 0x2e, 0xfe, 0xca, 0x5a, 0xdf, 0xd2, 0x2e, 0xf9, 0x35, 0x50,
        0x05, 0x7a, 0x3f, 0x85, 0x1b, 0x1d, 0x67, 0x1e, 0xd9, 0x90, 0x48, 0xea, 0x91, 0x5b, 0xe0,
        0x69, 0xe8, 0xb9, 0x4c, 0xa4, 0x94, 0xfd, 0x1b, 0xcf, 0x4f, 0x0e, 0x01, 0xbc, 0x80, 0x0e,
        0x9c, 0xbf, 0x78, 0x24, 0xd6, 0xb1, 0x31, 0xdb, 0xa8, 0x80, 0xf4, 0xa1, 0xc8, 0xf1, 0xb2,
        0xc2, 0xb6, 0x47, 0x9d, 0x59, 0x32, 0xe6, 0x0f, 0xf4, 0x84, 0x27, 0x59, 0x4b, 0xda, 0x41,
        0x81, 0xb2, 0x4e, 0x51, 0xd4, 0x16, 0x28, 0xe7, 0x48, 0xf0, 0xa5, 0xd1, 0x92, 0x1f, 0x4e,
        0xbe, 0x81, 0x8f, 0xae, 0xbc, 0x5d, 0xf9, 0xe3, 0x39, 0x11, 0x58, 0x88, 0x1e, 0x86, 0x50,
        0x89, 0x48, 0xdd, 0x77, 0x56, 0x29, 0x53, 0xf3, 0xed, 0x70, 0xd3, 0xbc, 0x86, 0x76, 0xc8,
        0x6c, 0x13, 0xb5, 0x13, 0x7a, 0xcb, 0xbe, 0xcf, 0xce, 0xdc, 0x09, 0xcd, 0x23, 0x3d, 0xc7,
        0x09, 0xdd, 0xcb, 0xa3, 0x87, 0x29, 0xb1, 0x6d, 0x02, 0xa4, 0x95, 0xb5, 0x5a, 0x99, 0x81,
        0xe8, 0x94, 0x57, 0x03, 0x64, 0xe2, 0xec, 0x0f, 0x8a, 0xa0, 0x60, 0x6d, 0x6f, 0xfc, 0xf3,
        0x63, 0x19, 0xf8, 0xe8, 0x29, 0xee, 0x1c, 0x34, 0x4f, 0x46, 0x33, 0xb4, 0x7b, 0x57, 0x5d,
        0x2c, 0x0e, 0x00, 0x6f, 0x67, 0x20, 0x94, 0x01, 0xce, 0x5f, 0xd1, 0xf1, 0xb7, 0x77, 0xd3,
        0xab, 0x81, 0x1a, 0x97, 0x97, 0xcf, 0x1c, 0x97, 0x6b, 0x51, 0xce, 0xf5, 0x52, 0x8d, 0x0c,
        0xd2, 0xbb, 0x0b, 0xe6, 0x25, 0x94, 0x8f, 0x96, 0xb0, 0x7f, 0x9b, 0xdc, 0xc8, 0x0d, 0x77,
        0x5a, 0x72, 0x34, 0x0d, 0x09, 0x50, 0x10, 0x98, 0xc8, 0x43, 0x95, 0xd9, 0x78, 0x83, 0xbb,
        0xd6, 0x3f, 0x70, 0x57, 0x52, 0x87, 0x3c, 0x60, 0xfd, 0x13, 0x9f, 0x31, 0x36, 0x21, 0x67,
        0xc4, 0x65, 0xd2, 0xd9, 0xbf, 0x74, 0x92, 0x17, 0x77, 0x05, 0x56, 0xc7, 0x7d, 0x85, 0x6a,
        0xf5, 0x46, 0x2b, 0xff, 0x9a, 0xaf, 0xd8, 0x7b, 0x33, 0xed, 0x6b, 0x06, 0x0d, 0xb1, 0xa9,
        0xd5, 0x69, 0x9e, 0x1b, 0xfc, 0x28, 0x0c, 0xc6, 0x0b, 0xaa, 0xce, 0x07, 0x4b, 0x4a, 0x3f,
        0xe4, 0x46, 0x6e, 0xbb, 0x28, 0x17, 0x0d, 0xfc, 0x0e, 0xa5, 0x85, 0xe6, 0x1c, 0x78, 0x97,
        0xb7, 0xda, 0x5a, 0x1e, 0x85, 0x31, 0x64, 0xd9, 0xb6, 0xe2, 0x16, 0xa4, 0x2e, 0x02, 0x6c,
        0xa9, 0x83, 0x8f, 0xe7, 0x32, 0x97, 0xb3, 0xf2, 0xe6, 0xfd, 0xb5, 0xd0, 0xca, 0xf4, 0x50,
        0x20, 0x48, 0xec, 0x97, 0x53, 0xc1, 0x2d, 0x10, 0x1e, 0x74, 0x11, 0x5d, 0x4d, 0xa6, 0x4b,
        0xa3, 0x7e, 0xe8, 0xdd, 0x7e, 0x1c, 0x35, 0x30, 0x89, 0xa8, 0xf1, 0xd4, 0x71, 0x0d, 0x28,
        0x01, 0xe4, 0x89, 0x74, 0xcb, 0x0b, 0x81, 0x60, 0xda, 0x53, 0xc2, 0x0f, 0x27, 0x72, 0x65,
        0xab, 0x87, 0xaa, 0x8d, 0xba, 0x34, 0x87, 0x1e, 0x8c, 0x96, 0x10, 0xc2, 0x9a, 0xfe, 0xcc,
        0x54, 0xf5, 0x8c, 0x80, 0x5f, 0x9b, 0x13, 0xb3, 0x67, 0x04, 0x11, 0x73, 0x1e, 0x9d, 0xaa,
        0xc0, 0xe2, 0xe1, 0x27, 0xc1, 0x30, 0xcc, 0x3e, 0x37, 0xa6, 0xec, 0xb2, 0x37, 0x87, 0x50,
        0x8b, 0x4b, 0xbf, 0x26, 0xf3, 0x4d, 0x1d, 0xcf, 0x42, 0x1d, 0x57, 0xc5, 0x53, 0x62, 0xdd,
        0xc6, 0x10, 0xb7, 0x80, 0x52, 0x84, 0xe9, 0x31, 0x96, 0x95, 0x0f, 0xca, 0xd8, 0xea, 0xb1,
        0x71, 0x7e, 0x9c, 0x27, 0x2a, 0xca, 0xe1, 0xe9, 0x6e, 0x80, 0x70, 0xb8, 0x63, 0xb1, 0x57,
        0xcc, 0xdc, 0x8d, 0xdd, 0xcb, 0x94, 0xb4, 0x5e, 0x11, 0xe6, 0x56, 0xcd, 0x68, 0x8d, 0x71,
        0x32, 0x26, 0x81, 0x52, 0xe2, 0x76, 0x0a, 0xa2, 0x00, 0x88, 0x06, 0x2f, 0x69, 0x61, 0x30,
        0x47, 0xa1, 0x90, 0x40, 0xad, 0x22, 0xca, 0x78, 0xc4, 0x64, 0x4e, 0xac, 0xf7, 0xa7, 0x28,
        0xac, 0xa1, 0x6f, 0x92, 0x23, 0xd8, 0x02, 0x19, 0xba, 0x57, 0x50, 0xe5, 0xd8, 0xfa, 0xb5,
        0x64, 0xd8, 0x90, 0x96, 0x39, 0x4d, 0x8d, 0x80, 0x37, 0x41, 0xd2, 0xd5, 0xa0, 0xdd, 0xfb,
        0x51, 0xb7, 0x6f, 0x4e, 0x7f, 0x14, 0xfe, 0x4c, 0x26, 0x56, 0x61, 0xa7, 0x5b, 0x25, 0x39,
        0x14, 0x85, 0xf7, 0x23, 0xeb, 0x11, 0xe1, 0x0d, 0xf1, 0xc3, 0xcd, 0xad, 0x40, 0x5d, 0xa4,
        0x1d, 0x27, 0x94, 0x90, 0x3a, 0x29, 0xd7, 0xd3, 0x83, 0xcf, 0xef, 0xb9, 0x71, 0x00, 0x9a,
        0x9f, 0x75, 0xac, 0x66, 0xd3, 0x1a, 0xac, 0xab, 0x8c, 0xef, 0xe1, 0xa8, 0x43, 0xce, 0x95,
        0x33, 0x1d, 0xc4, 0x5e, 0x9a, 0xe5, 0x10, 0x74, 0x4e, 0xff, 0xe5, 0x81, 0x73, 0x71, 0x10,
        0x1a, 0x2f, 0x66, 0x28, 0xe8, 0x3f, 0xaf, 0xd3, 0x84, 0xbd, 0x37, 0xd7, 0xa1, 0x9e, 0x14,
        0xc1, 0x46, 0x3a, 0x38, 0xb6, 0x40, 0x98, 0xba, 0x8c, 0x82, 0xb1, 0xe6, 0xee, 0x0f, 0x4a,
        0x9c, 0x0f, 0xf5, 0x3c, 0x5d, 0x22, 0xe5, 0xed, 0x5a, 0x20, 0x17, 0x18, 0xc0, 0x82, 0xf1,
        0x62, 0x2a, 0xf5, 0x82, 0x6a, 0x63, 0x05, 0x45, 0xae, 0x05, 0xa5, 0xc3, 0xbb, 0xcf, 0xf5,
        0x71, 0xe4, 0x38, 0x57, 0x20, 0x0b, 0x99, 0xae, 0x7c, 0x88, 0x54, 0xee, 0x04, 0x5f, 0x39,
        0x54, 0x1d, 0x0d, 0xa9, 0x6c, 0xad, 0x63, 0x61, 0xfa, 0x0b, 0xc5, 0x26, 0xdd, 0x5d, 0x9b,
        0xbf, 0x12, 0xab, 0xd5, 0xf5, 0x0e, 0x48, 0x32, 0xc6, 0xb0, 0x3e, 0xf5, 0x2f, 0x6f, 0x0d,
        0x5d, 0xb9, 0x51, 0xb7, 0x0e, 0xeb, 0xa3, 0x86, 0xc2, 0x1c, 0xf4, 0xad, 0x01, 0xc1, 0x5f,
        0xcd, 0x3f, 0x54, 0x20, 0x86, 0x51, 0x0a, 0xdd, 0x3d, 0x3f, 0x51, 0x8a, 0x74, 0x9e, 0xa3,
        0xa2, 0x9c, 0x90, 0x63, 0x61, 0x04, 0xc1, 0xe8, 0x3d, 0x2e, 0xe4, 0x23, 0x41, 0x59, 0x21,
        0xc3, 0x2f, 0x65, 0xf6, 0x54, 0x6b, 0x39, 0x38, 0x4c, 0x6f, 0xb6, 0x8b, 0x1f, 0x69, 0x89,
        0x0b, 0x4f, 0x57, 0x8a, 0xa9, 0xb4, 0xe0, 0x2b, 0x09, 0x80, 0x37, 0x43, 0xa5, 0x97, 0xcd,
        0xb0, 0xe8, 0xe3, 0x2e, 0xee, 0xbb, 0x24, 0x62, 0xad, 0xd6, 0xc7, 0x64, 0x85, 0x0a, 0xc2,
        0x75, 0x99, 0x79, 0x69, 0xb9, 0x86, 0xf7, 0x83, 0x58, 0xa5, 0x25, 0xf7, 0x48, 0xa1, 0x3c,
        0xea, 0x01, 0x58, 0xea, 0x94, 0x06, 0x7f, 0x81, 0x39, 0x59, 0xab, 0xc0, 0xaa, 0x15, 0x1a,
        0x60, 0x04, 0xb4, 0x90, 0xe5, 0x65, 0xcb, 0xce, 0x11, 0xee, 0xfe, 0x94, 0x57, 0x7f, 0xdc,
        0x9c, 0x44, 0x5f, 0xa2, 0x32, 0xc8, 0xb9, 0x36, 0x0f, 0xf7, 0x17, 0xb1, 0xeb, 0x17, 0x63,
        0x6c, 0x69, 0xf0, 0x87, 0x91, 0x2c, 0xaf, 0x43, 0x5a, 0xe3, 0xcd, 0x68, 0xfc, 0x21, 0x4c,
        0x96, 0xce, 0x3f, 0x3f, 0x2b, 0x84, 0xfc, 0x48, 0xc7, 0xf5, 0x33, 0x7f, 0xa3, 0x4f, 0x6a,
        0x12, 0x5d, 0x27, 0x9f, 0xae, 0x61, 0xf3, 0x62, 0x15, 0x3a, 0x4b, 0x2e, 0xe7, 0x45, 0x43,
        0x22, 0xd4, 0xb0, 0xdd, 0xf8, 0x99, 0x4d, 0x46, 0x85, 0xac, 0x13, 0x91, 0x2a, 0x19, 0xff,
        0xfd, 0x7c, 0x7e, 0x0b, 0x61, 0x33, 0x63, 0xc3, 0x98, 0xdd, 0xff, 0x4c, 0x4f, 0xdb, 0x64,
        0xe1, 0x3c, 0x42, 0x23, 0xb1, 0xfc, 0x6e, 0xd4, 0xa0, 0xd2, 0x1b, 0xad, 0x56, 0x9b, 0x07,
        0x21, 0xbd, 0x42, 0x79, 0x58, 0xda, 0x5e, 0x5a, 0x00, 0xc4, 0xcc, 0xea, 0x77, 0x52, 0x65,
        0x59, 0x4b, 0xbd, 0xe4, 0x21, 0xea, 0xdf, 0xb2, 0x5e, 0x77, 0x07, 0x63, 0x49, 0x0d, 0xc1,
        0xd0, 0xe9, 0xd8, 0x97, 0xcc, 0x04, 0x6a, 0x2b, 0x71, 0xea, 0x92, 0xf0, 0xed, 0x60, 0xfc,
        0xb4, 0x3c, 0x55, 0x2b, 0xc0, 0x88, 0x8d, 0x68, 0xda, 0x8f, 0x13, 0x4a, 0xea, 0x9d, 0x6b,
        0x98, 0xbe, 0xf9, 0x04, 0xec, 0xaf, 0x05, 0x29, 0x45, 0x9a, 0x5c, 0x2f, 0x97, 0x5b, 0x27,
        0x1e, 0x78, 0x17, 0xc3, 0x97, 0x1c, 0x3e, 0x73, 0xda, 0xfb, 0xa2, 0x1b, 0x60, 0x27, 0xed,
        0xff, 0x8c, 0x30, 0x24, 0x31, 0x6a, 0x02, 0xae, 0xf5, 0x00, 0x71, 0x97, 0xa5, 0xd3, 0x8c,
        0x9f, 0x7a, 0x99, 0x84, 0x19, 0x5e, 0x22, 0x66, 0x93, 0xcd, 0x25, 0x2f, 0x1c, 0x60, 0x2a,
        0xa2, 0x44, 0xf8, 0xdf, 0x96, 0xd0, 0x31, 0xa8, 0x3d, 0xa2, 0xeb, 0x81, 0x53, 0xb8, 0x62,
        0xeb, 0xe9, 0x8d, 0xc8, 0xa2, 0xc9, 0x2d, 0x41, 0x78, 0x2f, 0xc9, 0x4b, 0x37, 0xff, 0x05,
        0xc2, 0x98, 0x7b, 0x37, 0x45, 0xba, 0x35, 0x57, 0x35, 0xd8, 0x23, 0x59, 0x06, 0x5c, 0xd9,
        0xe4, 0x47, 0x3c, 0x08, 0xba, 0x45, 0x69, 0x37, 0x6f, 0x43, 0x30, 0x79, 0x07, 0x73, 0x50,
        0x48, 0x5e, 0x27, 0xad, 0x30, 0x79, 0x58, 0xaf, 0x36, 0x6e, 0x97, 0x1d, 0xbf, 0x95, 0xfc,
        0xb1, 0xea, 0x0e, 0x13, 0x59, 0xd4, 0xa2, 0xed, 0xab, 0x3b, 0x17, 0x07, 0x56, 0x32, 0x75,
        0x9a, 0x73, 0xf2, 0xaf, 0xc9, 0xf3, 0xc7, 0xe6, 0xf2, 0x6f, 0x97, 0x27, 0x66, 0x69, 0x31,
        0x49, 0x28, 0xa4, 0x72, 0x65, 0x73, 0xcc, 0xd3, 0xdd, 0xb1, 0xca, 0x66, 0xe3, 0xa0, 0xca,
        0xdb, 0xb1, 0xa3, 0x6e, 0x3f, 0x27, 0xaf, 0x1a, 0xce, 0x6b, 0x86, 0xe5, 0xcc, 0xb0, 0xea,
        0x00, 0x1d, 0x64, 0xbb, 0x80, 0x75, 0xb9, 0x5b, 0x9d, 0x6c, 0x04, 0x26, 0x59, 0x9c, 0xe9,
        0x5f, 0xce, 0xe0, 0x88, 0x67, 0x32, 0xa7, 0xc9, 0x12, 0xaf, 0xb6, 0x8a, 0xa8, 0x46, 0x4e,
        0xc2, 0x2b, 0x3c, 0xa4, 0xc8, 0xcb, 0x39, 0x45, 0x8b, 0xe3, 0xca, 0x1c, 0x83, 0xca, 0xb2,
        0x75, 0xbf, 0x15, 0x54, 0x06, 0xdb, 0xb6, 0xff, 0xdb, 0xd2, 0x2a, 0x68, 0x68, 0xa1, 0x40,
        0xec, 0x98, 0x84, 0x92, 0x6f, 0x47, 0xdc, 0x10, 0x23, 0xc7, 0x9e, 0xae, 0x10, 0x5b, 0x84,
        0x46, 0x80, 0xb2, 0x58, 0xd7, 0x95, 0xee, 0x44, 0x54, 0xa9, 0x19, 0x16, 0xef, 0x62, 0x0f,
        0x7b, 0xe3, 0xd1, 0x26, 0x2d, 0x5a, 0x02, 0x9c, 0x4c, 0xed, 0x96, 0x6e, 0xa7, 0x73, 0x33,
        0xd4, 0x0f, 0x25, 0x52, 0xc8, 0xea, 0xa4, 0x68, 0x75, 0x24, 0xc5, 0x39, 0x3a, 0x87, 0xb9,
        0xe4, 0x27, 0x0f, 0xd1, 0x77, 0xf1, 0x07, 0x41, 0xfd, 0x81, 0x85, 0xa8, 0x90, 0xa9, 0xe4,
        0xe1, 0xee, 0x4b, 0x6c, 0x04, 0x91, 0xd3, 0xbc, 0xec, 0x77, 0xa3, 0x64, 0x0e, 0xb2, 0x30,
        0x29, 0xe7, 0xa1, 0x66, 0x70, 0x4e, 0xcb, 0xaa, 0x60, 0x82, 0xee, 0x06, 0xcd, 0x82, 0x98,
        0x47, 0xcd, 0x7d, 0x1e, 0x8a, 0x12, 0xbe, 0x1d, 0x43, 0x61, 0x40, 0x95, 0x5d, 0x1d, 0x9d,
        0x87, 0x7a, 0x27, 0xc1, 0xa1, 0x82, 0x88, 0x4e, 0xbb, 0x83, 0xa5, 0xa2, 0x53, 0xc7, 0xde,
        0x17, 0x2f, 0xf5, 0x54, 0x03, 0xdd, 0x2d, 0xb4, 0x9a, 0xb9, 0x1c, 0x19, 0xff, 0x75, 0xf7,
        0x16, 0xbd, 0x21, 0xc2, 0x19, 0xf5, 0xe1, 0x45, 0xf8, 0x34, 0x19, 0x95, 0xab, 0xc9, 0x0e,
        0xa8, 0x6f, 0x14, 0x97, 0x89, 0x96, 0xf8, 0xfd, 0x0c, 0x2f, 0x44, 0x34, 0xe9, 0x47, 0xcb,
        0x09, 0xee, 0x7d, 0x15, 0xf6, 0x39, 0x85, 0x6c, 0xe6, 0x8e, 0xa0, 0x22, 0x43, 0xa2, 0x40,
        0xd7, 0xdf, 0x6f, 0x53, 0x0e, 0x9c, 0xa3, 0xd6, 0x9f, 0xb9, 0x23, 0x1f, 0x49, 0xc1, 0x72,
        0x2b, 0x8a, 0x22, 0x81, 0x74, 0xb8, 0x2a, 0xd1, 0xc3, 0xb0, 0x9b, 0x03, 0x21, 0xbc, 0x73,
        0x6d, 0x68, 0x1d, 0x82, 0x2f, 0x23, 0xcd, 0x29, 0xc4, 0xe5, 0x49, 0x3c, 0xb0, 0x7e, 0x6a,
        0xcf, 0xcd, 0xef, 0x26, 0x82, 0x35, 0x62, 0xc3, 0x54, 0x0d, 0x4f, 0xe0, 0x3c, 0xda, 0x18,
        0x41, 0x26, 0xac, 0xd2, 0x44, 0x45, 0xcd, 0x87, 0x01, 0xe8, 0x21, 0x3a, 0x12, 0x56, 0x64,
        0x24, 0x9d, 0x79, 0x12, 0xa5, 0x6b, 0xaf, 0x96, 0x1e, 0x6c, 0x5a, 0x49, 0x7a, 0x0c, 0x7b,
        0xb7, 0x1e, 0x2e, 0xee, 0x4c, 0x84, 0x25, 0x75, 0x56, 0x06, 0x42, 0xf7, 0x3e, 0xcc, 0xd3,
        0xc7, 0x4f, 0x11, 0x35, 0xfb, 0xcc, 0x1a, 0x78, 0xa9, 0x92, 0x41, 0xc5, 0x28, 0x9c, 0x91,
        0xb0, 0x33, 0x55, 0x08, 0xea, 0x98, 0xb0, 0x0f, 0x45, 0x8b, 0xe7, 0xae, 0xe8, 0x3d, 0x2e,
        0x7a, 0xe3, 0xdb, 0xae, 0xa1, 0x40, 0x2c, 0xee, 0x30, 0x80, 0xb7, 0xea, 0xc2, 0xdf, 0xec,
        0x28, 0xfd, 0xfb, 0x7c, 0x08, 0x6d, 0x1c, 0xcb, 0x47, 0x79, 0xa5, 0x30, 0x8d, 0xd5, 0xce,
        0x8c, 0xe8, 0x4d, 0x8b, 0x6f, 0x3a, 0x7a, 0xd7, 0x28, 0xb7, 0x18, 0x46, 0x23, 0x89, 0xc6,
        0x99, 0x9d, 0x32, 0x25, 0x7b, 0xc7, 0x1f, 0x0e, 0xf9, 0xb9, 0x40, 0x97, 0x4c, 0x44, 0x4a,
        0xeb, 0x5e, 0x3b, 0xb6, 0x1e, 0x86, 0x42, 0x9a, 0x83, 0x4a, 0xb6, 0x99, 0xe9, 0x63, 0x33,
        0x2b, 0x70, 0xcc, 0xcf, 0xc2, 0x03, 0x39, 0x3d, 0xac, 0x34, 0x55, 0x39, 0x12, 0x22, 0x5f,
        0x8c, 0xd8, 0x2a, 0x09, 0xc4, 0xb9, 0xae, 0xd5, 0x39, 0x5c, 0x0b, 0xd3, 0x75, 0x62, 0x60,
        0xce, 0x45, 0x73, 0x32, 0x0a, 0xbc, 0x5f, 0xc2, 0xf1, 0xae, 0x9e, 0xd5, 0x24, 0xab, 0xbe,
        0x1b, 0x03, 0x82, 0x72, 0xf6, 0x75, 0x3a, 0x2a, 0xca, 0xad, 0x28, 0x1c, 0x52, 0xc4, 0x79,
        0xb4, 0x73, 0x7f, 0x71, 0x69, 0xa1, 0x19, 0x77, 0x2f, 0x7a, 0x71, 0x92, 0x48, 0x59, 0x57,
        0xfe, 0x88, 0x4f, 0x69, 0xe5, 0xfd, 0x36, 0x6f, 0x7c, 0xd8, 0xb3, 0x24, 0x9a, 0xcc, 0xc5,
        0x1e, 0xd4, 0x2a, 0x59, 0xd0, 0x57, 0xa8, 0x57, 0x36, 0xd2, 0x95, 0xbb, 0x6e, 0x08, 0xca,
        0xfd, 0x4e, 0x8c, 0x58, 0xff, 0x6b, 0x09, 0xea, 0xb3, 0x90, 0xb8, 0x40, 0x83, 0x0c, 0xcb,
        0xb2, 0x43, 0x74, 0xe2, 0xec, 0x5e, 0x31, 0x24, 0x2d, 0x9b, 0xa9, 0x59, 0xe9, 0x22, 0x95,
        0x8e, 0x3a, 0x87, 0xbd, 0x9c, 0x2f, 0x91, 0xbb, 0x73, 0x8b, 0xc3, 0x6e, 0x3c, 0xe0, 0x05,
        0xbc, 0x27, 0x39, 0x2c, 0x6c, 0x49, 0x49, 0x2f, 0x35, 0x4c, 0x9e, 0xa5, 0x83, 0x93, 0xf5,
        0x4c, 0x02, 0x8c, 0xc7, 0x05, 0x65, 0x0d, 0x75, 0xa7, 0xd2, 0xdc, 0xbf, 0x61, 0x24, 0x18,
        0xa6, 0x1e, 0x0f, 0xd0, 0x93, 0xc7, 0xc3, 0xfe, 0x64, 0xb1, 0x42, 0xd9, 0x26, 0xde, 0x6a,
        0x38, 0xa6, 0x3e, 0x37, 0xfa, 0x7a, 0x35, 0x92, 0x32, 0x7a, 0xda, 0xef, 0x3d, 0x85, 0xa7,
        0xc1, 0x13, 0x83, 0xcb, 0x68, 0x13, 0x6e, 0xe1, 0x56, 0x75, 0xa3, 0x2f, 0x70, 0xb8, 0x9a,
        0xb6, 0x6f, 0xef, 0x56, 0x18, 0x4a, 0xb1, 0x0a, 0x5d, 0x6d, 0xd3, 0x3f, 0x95, 0x0f, 0xe9,
        0xc9, 0xd1, 0x63, 0xa0, 0x0a, 0x63, 0xe1, 0x76, 0x4c, 0x5d, 0x34, 0xf6, 0xc7, 0x59, 0xe0,
        0x8d, 0x7a, 0x54, 0xd7, 0xe9, 0x70, 0x06, 0xa8, 0x7d, 0xa2, 0x4e, 0x2e, 0xd3, 0x8c, 0x1c,
        0xf9, 0x1f, 0x85, 0xa9, 0x0b, 0xc9, 0xc4, 0x88, 0xb3, 0x02, 0x6d, 0x1a, 0x94, 0xe4, 0x88,
        0xa8, 0xc3, 0xac, 0x3f, 0x39, 0xeb, 0x16, 0x3c, 0x30, 0x20, 0xb7, 0x79, 0x60, 0x99, 0x23,
        0xf4, 0xf3, 0x90, 0xc8, 0x52, 0x80, 0x50, 0x43, 0x4d, 0x92, 0x86, 0xb6, 0x9a, 0xad, 0xb0,
        0xcf, 0x43, 0x22, 0x6a, 0x41, 0x03, 0xf6, 0xd9, 0x26, 0x78, 0x0a, 0xed, 0xbe, 0x4d, 0x69,
        0xff, 0x28, 0x4a, 0xd1, 0xf5, 0x5e, 0xfe, 0x41, 0xb8, 0xce, 0x03, 0xae, 0x75, 0x85, 0xc9,
        0x99, 0x32, 0xdc, 0x5c, 0xfc, 0x6c, 0x78, 0x55, 0xd2, 0xd9, 0xcf, 0x47, 0x92, 0x8f, 0x5c,
        0xaf, 0x0d, 0xa9, 0xe7, 0x27, 0xc0, 0xd7, 0x3b, 0xb5, 0xb5, 0xa8, 0xf3, 0x33, 0xb0, 0x68,
        0x17, 0x7e, 0x68, 0xfc, 0xab, 0xf4, 0x32, 0x7d, 0x01, 0x0d, 0x29, 0x06, 0xd7, 0xe3, 0xde,
        0xd2, 0xba, 0xcc, 0x8b, 0x0e, 0x5a, 0xa4, 0x02, 0x1f, 0xc6, 0x59, 0x6f, 0xb4, 0xcb, 0xdf,
        0x77, 0xba, 0x92, 0x65, 0x6d, 0xfb, 0xaa, 0x2a, 0xb4, 0x7b, 0xf0, 0xb3, 0xd1, 0x97, 0xde,
        0x09, 0x88, 0x0a, 0xbd, 0x9b, 0xe0, 0x7a, 0x47, 0x75, 0x86, 0xc2, 0x76, 0xca, 0xe9, 0xe5,
        0x4e, 0x98, 0x4f, 0x58, 0xed, 0xf4, 0x93, 0x89, 0x51, 0xff, 0x2f, 0x53, 0x29, 0x3c, 0x26,
        0xb4, 0xb2, 0xee, 0x95, 0x08, 0xb8, 0x85, 0x52, 0x64, 0xe5, 0x33, 0x81, 0x76, 0x1b, 0xb2,
        0x48, 0x60, 0x04, 0x0b, 0x83, 0x82, 0x46, 0x82, 0x05, 0x63, 0xc8, 0x11, 0x6e, 0xa6, 0x55,
        0x9c, 0xd2, 0x09, 0x36, 0x0f, 0xc3, 0x92, 0x53, 0x46, 0x06, 0x8d, 0x43, 0xe3, 0x50, 0x9b,
        0xf0, 0x70, 0x0f, 0xec, 0xb6, 0xa1, 0x54, 0x73, 0xaf, 0x53, 0xaf, 0x31, 0xdb, 0xa8, 0xc6,
        0x96, 0xd3, 0xb5, 0xd2, 0xf7, 0x3a, 0x3f, 0x30, 0xbb, 0xb7, 0x44, 0xd8, 0xe4, 0x4d, 0x14,
        0x5c, 0x4b, 0xab, 0x68, 0x38, 0x00, 0x4f, 0x8f, 0x5f, 0xd3, 0xe1, 0xb1, 0x58, 0x20, 0x64,
        0xf9, 0xf6, 0x27, 0x4f, 0xea, 0x39, 0xe8, 0x5e, 0x03, 0x04, 0xa9, 0x3d, 0x17, 0xef, 0x00,
        0x2c, 0x5b, 0xd5, 0x15, 0x3a, 0x43, 0x76, 0x8b, 0x06, 0x22, 0x0c, 0xa5, 0x0a, 0x9f, 0xd1,
        0xaf, 0xd6, 0x3b, 0x4e, 0xa6, 0x99, 0xe7, 0xc0, 0x6d, 0xbd, 0x35, 0xe6, 0xbc, 0xa8, 0xf6,
        0xd6, 0x21, 0xda, 0xae, 0x33, 0x12, 0xcc, 0xb2, 0xef, 0x5b, 0x50, 0x92, 0xe2, 0xf4, 0xf8,
        0x8e, 0x9e, 0xd1, 0x3e, 0xfc, 0x1e, 0xff, 0xc1, 0xdf, 0x4a, 0x8e, 0x11, 0x96, 0x56, 0x68,
        0xd6, 0xde, 0x19, 0x8c, 0x51, 0xb1, 0x26, 0x6f, 0x04, 0x3b, 0x93, 0x39, 0x97, 0x74, 0xd5,
        0x5a, 0x20, 0xa1, 0x9a, 0x3b, 0x32, 0x06, 0xe4, 0x4a, 0x32, 0xc3, 0xee, 0x11, 0xd3, 0x1d,
        0xeb, 0x00, 0xd4, 0x58, 0x4a, 0xbe, 0x3a, 0x82, 0x36, 0xb7, 0x20, 0x71, 0xdc, 0xd6, 0x70,
        0xc0, 0x46, 0x67, 0x03, 0x70, 0x1f, 0x86, 0x15, 0x11, 0xea, 0x51, 0x8c, 0xfb, 0x8b, 0xb5,
        0x08, 0x7b, 0x5e, 0x5e, 0x80, 0x7f, 0x18, 0x96, 0xb5, 0x9b, 0x3f, 0xca, 0xa1, 0xcc, 0xfe,
        0x73, 0x9c, 0x05, 0x49, 0x19, 0xee, 0x70, 0x90, 0x00, 0x6e, 0x7a, 0x9c, 0x1e, 0xdb, 0x9c,
        0x90, 0x2a, 0x77, 0x41, 0x95, 0xa0, 0x3f, 0x8a, 0x2b, 0xec, 0x9b, 0xc1, 0xc8, 0x22, 0xc4,
        0xd0, 0xf1, 0x4d, 0xc1, 0x3c, 0x31, 0x46, 0xd9, 0xe9, 0xc4, 0x71, 0x51, 0xc7, 0x60, 0x14,
        0x2d, 0x86, 0x1c, 0xc2, 0x25, 0xbc, 0x40, 0x8d, 0x2c, 0x22, 0x8f, 0x34, 0xc3, 0x40, 0x23,
        0x21, 0x1c, 0x31, 0x71, 0x53, 0x70, 0x1c, 0xfc, 0x09, 0x9b, 0x81, 0x4b, 0x0f, 0x90, 0xd8,
        0x53, 0x87, 0xf1, 0x83, 0xbd, 0xe9, 0x13, 0xa2, 0x66, 0x11, 0xa3, 0xf4, 0xe7, 0x43, 0x36,
        0x5b, 0x93, 0xb4, 0xc0, 0xaa, 0x05, 0xa5, 0xbc, 0x28, 0x48, 0x97, 0xdf, 0xc5, 0xae, 0x6a,
        0xba, 0xbb, 0xeb, 0x40, 0x30, 0xfb, 0x32, 0x54, 0x5d, 0x51, 0x4e, 0x0b, 0x9b, 0xa3, 0x66,
        0x29, 0x87, 0x69, 0x6f, 0x70, 0x3f, 0x31, 0xc8, 0x70, 0x73, 0x9f, 0x22, 0x4c, 0x4d, 0x7b,
        0xd9, 0x78, 0xdb, 0xa6, 0xa8, 0xaf, 0x71, 0x7a, 0x9f, 0xe6, 0x0b, 0x71, 0x55, 0x58, 0x0e,
        0x13, 0x03, 0x54, 0xef, 0x7d, 0xba, 0x84, 0xd5, 0x0c, 0x4d, 0x65, 0x9c, 0xa5, 0xd7, 0x74,
        0x57, 0x80, 0x5d, 0xc9, 0x92, 0x53, 0x68, 0x37, 0x5c, 0xc5, 0x35, 0xc7, 0x93, 0xdc, 0x7c,
        0x3b, 0xfc, 0x65, 0xd1, 0xca, 0xa5, 0x0e, 0x7c, 0x9d, 0xf4, 0x73, 0xa6, 0x38, 0x22, 0x01,
        0xdf, 0xf0, 0xf1, 0x69, 0x47, 0x62, 0xdc, 0x58, 0x78, 0x2a, 0xce, 0x00, 0x27, 0x0c, 0xa6,
        0xe8, 0x38, 0x61, 0x8f, 0xa5, 0x5e, 0x51, 0xe3, 0x1b, 0x94, 0x14, 0x55, 0xdc, 0xa2, 0x4d,
        0x11, 0xe4, 0x70, 0x2a, 0x61, 0x24, 0x9b, 0x69, 0xa6, 0x4d, 0x38, 0xda, 0xa9, 0x28, 0xe0,
        0x14, 0xe5, 0x04, 0x78, 0x83, 0x26, 0x1a, 0x9e, 0xe8, 0x0e, 0x64, 0xa9, 0xc1, 0x3c, 0x8f,
        0xd4, 0x30, 0x3b, 0xbb, 0x8d, 0x9a, 0x68, 0xe9, 0xc5, 0x2f, 0xc9, 0xec, 0x9b, 0x56, 0x4b,
        0xa0, 0xb2, 0x51, 0x68, 0x38, 0x42, 0x22, 0x5b, 0x4d, 0x66, 0xb4, 0x74, 0x3a, 0x18, 0x1d,
        0xe1, 0x25, 0xc1, 0x63, 0xac, 0xb3, 0x0c, 0xd7, 0x98, 0xdd, 0xb8, 0xf2, 0xd2, 0x27, 0xb1,
        0x08, 0x03, 0x39, 0x88, 0x0e, 0xdc, 0x13, 0xcd, 0xac, 0xf6, 0xfc, 0x70, 0x4a, 0x0a, 0x6c,
        0x7b, 0xce, 0xeb, 0x63, 0xd6, 0xf1, 0x20, 0x7b, 0x81, 0x47, 0x53, 0x57, 0x3d, 0xec, 0x6e,
        0x52, 0xba, 0x41, 0x00, 0x96, 0xbc, 0x42, 0x7f, 0xed, 0x1b, 0x2e, 0x7d, 0x69, 0x90, 0xc7,
        0x17, 0xc8, 0xf3, 0x1b, 0x32, 0x6e, 0x97, 0x5a, 0xbc, 0x0f, 0xe4, 0x86, 0xc5, 0x50, 0x58,
        0xf1, 0x6f, 0x2d, 0xf8, 0xd3, 0x03, 0x6f, 0x08, 0xb1, 0xbd, 0xed, 0xbd, 0xa4, 0x82, 0xc4,
        0xa6, 0xa3, 0xde, 0x86, 0xba, 0xb5, 0x9c, 0x5a, 0x5e, 0x62, 0x18, 0xd1, 0x70, 0xe1, 0x94,
        0x27, 0xa5, 0xc4, 0xa4, 0x91, 0xa1, 0xb7, 0x5e, 0x4b, 0x97, 0x22, 0xf0, 0x5a, 0x76, 0xe2,
        0xfe, 0xe4, 0x36, 0x41, 0x35, 0xff, 0x81, 0x1c, 0x88, 0xf0, 0xba, 0xa3, 0x7a, 0x30, 0x10,
        0x64, 0xd5, 0x59, 0xc8, 0x68, 0x43, 0x93, 0x60, 0xc0, 0x92, 0x47, 0x3c, 0xd3, 0xd6, 0xa6,
        0xfc, 0x0a, 0x09, 0xdf, 0x60, 0xb0, 0xd2, 0xb4, 0xb4, 0xb8, 0x2d, 0xc0, 0x72, 0x1b, 0x70,
        0xc0, 0xa8, 0x93, 0x89, 0x53, 0xe1, 0xa5, 0xbe, 0x87, 0x0f, 0xc0, 0xd5, 0x5f, 0x9d, 0xf5,
        0x0f, 0x04, 0x0a, 0xd7, 0x98, 0xdb, 0x59, 0x3e, 0x3f, 0x0e, 0xbe, 0x42, 0xe9, 0x2e, 0x84,
        0x75, 0xb0, 0x2b, 0xc5, 0x7c, 0x44, 0x31, 0x47, 0xc2, 0x6a, 0x3d, 0xd3, 0x33, 0x15, 0xf4,
        0x8d, 0xce, 0xde, 0x74, 0xf9, 0x80, 0x0a, 0xe6, 0x27, 0x8b, 0x04, 0xef, 0x5c, 0x7b, 0x56,
        0x01, 0x66, 0x7a, 0xe7, 0xaa, 0x4f, 0x39, 0x08, 0xb3, 0x16, 0x78, 0xe0, 0xf9, 0x03, 0xd3,
        0xf9, 0x9b, 0x35, 0x33, 0x91, 0x6d, 0x53, 0xf9, 0x71, 0x44, 0xef, 0x44, 0x56, 0x79, 0x26,
        0xd7, 0x54, 0x59, 0x22, 0x6c, 0xa6, 0xd0, 0x33, 0xf6, 0x40, 0x95, 0x47, 0x06, 0x30, 0x4a,
        0xd2, 0xd4, 0x07, 0x3d, 0x3d, 0xc7, 0xf4, 0xa1, 0x56, 0x8a, 0x54, 0x40, 0xd8, 0x4b, 0x51,
        0x91, 0xbb, 0xa6, 0x03, 0x39, 0x4c, 0x2b, 0xc7, 0x4b, 0x76, 0xc1, 0x41, 0x37, 0xc0, 0x6b,
        0x4b, 0xab, 0x28, 0xd0, 0x24, 0x1b, 0xdd, 0x2a, 0x46, 0x9e, 0x40, 0x12, 0x8c, 0xde, 0xa8,
        0x18, 0x33, 0x55, 0x9e, 0x77, 0x36, 0xba, 0x2a, 0x79, 0x1c, 0x7f, 0xff, 0x74, 0x1e, 0x7a,
        0x84, 0xc6, 0x32, 0x83, 0x19, 0xcf, 0xc4, 0xdc, 0xe1, 0x80, 0x90, 0x6d, 0x19, 0xcb, 0x9e,
        0x07, 0x3a, 0xef, 0x20, 0xa0, 0xc4, 0xc7, 0x11, 0x39, 0x08, 0x18, 0x90, 0xc5, 0xd0, 0xa2,
        0x05, 0x10, 0x47, 0x40, 0x3d, 0x14, 0x6f, 0x78, 0xe9, 0x54, 0xa0, 0xbf, 0x9f, 0x9a, 0x88,
        0x1a, 0x6f, 0x12, 0x87, 0xf6, 0x75, 0x7e, 0x92, 0x59, 0x82, 0x33, 0xe6, 0xc7, 0x66, 0xf0,
        0x55, 0x50, 0x4c, 0x0b, 0x2e, 0xa4, 0xca, 0x8f, 0x46, 0x4b, 0x1a, 0x96, 0x24, 0xf8, 0x6b,
        0x76, 0xfd, 0x1b, 0x4c, 0x54, 0xd4, 0x90, 0xf3, 0x47, 0x7a, 0x64, 0x0f, 0x9a, 0xc4, 0x74,
        0xd1, 0x06, 0xc1, 0x9e, 0xad, 0xbd, 0x58, 0xaa, 0xa6, 0x1d, 0x88, 0x57, 0xbc, 0x2a, 0xc0,
        0x89, 0xea, 0x74, 0x7f, 0xe5, 0xc2, 0xd6, 0xa2, 0x63, 0x30, 0xdd, 0xf3, 0x46, 0x40, 0x73,
        0x1a, 0x21, 0x77, 0x3e, 0xf8, 0xce, 0xb5, 0x64, 0x31, 0xf5, 0xa3, 0x52, 0xf2, 0xbc, 0xf7,
        0xa1, 0xe6, 0x24, 0xeb, 0x7a, 0x97, 0x47, 0xfe, 0x0d, 0x8a, 0xc8, 0x33, 0xbd, 0x16, 0x70,
        0x6b, 0xe5, 0xcf, 0x5b, 0xb4, 0x16, 0x46, 0x19, 0x98, 0x0e, 0x17, 0x2d, 0x00, 0xa7, 0xe0,
        0x86, 0x67, 0xb9, 0xcf, 0xab, 0x8b, 0x6e, 0x4b, 0xf3, 0x71, 0x72, 0xfd, 0x37, 0x3c, 0x83,
        0xe8, 0x80, 0x2c, 0xd2, 0x4d, 0x2e, 0xad, 0xf3, 0xfb, 0xa2, 0x18, 0xae, 0xc6, 0x82, 0xb3,
        0x34, 0x45, 0xd7, 0x13, 0xb6, 0xdd, 0x5b, 0xd3, 0x6f, 0x2d, 0xc0, 0xf6, 0x57, 0x4a, 0xc0,
        0x7f, 0x40, 0xa2, 0xdd, 0x20, 0xee, 0xff, 0x6b, 0x6b, 0x14, 0xd7, 0x24, 0xcf, 0x20, 0xed,
        0x05, 0xf0, 0x30, 0x3d, 0xf0, 0xd1, 0x8d, 0xa1, 0xb4, 0x8a, 0x9d, 0x48, 0xd5, 0x1d, 0x3c,
        0x65, 0xed, 0xea, 0xd7, 0x75, 0xdd, 0x5d, 0x1a, 0x8f, 0xc9, 0x94, 0xd7, 0xf6, 0xfe, 0x51,
        0x67, 0xef, 0xd2, 0x14, 0x35, 0x44, 0x00, 0x06, 0x35, 0x4a, 0x27, 0x8e, 0x29, 0xd3, 0x72,
        0xb6, 0x72, 0x64, 0xad, 0xd5, 0xea, 0x89, 0xae, 0xcd, 0xef, 0x6c, 0x5f, 0x96, 0xa6, 0x3e,
        0xdd, 0x99, 0xdc, 0x13, 0x43, 0x15, 0xe3, 0x74, 0x91, 0xf1, 0x89, 0xc0, 0x86, 0x6a, 0x78,
        0x2b, 0x1a, 0x4b, 0x22, 0xa0, 0xc5, 0x02, 0xcb, 0x81, 0x2f, 0xe7, 0xf8, 0x98, 0xa7, 0x0d,
        0x83, 0x8f, 0x48, 0x9d, 0x0a, 0xf2, 0x63, 0xa9, 0x4b, 0xaf, 0x02, 0x30, 0x1a, 0xfe, 0x52,
        0x9f, 0xea, 0x5b, 0x8a, 0x0c, 0x12, 0xf9, 0x36, 0x39, 0x1d, 0xb0, 0x08, 0x41, 0xbb, 0x18,
        0xd1, 0xca, 0x9d, 0xf6, 0x38, 0x0a, 0xe1, 0x36, 0x15, 0x07, 0xde, 0x93, 0xb4, 0x82, 0x32,
        0x1f, 0x88, 0x3a, 0xd7, 0x61, 0x82, 0x7d, 0x1d, 0xa4, 0x7b, 0x59, 0x71, 0x22, 0xe4, 0xdd,
        0xb9, 0x44, 0x13, 0xf9, 0x4c, 0x5a, 0xad, 0xed, 0x73, 0x74, 0x3d, 0x94, 0xcc, 0xca, 0x9f,
        0x7b, 0x6a, 0x4b, 0x59, 0x28, 0xfe, 0x5c, 0x48, 0x5c, 0x98, 0x08, 0x05, 0x0e, 0x1c, 0xf7,
        0x6a, 0xc9, 0x49, 0x19, 0x44, 0x92, 0xa9, 0x7b, 0x39, 0xa9, 0xd9, 0x59, 0x85, 0xef, 0xe7,
        0x25, 0x44, 0x8a, 0xdd, 0xc0, 0x02, 0x53, 0xa0, 0x71, 0xb6, 0x06, 0xad, 0x97, 0xb6, 0x7e,
        0x0a, 0xc5, 0x0d, 0x77, 0xf6, 0x4c, 0x5c, 0x58, 0xf2, 0x95, 0x22, 0x59, 0x09, 0x8e, 0x28,
        0x3b, 0x36, 0x6d, 0x9c, 0x9b, 0x4f, 0x79, 0xb1, 0x99, 0x03, 0xfe, 0x35, 0x28, 0xbf, 0xf4,
        0x3a, 0xf7, 0x10, 0xda, 0x84, 0x2b, 0x9f, 0xb4, 0x8a, 0xea, 0x87, 0x76, 0xba, 0x0e, 0x6c,
        0xf0, 0x01, 0xb8, 0xe7, 0x8a, 0x1d, 0xf4, 0xc2, 0xfe, 0xd2, 0x07, 0xe1, 0xa1, 0x17, 0x70,
        0xe2, 0x8b, 0x03, 0xc1, 0xbc, 0x66, 0x28, 0x0f, 0xbd, 0xa1, 0x5d, 0x49, 0xad, 0x54, 0xb4,
        0xdf, 0x5d, 0xf5, 0x9c, 0xf9, 0xa0, 0x8d, 0x3b, 0x17, 0xaf, 0x7c, 0x43, 0x44, 0x8a, 0xe5,
        0x20, 0x3d, 0x1d, 0xe7, 0xe2, 0xee, 0x5c, 0x8a, 0xe7, 0x6a, 0x2f, 0x63, 0x78, 0x7c, 0x82,
        0x1c, 0x6a, 0x76, 0x76, 0xc5, 0xdc, 0xad, 0xfd, 0xae, 0x79, 0xff, 0x49, 0xc1, 0xc1, 0xd5,
        0x85, 0xd0, 0x2e, 0x7c, 0x96, 0x36, 0x65, 0x63, 0xae, 0x12, 0xa7, 0xee, 0x3c, 0xd8, 0xfa,
        0x98,
    ];
}
