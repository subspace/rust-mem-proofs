mod utils;

use crate::Piece;
use crate::PIECE_SIZE;
use rayon::prelude::*;
use std::convert::TryInto;
use std::io::Write;

const BLOCK_SIZE_BITS: u32 = 24;
pub const BLOCK_SIZE: usize = 3;
const AES_SBOX: [u8; 256] = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
];

type Block = [u8; 3];

pub struct SBoxDirect(Vec<Block>);

impl SBoxDirect {
    /// Create direct SBox used for encoding
    pub fn new() -> Self {
        let mut result = vec![[0_u8; 3]; 2_usize.pow(BLOCK_SIZE_BITS)];

        for x in 0..2_u32.pow(BLOCK_SIZE_BITS) {
            let [.., x1, x2, x3] = x.to_be_bytes();
            result[x as usize] = [
                AES_SBOX[x1 as usize],
                AES_SBOX[x2 as usize],
                AES_SBOX[x3 as usize],
            ];
        }

        Self(result)
    }

    fn get(&self, x: Block) -> Block {
        let index = u32::from_be_bytes([0, x[0], x[1], x[2]]);
        self.0[index as usize]
    }
}

pub struct SBoxInverse(Vec<Block>);

impl SBoxInverse {
    /// Create inverse SBox used for decoding
    pub fn new() -> Self {
        let mut result = vec![[0_u8; 3]; 2_usize.pow(BLOCK_SIZE_BITS)];

        for x in 0..2_u32.pow(BLOCK_SIZE_BITS) {
            let [.., x1, x2, x3] = x.to_be_bytes();
            let y = u32::from_be_bytes([
                0,
                AES_SBOX[x1 as usize],
                AES_SBOX[x2 as usize],
                AES_SBOX[x3 as usize],
            ]);
            result[y as usize] = [x1, x2, x3];
        }

        Self(result)
    }

    fn get(&self, y: Block) -> Block {
        let index = u32::from_be_bytes([0, y[0], y[1], y[2]]);
        self.0[index as usize]
    }
}

pub fn encode_simple(piece: &mut Piece, iv: Block, breadth_iterations: usize, sbox: &SBoxDirect) {
    let mut feedback = iv;
    for _ in 0..breadth_iterations {
        piece.chunks_exact_mut(BLOCK_SIZE).for_each(|mut block| {
            feedback = sbox.get([
                block[0] ^ feedback[0],
                block[1] ^ feedback[1],
                block[2] ^ feedback[2],
            ]);

            block.write_all(&feedback[..]).unwrap();
        });
    }
}

pub fn encode_pipelined_x4(
    pieces: [&mut Piece; 4],
    ivs: [Block; 4],
    breadth_iterations: usize,
    sbox: &SBoxDirect,
) {
    let mut feedbacks = ivs;
    let [piece1, piece2, piece3, piece4] = pieces;
    for _ in 0..breadth_iterations {
        piece1
            .chunks_exact_mut(BLOCK_SIZE)
            .zip(piece2.chunks_exact_mut(BLOCK_SIZE))
            .zip(piece3.chunks_exact_mut(BLOCK_SIZE))
            .zip(piece4.chunks_exact_mut(BLOCK_SIZE))
            .map(|(((block1, block2), block3), block4)| [block1, block2, block3, block4])
            .for_each(|mut blocks| {
                blocks
                    .iter_mut()
                    .zip(feedbacks.iter_mut())
                    .for_each(|(block, feedback)| {
                        *feedback = sbox.get([
                            block[0] ^ feedback[0],
                            block[1] ^ feedback[1],
                            block[2] ^ feedback[2],
                        ]);
                        block.write_all(&feedback[..]).unwrap();
                    });
            });
    }
}

pub fn encode_pipelined_x8(
    pieces: [&mut Piece; 8],
    ivs: [Block; 8],
    breadth_iterations: usize,
    sbox: &SBoxDirect,
) {
    let mut feedbacks = ivs;
    let [piece1, piece2, piece3, piece4, piece5, piece6, piece7, piece8] = pieces;
    for _ in 0..breadth_iterations {
        piece1
            .chunks_exact_mut(BLOCK_SIZE)
            .zip(piece2.chunks_exact_mut(BLOCK_SIZE))
            .zip(piece3.chunks_exact_mut(BLOCK_SIZE))
            .zip(piece4.chunks_exact_mut(BLOCK_SIZE))
            .zip(piece5.chunks_exact_mut(BLOCK_SIZE))
            .zip(piece6.chunks_exact_mut(BLOCK_SIZE))
            .zip(piece7.chunks_exact_mut(BLOCK_SIZE))
            .zip(piece8.chunks_exact_mut(BLOCK_SIZE))
            .map(
                |(((((((block1, block2), block3), block4), block5), block6), block7), block8)| {
                    [
                        block1, block2, block3, block4, block5, block6, block7, block8,
                    ]
                },
            )
            .for_each(|mut blocks| {
                blocks
                    .iter_mut()
                    .zip(feedbacks.iter_mut())
                    .for_each(|(block, feedback)| {
                        *feedback = sbox.get([
                            block[0] ^ feedback[0],
                            block[1] ^ feedback[1],
                            block[2] ^ feedback[2],
                        ]);
                        block.write_all(&feedback[..]).unwrap();
                    });
            });
    }
}

pub fn encode_pipelined_x8_hack(
    pieces: &mut [Piece],
    ivs: &[Block],
    breadth_iterations: usize,
    sbox: &SBoxDirect,
) {
    assert!(pieces.len() == ivs.len());

    let mut feedbacks = ivs.to_owned();
    let (piece1, pieces) = pieces.split_first_mut().unwrap();
    let (piece2, pieces) = pieces.split_first_mut().unwrap();
    let (piece3, pieces) = pieces.split_first_mut().unwrap();
    let (piece4, pieces) = pieces.split_first_mut().unwrap();
    let (piece5, pieces) = pieces.split_first_mut().unwrap();
    let (piece6, pieces) = pieces.split_first_mut().unwrap();
    let (piece7, pieces) = pieces.split_first_mut().unwrap();
    let (piece8, _) = pieces.split_first_mut().unwrap();
    for _ in 0..breadth_iterations {
        piece1
            .chunks_exact_mut(BLOCK_SIZE)
            .zip(piece2.chunks_exact_mut(BLOCK_SIZE))
            .zip(piece3.chunks_exact_mut(BLOCK_SIZE))
            .zip(piece4.chunks_exact_mut(BLOCK_SIZE))
            .zip(piece5.chunks_exact_mut(BLOCK_SIZE))
            .zip(piece6.chunks_exact_mut(BLOCK_SIZE))
            .zip(piece7.chunks_exact_mut(BLOCK_SIZE))
            .zip(piece8.chunks_exact_mut(BLOCK_SIZE))
            .map(
                |(((((((block1, block2), block3), block4), block5), block6), block7), block8)| {
                    [
                        block1, block2, block3, block4, block5, block6, block7, block8,
                    ]
                },
            )
            .for_each(|mut blocks| {
                blocks
                    .iter_mut()
                    .zip(feedbacks.iter_mut())
                    .for_each(|(block, feedback)| {
                        *feedback = sbox.get([
                            block[0] ^ feedback[0],
                            block[1] ^ feedback[1],
                            block[2] ^ feedback[2],
                        ]);
                        block.write_all(&feedback[..]).unwrap();
                    });
            });
    }
}

pub fn encode_pipelined_x16(
    pieces: [&mut Piece; 16],
    ivs: [Block; 16],
    breadth_iterations: usize,
    sbox: &SBoxDirect,
) {
    let mut feedbacks = ivs;
    let [piece1, piece2, piece3, piece4, piece5, piece6, piece7, piece8, piece9, piece10, piece11, piece12, piece13, piece14, piece15, piece16] =
        pieces;
    for _ in 0..breadth_iterations {
        piece1
            .chunks_exact_mut(BLOCK_SIZE)
            .zip(piece2.chunks_exact_mut(BLOCK_SIZE))
            .zip(piece3.chunks_exact_mut(BLOCK_SIZE))
            .zip(piece4.chunks_exact_mut(BLOCK_SIZE))
            .zip(piece5.chunks_exact_mut(BLOCK_SIZE))
            .zip(piece6.chunks_exact_mut(BLOCK_SIZE))
            .zip(piece7.chunks_exact_mut(BLOCK_SIZE))
            .zip(piece8.chunks_exact_mut(BLOCK_SIZE))
            .zip(piece9.chunks_exact_mut(BLOCK_SIZE))
            .zip(piece10.chunks_exact_mut(BLOCK_SIZE))
            .zip(piece11.chunks_exact_mut(BLOCK_SIZE))
            .zip(piece12.chunks_exact_mut(BLOCK_SIZE))
            .zip(piece13.chunks_exact_mut(BLOCK_SIZE))
            .zip(piece14.chunks_exact_mut(BLOCK_SIZE))
            .zip(piece15.chunks_exact_mut(BLOCK_SIZE))
            .zip(piece16.chunks_exact_mut(BLOCK_SIZE))
            .map(
                |(
                    (
                        (
                            (
                                (
                                    (
                                        (
                                            (
                                                (
                                                    (
                                                        (
                                                            (
                                                                (
                                                                    ((block1, block2), block3),
                                                                    block4,
                                                                ),
                                                                block5,
                                                            ),
                                                            block6,
                                                        ),
                                                        block7,
                                                    ),
                                                    block8,
                                                ),
                                                block9,
                                            ),
                                            block10,
                                        ),
                                        block11,
                                    ),
                                    block12,
                                ),
                                block13,
                            ),
                            block14,
                        ),
                        block15,
                    ),
                    block16,
                )| {
                    [
                        block1, block2, block3, block4, block5, block6, block7, block8, block9,
                        block10, block11, block12, block13, block14, block15, block16,
                    ]
                },
            )
            .for_each(|mut blocks| {
                blocks
                    .iter_mut()
                    .zip(feedbacks.iter_mut())
                    .for_each(|(block, feedback)| {
                        *feedback = sbox.get([
                            block[0] ^ feedback[0],
                            block[1] ^ feedback[1],
                            block[2] ^ feedback[2],
                        ]);
                        block.write_all(&feedback[..]).unwrap();
                    });
            });
    }
}

pub fn encode_simple_parallel(
    pieces: &mut [Piece],
    iv: Block,
    breadth_iterations: usize,
    sbox: &SBoxDirect,
    thread_pipelining: usize,
) {
    pieces
        .par_chunks_mut(thread_pipelining)
        .for_each(|pieces: &mut [Piece]| {
            for piece in pieces {
                encode_simple(piece, iv, breadth_iterations, sbox);
            }
        });
}

pub fn encode_pipelined_x8_parallel(
    pieces: &mut [Piece],
    ivs: &[Block],
    breadth_iterations: usize,
    sbox: &SBoxDirect,
) {
    assert!(pieces.len() % 8 == 0);

    pieces
        .par_chunks_mut(8)
        .zip_eq(ivs.par_chunks(8))
        .for_each(|(pieces, ivs)| encode_pipelined_x8_hack(pieces, ivs, breadth_iterations, sbox));
}

pub fn decode_simple(piece: &mut Piece, iv: Block, breadth_iterations: usize, sbox: &SBoxInverse) {
    for _ in 1..breadth_iterations {
        decode_internal(piece, None, sbox);
    }

    decode_internal(piece, Some(iv), sbox);
}

fn decode_internal(piece: &mut Piece, iv: Option<Block>, sbox: &SBoxInverse) {
    for i in (1..(PIECE_SIZE / BLOCK_SIZE)).rev() {
        let (block, feedback) = utils::piece_to_blocks_and_feedback(piece, i);

        decode_block_internal(block, feedback, sbox);
    }

    let (first_block, feedback) = utils::piece_to_first_blocks_and_feedback(piece, iv);
    decode_block_internal(first_block, &feedback, sbox);
}

fn decode_block_internal(block: &mut [u8], feedback: &Block, sbox: &SBoxInverse) {
    let decoded = sbox.get([block[0], block[1], block[2]]);

    block[0] = decoded[0] ^ feedback[0];
    block[1] = decoded[1] ^ feedback[1];
    block[2] = decoded[2] ^ feedback[2];
}

pub fn decode_pipelined(
    piece: &mut Piece,
    iv: Block,
    breadth_iterations: usize,
    sbox: &SBoxInverse,
) {
    for _ in 1..breadth_iterations {
        decode_pipelined_internal(piece, None, sbox);
    }

    decode_pipelined_internal(piece, Some(iv), sbox);
}

fn decode_pipelined_internal(piece: &mut Piece, iv: Option<Block>, sbox: &SBoxInverse) {
    let pipelining_factor = 8;
    // 8 is our pipelining factor
    let (sub_piece_1, remainder) =
        piece.split_at_mut(PIECE_SIZE / pipelining_factor / BLOCK_SIZE * BLOCK_SIZE);
    let (sub_piece_2, remainder) =
        remainder.split_at_mut(PIECE_SIZE / pipelining_factor / BLOCK_SIZE * BLOCK_SIZE);
    let (sub_piece_3, remainder) =
        remainder.split_at_mut(PIECE_SIZE / pipelining_factor / BLOCK_SIZE * BLOCK_SIZE);
    let (sub_piece_4, remainder) =
        remainder.split_at_mut(PIECE_SIZE / pipelining_factor / BLOCK_SIZE * BLOCK_SIZE);
    let (sub_piece_5, remainder) =
        remainder.split_at_mut(PIECE_SIZE / pipelining_factor / BLOCK_SIZE * BLOCK_SIZE);
    let (sub_piece_6, remainder) =
        remainder.split_at_mut(PIECE_SIZE / pipelining_factor / BLOCK_SIZE * BLOCK_SIZE);
    let (sub_piece_7, remainder) =
        remainder.split_at_mut(PIECE_SIZE / pipelining_factor / BLOCK_SIZE * BLOCK_SIZE);
    let (sub_piece_8, sub_piece_last) =
        remainder.split_at_mut(PIECE_SIZE / pipelining_factor / BLOCK_SIZE * BLOCK_SIZE);

    let feedback_2 = sub_piece_1[(sub_piece_1.len() - BLOCK_SIZE)..]
        .try_into()
        .unwrap();
    let feedback_3 = sub_piece_2[(sub_piece_2.len() - BLOCK_SIZE)..]
        .try_into()
        .unwrap();
    let feedback_4 = sub_piece_3[(sub_piece_3.len() - BLOCK_SIZE)..]
        .try_into()
        .unwrap();
    let feedback_5 = sub_piece_4[(sub_piece_4.len() - BLOCK_SIZE)..]
        .try_into()
        .unwrap();
    let feedback_6 = sub_piece_5[(sub_piece_5.len() - BLOCK_SIZE)..]
        .try_into()
        .unwrap();
    let feedback_7 = sub_piece_6[(sub_piece_6.len() - BLOCK_SIZE)..]
        .try_into()
        .unwrap();
    let feedback_8 = sub_piece_7[(sub_piece_7.len() - BLOCK_SIZE)..]
        .try_into()
        .unwrap();
    let feedback_last = sub_piece_8[(sub_piece_8.len() - BLOCK_SIZE)..]
        .try_into()
        .unwrap();

    for i in (1..(PIECE_SIZE / pipelining_factor / BLOCK_SIZE)).rev() {
        let (ends_with_feedback_1, starts_with_block_1) = sub_piece_1.split_at_mut(i * BLOCK_SIZE);
        let (ends_with_feedback_2, starts_with_block_2) = sub_piece_2.split_at_mut(i * BLOCK_SIZE);
        let (ends_with_feedback_3, starts_with_block_3) = sub_piece_3.split_at_mut(i * BLOCK_SIZE);
        let (ends_with_feedback_4, starts_with_block_4) = sub_piece_4.split_at_mut(i * BLOCK_SIZE);
        let (ends_with_feedback_5, starts_with_block_5) = sub_piece_5.split_at_mut(i * BLOCK_SIZE);
        let (ends_with_feedback_6, starts_with_block_6) = sub_piece_6.split_at_mut(i * BLOCK_SIZE);
        let (ends_with_feedback_7, starts_with_block_7) = sub_piece_7.split_at_mut(i * BLOCK_SIZE);
        let (ends_with_feedback_8, starts_with_block_8) = sub_piece_8.split_at_mut(i * BLOCK_SIZE);

        let feedback_1 = ends_with_feedback_1[(ends_with_feedback_1.len() - BLOCK_SIZE)..]
            .as_ref()
            .try_into()
            .unwrap();
        let feedback_2 = ends_with_feedback_2[(ends_with_feedback_2.len() - BLOCK_SIZE)..]
            .as_ref()
            .try_into()
            .unwrap();
        let feedback_3 = ends_with_feedback_3[(ends_with_feedback_3.len() - BLOCK_SIZE)..]
            .as_ref()
            .try_into()
            .unwrap();
        let feedback_4 = ends_with_feedback_4[(ends_with_feedback_4.len() - BLOCK_SIZE)..]
            .as_ref()
            .try_into()
            .unwrap();
        let feedback_5 = ends_with_feedback_5[(ends_with_feedback_5.len() - BLOCK_SIZE)..]
            .as_ref()
            .try_into()
            .unwrap();
        let feedback_6 = ends_with_feedback_6[(ends_with_feedback_6.len() - BLOCK_SIZE)..]
            .as_ref()
            .try_into()
            .unwrap();
        let feedback_7 = ends_with_feedback_7[(ends_with_feedback_7.len() - BLOCK_SIZE)..]
            .as_ref()
            .try_into()
            .unwrap();
        let feedback_8 = ends_with_feedback_8[(ends_with_feedback_8.len() - BLOCK_SIZE)..]
            .as_ref()
            .try_into()
            .unwrap();

        let (block_1, _) = starts_with_block_1.split_at_mut(BLOCK_SIZE);
        let (block_2, _) = starts_with_block_2.split_at_mut(BLOCK_SIZE);
        let (block_3, _) = starts_with_block_3.split_at_mut(BLOCK_SIZE);
        let (block_4, _) = starts_with_block_4.split_at_mut(BLOCK_SIZE);
        let (block_5, _) = starts_with_block_5.split_at_mut(BLOCK_SIZE);
        let (block_6, _) = starts_with_block_6.split_at_mut(BLOCK_SIZE);
        let (block_7, _) = starts_with_block_7.split_at_mut(BLOCK_SIZE);
        let (block_8, _) = starts_with_block_8.split_at_mut(BLOCK_SIZE);

        decode_block_internal(block_1, feedback_1, sbox);
        decode_block_internal(block_2, feedback_2, sbox);
        decode_block_internal(block_3, feedback_3, sbox);
        decode_block_internal(block_4, feedback_4, sbox);
        decode_block_internal(block_5, feedback_5, sbox);
        decode_block_internal(block_6, feedback_6, sbox);
        decode_block_internal(block_7, feedback_7, sbox);
        decode_block_internal(block_8, feedback_8, sbox);
    }

    // Because piece size is not a multiple of block and pipelining factor, we have 5 more elements
    // remaining here
    let (sub_piece_last_1, remainder) = sub_piece_last.split_at_mut(BLOCK_SIZE);
    let (sub_piece_last_2, remainder) = remainder.split_at_mut(BLOCK_SIZE);
    let (sub_piece_last_3, remainder) = remainder.split_at_mut(BLOCK_SIZE);
    let (sub_piece_last_4, sub_piece_last_5) = remainder.split_at_mut(BLOCK_SIZE);
    decode_block_internal(
        sub_piece_last_5,
        sub_piece_last_4[..].try_into().unwrap(),
        sbox,
    );
    decode_block_internal(
        sub_piece_last_4,
        sub_piece_last_3[..].try_into().unwrap(),
        sbox,
    );
    decode_block_internal(
        sub_piece_last_3,
        sub_piece_last_2[..].try_into().unwrap(),
        sbox,
    );
    decode_block_internal(
        sub_piece_last_2,
        sub_piece_last_1[..].try_into().unwrap(),
        sbox,
    );
    decode_block_internal(sub_piece_last_1, &feedback_last, sbox);

    let feedback_1 = iv.unwrap_or_else(|| {
        // TODO: `- 1` and `sub_piece_last_5.len() - 1` is a hack caused by the fact that current
        //  piece length is not divisible by block size without remainder
        sub_piece_last_5[(sub_piece_last_5.len() - BLOCK_SIZE - 1)..(sub_piece_last_5.len() - 1)]
            .try_into()
            .unwrap()
    });

    // Finish last iteration that remains after loop above
    let (block_1, _) = sub_piece_1.split_at_mut(BLOCK_SIZE);
    let (block_2, _) = sub_piece_2.split_at_mut(BLOCK_SIZE);
    let (block_3, _) = sub_piece_3.split_at_mut(BLOCK_SIZE);
    let (block_4, _) = sub_piece_4.split_at_mut(BLOCK_SIZE);
    let (block_5, _) = sub_piece_5.split_at_mut(BLOCK_SIZE);
    let (block_6, _) = sub_piece_6.split_at_mut(BLOCK_SIZE);
    let (block_7, _) = sub_piece_7.split_at_mut(BLOCK_SIZE);
    let (block_8, _) = sub_piece_8.split_at_mut(BLOCK_SIZE);

    decode_block_internal(block_1, &feedback_1, sbox);
    decode_block_internal(block_2, &feedback_2, sbox);
    decode_block_internal(block_3, &feedback_3, sbox);
    decode_block_internal(block_4, &feedback_4, sbox);
    decode_block_internal(block_5, &feedback_5, sbox);
    decode_block_internal(block_6, &feedback_6, sbox);
    decode_block_internal(block_7, &feedback_7, sbox);
    decode_block_internal(block_8, &feedback_8, sbox);
}

pub fn decode_simple_parallel(
    pieces: &mut [Piece],
    iv: Block,
    breadth_iterations: usize,
    sbox: &SBoxInverse,
    thread_pipelining: usize,
) {
    pieces
        .par_chunks_mut(thread_pipelining)
        .for_each(|pieces: &mut [Piece]| {
            for piece in pieces {
                decode_simple(piece, iv, breadth_iterations, &sbox);
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PIECE_SIZE;
    use rand::Rng;

    #[test]
    fn test() {
        let iv = [1, 2, 3];
        let sbox = SBoxDirect::new();
        let sbox_inverse = SBoxInverse::new();
        let mut input = [0u8; PIECE_SIZE];
        rand::thread_rng().fill(&mut input[..]);

        for &iterations in &[1, 10] {
            let mut encoding = input;
            encode_simple(&mut encoding, iv, iterations, &sbox);

            assert_ne!(encoding[..], input[..]);

            {
                let mut encoding = encoding;
                decode_simple(&mut encoding, iv, iterations, &sbox_inverse);
                assert_eq!(encoding[..], input[..]);
            }

            {
                let mut encoding = encoding;
                decode_pipelined(&mut encoding, iv, iterations, &sbox_inverse);
                assert_eq!(encoding[..], input[..]);
            }
        }

        for &iterations in &[1, 10] {
            let mut encodings_1 = input;
            let mut encodings_2 = input;
            let mut encodings_3 = input;
            let mut encodings_4 = input;
            encode_pipelined_x4(
                [
                    &mut encodings_1,
                    &mut encodings_2,
                    &mut encodings_3,
                    &mut encodings_4,
                ],
                [iv; 4],
                iterations,
                &sbox,
            );

            assert_ne!(encodings_1[..], input[..]);
            assert_ne!(encodings_2[..], input[..]);
            assert_ne!(encodings_3[..], input[..]);
            assert_ne!(encodings_4[..], input[..]);

            decode_simple(&mut encodings_1, iv, iterations, &sbox_inverse);
            decode_simple(&mut encodings_2, iv, iterations, &sbox_inverse);
            decode_simple(&mut encodings_3, iv, iterations, &sbox_inverse);
            decode_simple(&mut encodings_4, iv, iterations, &sbox_inverse);
            assert_eq!(encodings_1[..], input[..]);
            assert_eq!(encodings_2[..], input[..]);
            assert_eq!(encodings_3[..], input[..]);
            assert_eq!(encodings_4[..], input[..]);
        }

        for &iterations in &[1, 10] {
            let inputs = vec![input; 3];
            let mut encodings = inputs.clone();
            encode_simple_parallel(&mut encodings, iv, iterations, &sbox, 1);

            assert_ne!(
                encodings
                    .iter()
                    .map(|array| array.to_vec())
                    .collect::<Vec<_>>(),
                inputs
                    .iter()
                    .map(|array| array.to_vec())
                    .collect::<Vec<_>>()
            );

            decode_simple_parallel(&mut encodings, iv, iterations, &sbox_inverse, 1);

            assert_eq!(
                encodings
                    .iter()
                    .map(|array| array.to_vec())
                    .collect::<Vec<_>>(),
                inputs
                    .iter()
                    .map(|array| array.to_vec())
                    .collect::<Vec<_>>()
            );
        }
    }
}
