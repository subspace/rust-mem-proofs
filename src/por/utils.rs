use crate::por::Block;
use crate::por::BLOCK_SIZE;
use crate::Piece;
use std::convert::TryInto;

/// Returns (blocks, feedback) tuple given block index in a piece
/// Handles cases when `number_of_blocks` is not a multiple of `piece.len()` gracefully (by adding
/// offset from the beginning of the piece)
pub fn piece_to_blocks_and_feedback(piece: &mut Piece, index: usize) -> (&mut [u8], &Block) {
    let (ends_with_feedback, starts_with_block) = piece.split_at_mut(index * BLOCK_SIZE);

    let feedback = ends_with_feedback[ends_with_feedback.len() - BLOCK_SIZE..]
        .as_ref()
        .try_into()
        .unwrap();

    let (blocks, _) = starts_with_block.split_at_mut(BLOCK_SIZE);

    (blocks, feedback)
}

/// Returns (blocks, feedback) tuple given piece and optional feedback
pub fn piece_to_first_blocks_and_feedback(
    piece: &mut Piece,
    feedback: Option<Block>,
) -> (&mut [u8], Block) {
    let (first_blocks, remainder) = piece.split_at_mut(BLOCK_SIZE);
    // At this point last block is already decoded, so we can use it as an IV to previous iteration
    let iv = feedback.unwrap_or_else(move || {
        // TODO: `- 1` and `remainder.len() - 1` is a hack caused by the fact that current piece
        //  length is not divisible by block size without remainder
        remainder[(remainder.len() - BLOCK_SIZE - 1)..(remainder.len() - 1)]
            .try_into()
            .unwrap()
    });

    (first_blocks, iv)
}
