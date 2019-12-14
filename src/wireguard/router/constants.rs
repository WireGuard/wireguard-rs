// WireGuard semantics constants

pub const MAX_STAGED_PACKETS: usize = 128;

// performance constants

pub const PARALLEL_QUEUE_SIZE: usize = MAX_STAGED_PACKETS;
pub const INORDER_QUEUE_SIZE: usize = PARALLEL_QUEUE_SIZE;
pub const MAX_INORDER_CONSUME: usize = INORDER_QUEUE_SIZE;
