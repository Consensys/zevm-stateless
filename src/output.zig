//! Output types for stateless block execution.
//!
//! StatelessValidationResult is the top-level result committed by the guest,
//! mirroring StatelessValidationResult from the stateless guest spec.
//!
//! ProofOutput is the internal per-block detail returned by executeBlock.

const primitives = @import("primitives");

/// Result of executing one transaction.
pub const ReceiptData = struct {
    /// Cumulative gas used after this tx.
    cumulative_gas_used: u64,
    /// Whether the tx succeeded.
    success: bool,
    /// Logs emitted.
    logs_bloom: [256]u8,
};

/// Top-level result of stateless validation.
/// Mirrors StatelessValidationResult from the stateless guest spec.
/// Serialized by serializeStatelessOutput (io.zig) as the guest's public output.
pub const StatelessValidationResult = struct {
    /// Block hash — keccak256 of the block header RLP.
    /// Binds this result to a specific input payload
    /// (spec: new_payload_request_root via SSZ hash tree root; we use block hash).
    new_payload_request_root: [32]u8,
    /// Whether execution completed without error.
    successful_validation: bool,
    /// Pre-execution state root (trust anchor from parent header).
    pre_state_root: [32]u8,
    /// Post-execution state root.
    post_state_root: [32]u8,
    /// Receipts root derived from the executed transactions.
    receipts_root: [32]u8,
    /// Chain ID from the input ChainConfig.
    chain_id: u64,
};

/// Internal per-block execution detail returned by executeBlock.
pub const ProofOutput = struct {
    /// Pre-execution state root (must match the block's parentHash state).
    pre_state_root: primitives.Hash,
    /// Post-execution state root.
    post_state_root: primitives.Hash,
    /// Receipts root derived from the executed transactions.
    receipts_root: primitives.Hash,
    /// Per-transaction receipt data.
    receipts: []const ReceiptData,
    /// Fork name used for execution (e.g. "Prague").
    fork_name: []const u8,
};
