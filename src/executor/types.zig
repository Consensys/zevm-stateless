/// Canonical EVM state transition types.
///
/// Defines the core types used by the executor, t8n tool, and spec-test runner.
/// JSON parsing lives in t8n/input.zig; these are pure data definitions.
const std = @import("std");

// ─── Primitive aliases ────────────────────────────────────────────────────────

pub const Address = [20]u8;
pub const Hash = [32]u8;
pub const U256 = u256;

// ─── State types ──────────────────────────────────────────────────────────────

pub const AllocAccount = struct {
    balance: U256 = 0,
    nonce: u64 = 0,
    code: []const u8 = &.{},
    storage: std.AutoHashMapUnmanaged(U256, U256) = .{},
};

pub const AccessListEntry = struct {
    address: Address,
    storage_keys: []Hash,
};

pub const Withdrawal = struct {
    index: u64,
    validator_index: u64,
    address: Address,
    amount: u64, // gwei
};

pub const BlockHashEntry = struct {
    number: u64,
    hash: Hash,
};

// ─── Block environment ────────────────────────────────────────────────────────

pub const Env = struct {
    coinbase: Address = [_]u8{0} ** 20,
    gas_limit: u64 = 30_000_000,
    number: u64 = 0,
    timestamp: u64 = 0,
    difficulty: U256 = 0,
    base_fee: ?u64 = null,
    random: ?Hash = null,
    excess_blob_gas: ?u64 = null,
    parent_difficulty: ?U256 = null,
    parent_base_fee: ?u64 = null,
    parent_gas_used: ?u64 = null,
    parent_gas_limit: ?u64 = null,
    parent_timestamp: ?u64 = null,
    parent_uncle_hash: ?Hash = null,
    parent_excess_blob_gas: ?u64 = null,
    parent_blob_gas_used: ?u64 = null,
    parent_beacon_block_root: ?Hash = null,
    block_hashes: []BlockHashEntry = &.{},
    withdrawals: []Withdrawal = &.{},
};

// ─── Transaction types ────────────────────────────────────────────────────────

/// EIP-7702 authorization item (pre-recovered: signer known from fixture).
pub const AuthorizationItem = struct {
    chain_id: U256 = 0,
    address: Address = [_]u8{0} ** 20,
    nonce: u64 = 0,
    /// The recovered signer (authority). If null, treated as Invalid.
    signer: ?Address = null,
};

pub const TxInput = struct {
    type: u8 = 0,
    nonce: ?u64 = null,
    gas_price: ?u128 = null,
    max_fee_per_gas: ?u128 = null,
    max_priority_fee_per_gas: ?u128 = null,
    gas: u64 = 21_000,
    to: ?Address = null,
    from: ?Address = null,
    value: U256 = 0,
    data: []const u8 = &.{},
    v: ?U256 = null,
    r: ?U256 = null,
    s: ?U256 = null,
    secret_key: ?[32]u8 = null,
    protected: bool = true,
    chain_id: ?u64 = null,
    access_list: []AccessListEntry = &.{},
    blob_versioned_hashes: []Hash = &.{},
    max_fee_per_blob_gas: ?u128 = null,
    /// EIP-7702: authorization list for type 4 transactions.
    authorization_list: []AuthorizationItem = &.{},
};
