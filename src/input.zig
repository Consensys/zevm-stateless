//! StatelessInput: everything needed to execute a block without full state.
//!
//! Types mirror the stateless guest spec (ethereum/execution-specs stateless_guest.py),
//! using RLP serialization in place of SSZ.
//!
//! The witness format mirrors debug_executionWitness (EL JSON-RPC):
//!   - state:   flat pool of RLP-encoded trie node preimages (spec: ExecutionWitness.state)
//!   - codes:   flat array of contract bytecodes
//!   - keys:    20-byte account addresses or 52-byte address+storage_slot pairs
//!              (zevm extension for pre-alloc; not in the base spec)
//!   - headers: RLP-encoded block headers (for pre-state root + BLOCKHASH opcode)
//!
//! Proof verification works by hash lookup in the pool: given the state_root,
//! the verifier walks the trie by finding each node via keccak256(node) == expected_hash.

const primitives = @import("primitives");

/// EIP-2930 access list entry.
pub const AccessListEntry = struct {
    address: primitives.Address,
    storage_keys: []const primitives.Hash,
};

/// EIP-7702 authorization tuple (raw — signer recovered in transition()).
pub const AuthorizationTuple = struct {
    chain_id: u256,
    address: primitives.Address,
    nonce: u64,
    /// y_parity (0 or 1).
    v: u64,
    r: u256,
    s: u256,
};

/// Ethereum transaction (all types — Legacy through EIP-7702).
pub const Transaction = struct {
    tx_type: u8,
    chain_id: ?u64,
    nonce: u64,
    /// max_fee_per_gas for EIP-1559/4844/7702; gas_price for Legacy/EIP-2930.
    gas_price: u128,
    /// max_priority_fee_per_gas (EIP-1559/4844/7702 only).
    gas_priority_fee: ?u128,
    gas_limit: u64,
    /// null = contract creation.
    to: ?primitives.Address,
    value: u256,
    data: []const u8,
    access_list: []const AccessListEntry,
    /// EIP-4844 blob versioned hashes.
    blob_hashes: []const primitives.Hash,
    max_fee_per_blob_gas: u128,
    /// EIP-7702 authorization list.
    authorization_list: []const AuthorizationTuple,
    /// Signature fields.
    v: u64,
    r: u256,
    s: u256,
};

/// Full Ethereum block header (post-Cancun, up to and including Osaka/Prague).
///
/// Fields are listed in their canonical RLP order (indices 0–20).
/// Optional fields (15+) are absent in pre-London blocks.
pub const BlockHeader = struct {
    parent_hash: primitives.Hash, // [0]
    ommers_hash: primitives.Hash, // [1]  always KECCAK_EMPTY_LIST in PoS
    beneficiary: primitives.Address, // [2]
    state_root: primitives.Hash, // [3]  post-execution root
    transactions_root: primitives.Hash, // [4]
    receipts_root: primitives.Hash, // [5]
    logs_bloom: [256]u8, // [6]
    difficulty: u256, // [7]  always 0 for PoS
    number: u64, // [8]
    gas_limit: u64, // [9]
    gas_used: u64, // [10]
    timestamp: u64, // [11]
    extra_data: []const u8, // [12]
    mix_hash: primitives.Hash, // [13] prevRandao in PoS
    nonce: u64, // [14] always 0 in PoS
    // EIP-1559 (London+)
    base_fee_per_gas: ?u64, // [15]
    // EIP-4895 (Shanghai+)
    withdrawals_root: ?primitives.Hash, // [16]
    // EIP-4844 (Cancun+)
    blob_gas_used: ?u64, // [17]
    excess_blob_gas: ?u64, // [18]
    // EIP-4788 (Cancun+)
    parent_beacon_block_root: ?primitives.Hash, // [19]
    // EIP-7685 (Prague+)
    requests_hash: ?primitives.Hash, // [20]
};

/// Chain configuration needed for stateless validation.
pub const ChainConfig = struct {
    chain_id: u64 = 1,
};

/// Execution witness in debug_executionWitness flat-pool format.
/// Mirrors ExecutionWitness from the stateless guest spec.
pub const ExecutionWitness = struct {
    /// Pre-execution state root (derived from witness.headers during deserialization).
    state_root: primitives.Hash,

    /// Flat pool of RLP-encoded trie node preimages (spec: ExecutionWitness.state).
    /// Nodes are referenced by keccak256(node_bytes) during proof traversal.
    state: []const []const u8,

    /// Contract bytecodes. keccak256(codes[i]) == account.code_hash.
    codes: []const []const u8,

    /// Accessed state keys for this block (zevm extension — not in base spec):
    ///   20 bytes = account address
    ///   52 bytes = account address (20) + storage slot (32)
    ///   32 bytes = standalone storage slot (context = nearest preceding address key)
    keys: []const []const u8,

    /// RLP-encoded ancestor block headers needed for the BLOCKHASH opcode.
    headers: []const []const u8,
};

/// Backward-compatible alias. Prefer ExecutionWitness in new code.
pub const StateWitness = ExecutionWitness;

/// EIP-4895 withdrawal (Shanghai+).
pub const Withdrawal = struct {
    index: u64,
    validator_index: u64,
    address: primitives.Address,
    amount: u64, // gwei
};

/// Full input to the stateless guest program.
/// Mirrors StatelessInput from the stateless guest spec.
pub const StatelessInput = struct {
    /// Decoded block header (all consensus fields).
    block: BlockHeader,
    /// Transactions in execution order (decoded from RLP or binary).
    transactions: []const Transaction,
    /// Execution witness for MPT proof verification and stateless execution.
    witness: ExecutionWitness,
    /// EIP-4895 withdrawals (Shanghai+). Empty slice for pre-Shanghai blocks.
    withdrawals: []const Withdrawal = &.{},
    /// Block hash — keccak256 of the block header RLP. Populated during
    /// deserialization; serves as the commitment to the input payload
    /// (spec: new_payload_request_root).
    block_hash: primitives.Hash = @splat(0),
    /// Chain configuration (spec: ChainConfig). Defaults to mainnet.
    chain_config: ChainConfig = .{},
    /// Recovered transaction public keys, in transaction order (spec field).
    /// Empty in builds that perform ecrecover during execution.
    public_keys: []const []const u8 = &.{},
};
