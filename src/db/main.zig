//! WitnessDatabase: stateless EVM database backed by a pre-built MPT NodeIndex.
//!
//! Serves account/storage reads via live MPT proof verification (O(log n) per read
//! via NodeIndex O(1) node lookups). Contract bytecodes are served via linear scan
//! over the (bounded) codes pool.
//!
//! Wired into execution via InMemoryDB.fallback (see database.FallbackFns).
//! zevm's EVM execution stack is hardcoded to InMemoryDB throughout; making it
//! fully generic would require refactoring the interpreter opcode system.  The
//! fallback vtable is the minimal workaround: InMemoryDB starts empty so every
//! read misses and falls through to WitnessDatabase.

const std = @import("std");
const primitives = @import("primitives");
const state = @import("state");
const bytecode = @import("bytecode");
const mpt = @import("mpt");
const types = @import("executor_types");
const database = @import("database");

pub const DbError = error{
    /// MPT proof verification failed — witness is inconsistent with state root.
    InvalidWitness,
};

const EMPTY_TRIE_HASH: primitives.Hash = .{
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6,
    0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0,
    0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
};

/// Pre-execution snapshot of an account (from WitnessDatabase).
pub const AccountPreState = struct {
    nonce: u64 = 0,
    balance: u256 = 0,
    code_hash: primitives.Hash = primitives.KECCAK_EMPTY,
};

/// Access log returned by WitnessDatabase.takeAccessLog().
/// accounts:          address → pre-state snapshot (one entry per unique account accessed).
/// storage:           address → (slot → pre-state value) for all storage accesses.
/// committed_changed: address → set of slots committed to a value ≠ pre-block at any tx boundary.
///                    Used to distinguish cross-tx net-zero writes (storageChanges) from
///                    within-tx net-zero writes (storageReads) for EIP-7928 BAL validation.
pub const AccessLog = struct {
    accounts: std.AutoHashMapUnmanaged(primitives.Address, AccountPreState),
    storage: std.AutoHashMapUnmanaged(primitives.Address, std.AutoHashMapUnmanaged(primitives.StorageKey, primitives.StorageValue)),
    committed_changed: std.AutoHashMapUnmanaged(primitives.Address, std.AutoHashMapUnmanaged(primitives.StorageKey, void)),
};

/// Stateless database built from a pre-built NodeIndex + pre-state root.
///
/// Used as a fallback on InMemoryDB for stateless block execution:
///   db.fallback = witness_db.buildFallback();
///
/// Implements duck-typed Database interface (same methods as InMemoryDB):
///   basic(address)              → ?AccountInfo
///   codeByHash(code_hash)       → Bytecode
///   storage(address, key)       → StorageValue
///   blockHash(number)           → Hash
pub const WitnessDatabase = struct {
    node_index: *const mpt.NodeIndex,
    pre_state_root: primitives.Hash,
    codes: []const []const u8,
    block_hashes: []const types.BlockHashEntry,
    /// Arena allocator used for tracking maps (same arena as the block execution).
    tracking_alloc: std.mem.Allocator,
    /// Pre-state snapshots for each account accessed via basic() — committed only.
    pre_accounts: std.AutoHashMapUnmanaged(primitives.Address, AccountPreState),
    /// Pre-state storage values for each slot accessed via storage() — committed only.
    pre_storage: std.AutoHashMapUnmanaged(primitives.Address, std.AutoHashMapUnmanaged(primitives.StorageKey, primitives.StorageValue)),
    /// Per-tx pending account accesses (flushed to pre_accounts on commitTx, dropped on discardTx).
    pending_accounts: std.AutoHashMapUnmanaged(primitives.Address, AccountPreState),
    /// Per-tx pending storage accesses (flushed to pre_storage on commitTx, dropped on discardTx).
    pending_storage: std.AutoHashMapUnmanaged(primitives.Address, std.AutoHashMapUnmanaged(primitives.StorageKey, primitives.StorageValue)),
    /// Per-frame account key lists for checkpoint-aware rollback.
    /// When snapshotFrame() is called, a new list is pushed. revertFrame() pops it and removes
    /// those keys from pending. commitFrame() just pops (entries remain in pending).
    frame_accounts: std.ArrayListUnmanaged(std.ArrayListUnmanaged(primitives.Address)),
    /// Per-frame storage key lists for checkpoint-aware rollback.
    frame_storage: std.ArrayListUnmanaged(std.ArrayListUnmanaged(struct { addr: primitives.Address, slot: primitives.StorageKey })),
    /// Slots that were committed to a value different from their pre-block value at any tx boundary.
    /// Populated via the pre_commit_tx_slot fallback hook (called before each commitTx()).
    /// Used to distinguish cross-tx net-zero writes (storageChanges) from within-tx net-zero
    /// writes (storageReads) for EIP-7928 BAL validation.
    committed_changed_storage: std.AutoHashMapUnmanaged(primitives.Address, std.AutoHashMapUnmanaged(primitives.StorageKey, void)),

    const Self = @This();

    pub fn init(
        alloc: std.mem.Allocator,
        node_index: *const mpt.NodeIndex,
        pre_state_root: primitives.Hash,
        codes: []const []const u8,
        block_hashes: []const types.BlockHashEntry,
    ) Self {
        return .{
            .node_index = node_index,
            .pre_state_root = pre_state_root,
            .codes = codes,
            .block_hashes = block_hashes,
            .tracking_alloc = alloc,
            .pre_accounts = .{},
            .pre_storage = .{},
            .pending_accounts = .{},
            .pending_storage = .{},
            .frame_accounts = .{},
            .frame_storage = .{},
            .committed_changed_storage = .{},
        };
    }

    /// Commit pending per-tx tracking to the permanent access log.
    /// Called after a transaction commits successfully (including system calls).
    pub fn commitTxTracking(self: *Self) void {
        // Merge pending_accounts → pre_accounts (first-access only)
        var it = self.pending_accounts.iterator();
        while (it.next()) |kv| {
            if (!self.pre_accounts.contains(kv.key_ptr.*)) {
                self.pre_accounts.put(self.tracking_alloc, kv.key_ptr.*, kv.value_ptr.*) catch {};
            }
        }
        // Merge pending_storage → pre_storage (first-access only per slot)
        var sit = self.pending_storage.iterator();
        while (sit.next()) |kv| {
            const addr = kv.key_ptr.*;
            const pend_map = kv.value_ptr.*;
            const perm_entry = self.pre_storage.getOrPut(self.tracking_alloc, addr) catch continue;
            if (!perm_entry.found_existing) perm_entry.value_ptr.* = .{};
            var slot_it = pend_map.iterator();
            while (slot_it.next()) |slot_kv| {
                if (!perm_entry.value_ptr.*.contains(slot_kv.key_ptr.*)) {
                    perm_entry.value_ptr.*.put(self.tracking_alloc, slot_kv.key_ptr.*, slot_kv.value_ptr.*) catch {};
                }
            }
        }
        // Clear pending
        self.pending_accounts.clearRetainingCapacity();
        var pit = self.pending_storage.valueIterator();
        while (pit.next()) |v| v.clearRetainingCapacity();
        self.pending_storage.clearRetainingCapacity();
    }

    /// Record that a storage slot was committed with a value differing from its pre-block value.
    /// Called via the pre_commit_tx_slot fallback, BEFORE commitTx() resets original_value.
    /// Marks the slot so buildAccessedEntries can classify it as storageChange (not storageRead)
    /// even when its final post-block value equals its pre-block value (cross-tx net-zero write).
    pub fn notifyStorageSlotCommit(self: *Self, address: primitives.Address, slot: primitives.StorageKey, committed_value: primitives.StorageValue) void {
        // Retrieve the pre-block value: check committed pre_storage first, then pending.
        const pre_block_val: primitives.StorageValue = blk: {
            if (self.pre_storage.get(address)) |perm| {
                if (perm.get(slot)) |v| break :blk v;
            }
            if (self.pending_storage.get(address)) |pend| {
                if (pend.get(slot)) |v| break :blk v;
            }
            break :blk 0;
        };
        if (committed_value != pre_block_val) {
            const addr_entry = self.committed_changed_storage.getOrPut(self.tracking_alloc, address) catch return;
            if (!addr_entry.found_existing) addr_entry.value_ptr.* = .{};
            addr_entry.value_ptr.*.put(self.tracking_alloc, slot, {}) catch {};
        }
    }

    /// Discard pending per-tx tracking (transaction was reverted or invalid).
    pub fn discardTxTracking(self: *Self) void {
        self.pending_accounts.clearRetainingCapacity();
        var it = self.pending_storage.valueIterator();
        while (it.next()) |v| v.clearRetainingCapacity();
        self.pending_storage.clearRetainingCapacity();
        // Also clear any open frame stacks.
        for (self.frame_accounts.items) |*f| f.clearRetainingCapacity();
        self.frame_accounts.clearRetainingCapacity();
        for (self.frame_storage.items) |*f| f.clearRetainingCapacity();
        self.frame_storage.clearRetainingCapacity();
    }

    /// Push a new frame level for checkpoint-aware tracking.
    /// Called when a CALL/CREATE opens a journal checkpoint.
    pub fn snapshotFrameTracking(self: *Self) void {
        self.frame_accounts.append(self.tracking_alloc, .{}) catch {};
        self.frame_storage.append(self.tracking_alloc, .{}) catch {};
    }

    /// Current frame committed — pop its lists (entries stay in pending).
    pub fn commitFrameTracking(self: *Self) void {
        if (self.frame_accounts.pop()) |fa_val| {
            var fa = fa_val;
            fa.deinit(self.tracking_alloc);
        }
        if (self.frame_storage.pop()) |fs_val| {
            var fs = fs_val;
            fs.deinit(self.tracking_alloc);
        }
    }

    /// Current frame reverted — EIP-7928 keeps reverted accesses in BAL, so just pop like commit.
    pub fn revertFrameTracking(self: *Self) void {
        if (self.frame_accounts.pop()) |fa_val| {
            var fa = fa_val;
            fa.deinit(self.tracking_alloc);
        }
        if (self.frame_storage.pop()) |fs_val| {
            var fs = fs_val;
            fs.deinit(self.tracking_alloc);
        }
    }

    /// Remove an address from the current-tx pending access log.
    /// Called when a CALL opcode loaded an address purely for gas calculation
    /// (new_account_cost check) but then went OOG before the call executed.
    /// Only removes from pending_accounts; never removes from pre_accounts
    /// (which holds commits from earlier txs).
    pub fn untrackPendingAddress(self: *Self, address: primitives.Address) void {
        _ = self.pending_accounts.remove(address);
    }

    /// Returns true if the address is in the committed or pending access log.
    /// Used by BaTracker to distinguish legitimately-accessed nonexistent accounts
    /// from those only loaded for OOG gas calculation (which are removed via untrackPendingAddress).
    pub fn isTrackedAddress(self: *Self, address: primitives.Address) bool {
        return self.pre_accounts.contains(address) or self.pending_accounts.contains(address);
    }

    /// Force-add an address to the current-tx pending access log with an empty
    /// pre-state snapshot. Used for EIP-7702 delegation targets that are accessed
    /// (their code executes) but whose account state is not proven in the witness.
    pub fn forceTrackPendingAddress(self: *Self, address: primitives.Address) void {
        if (self.pre_accounts.contains(address) or self.pending_accounts.contains(address)) return;
        self.pending_accounts.put(self.tracking_alloc, address, .{}) catch {};
    }

    /// Drain and return the accumulated access log, resetting internal state.
    pub fn takeAccessLog(self: *Self) AccessLog {
        // Flush any uncommitted pending (e.g., post-block system calls that don't
        // go through the normal commitTx path).
        self.commitTxTracking();
        const log = AccessLog{
            .accounts = self.pre_accounts,
            .storage = self.pre_storage,
            .committed_changed = self.committed_changed_storage,
        };
        self.pre_accounts = .{};
        self.pre_storage = .{};
        self.committed_changed_storage = .{};
        return log;
    }

    // ── basic ───────────────────────────────────────────────────────────────

    pub fn basic(self: *Self, address: primitives.Address) !?state.AccountInfo {
        const account_state = mpt.verifyAccountIndexed(
            self.pre_state_root,
            address,
            self.node_index,
        ) catch |err| switch (err) {
            // InvalidProof means the witness doesn't include proof nodes for this account.
            // Treat as non-existent (e.g., precompile addresses have no witness proof).
            // Still track the access so EIP-7928 BAL includes it; untrackPendingAddress()
            // will remove it later if the access turns out to be an OOG gas-calc phantom.
            error.InvalidProof => {
                if (!self.pre_accounts.contains(address) and !self.pending_accounts.contains(address)) {
                    self.pending_accounts.put(self.tracking_alloc, address, .{}) catch {};
                    if (self.frame_accounts.items.len > 0) {
                        self.frame_accounts.items[self.frame_accounts.items.len - 1].append(
                            self.tracking_alloc, address,
                        ) catch {};
                    }
                }
                return null;
            },
            // Any other error (InvalidNode, InvalidRlp, InvalidHp) means corrupt witness data.
            else => return DbError.InvalidWitness,
        };

        // Track pre-state in pending (flushed to pre_accounts on commitTx).
        // Use pending so that accesses from reverted transactions are discarded.
        // Also track in the current frame so checkpoint reverts can remove it.
        if (!self.pre_accounts.contains(address) and !self.pending_accounts.contains(address)) {
            const ps: AccountPreState = if (account_state) |as| .{
                .nonce = as.nonce,
                .balance = as.balance,
                .code_hash = as.code_hash,
            } else .{};
            self.pending_accounts.put(self.tracking_alloc, address, ps) catch {};
            // Record in current frame for rollback on revertFrame.
            if (self.frame_accounts.items.len > 0) {
                self.frame_accounts.items[self.frame_accounts.items.len - 1].append(
                    self.tracking_alloc, address,
                ) catch {};
            }
        }

        const as = account_state orelse return null;
        return state.AccountInfo{
            .balance = as.balance,
            .nonce = as.nonce,
            .code_hash = as.code_hash,
            .code = null, // served on demand via codeByHash
        };
    }

    // ── codeByHash ──────────────────────────────────────────────────────────

    pub fn codeByHash(self: *Self, code_hash: primitives.Hash) !bytecode.Bytecode {
        if (std.mem.eql(u8, &code_hash, &primitives.KECCAK_EMPTY)) {
            return bytecode.Bytecode.newLegacy(&.{});
        }
        for (self.codes) |code_bytes| {
            const h = mpt.keccak256(code_bytes);
            if (std.mem.eql(u8, &h, &code_hash)) {
                // Detect EIP-7702 delegation pointer: 0xEF 0x01 0x00 + 20-byte address (23 bytes total).
                // Must return Bytecode.eip7702 so that setupCall detects it and loads the delegation target.
                if (code_bytes.len == 23 and code_bytes[0] == 0xEF and code_bytes[1] == 0x01 and code_bytes[2] == 0x00) {
                    var delegation_addr: primitives.Address = [_]u8{0} ** 20;
                    @memcpy(&delegation_addr, code_bytes[3..23]);
                    return bytecode.Bytecode{ .eip7702 = bytecode.Eip7702Bytecode.new(delegation_addr) };
                }
                return bytecode.Bytecode.newLegacy(code_bytes);
            }
        }
        return bytecode.Bytecode.new();
    }

    // ── storage ─────────────────────────────────────────────────────────────

    pub fn storage(
        self: *Self,
        address: primitives.Address,
        index: primitives.StorageKey,
    ) !primitives.StorageValue {
        const account_state = mpt.verifyAccountIndexed(
            self.pre_state_root,
            address,
            self.node_index,
        ) catch |err| switch (err) {
            // Witness doesn't include proof for this account — treat storage as 0.
            error.InvalidProof => return 0,
            else => return DbError.InvalidWitness,
        };

        const storage_root = if (account_state) |as| as.storage_root else EMPTY_TRIE_HASH;
        const slot = u256ToHash(index);
        const value = mpt.verifyStorageIndexed(storage_root, slot, self.node_index) catch |err| switch (err) {
            error.InvalidProof => return 0,
            else => return DbError.InvalidWitness,
        };

        // Track pre-state storage value in pending (flushed to pre_storage on commitTx).
        // Skip if already in permanent storage (already committed from an earlier tx).
        const already_committed = if (self.pre_storage.get(address)) |perm| perm.contains(index) else false;
        const already_pending = if (self.pending_storage.get(address)) |pend| pend.contains(index) else false;
        if (!already_committed and !already_pending) {
            const addr_entry = self.pending_storage.getOrPut(self.tracking_alloc, address) catch null;
            if (addr_entry) |e| {
                if (!e.found_existing) e.value_ptr.* = .{};
                e.value_ptr.*.put(self.tracking_alloc, index, value) catch {};
                // Record in current frame for rollback on revertFrame.
                if (self.frame_storage.items.len > 0) {
                    self.frame_storage.items[self.frame_storage.items.len - 1].append(
                        self.tracking_alloc, .{ .addr = address, .slot = index },
                    ) catch {};
                }
            }
        }

        return value;
    }

    // ── blockHash ───────────────────────────────────────────────────────────

    pub fn blockHash(self: *Self, number: u64) !primitives.Hash {
        for (self.block_hashes) |bhe| {
            if (bhe.number == number) return bhe.hash;
        }
        return [_]u8{0} ** 32;
    }

    // ── FallbackFns builder ─────────────────────────────────────────────────

    /// Build a FallbackFns vtable that routes InMemoryDB fallback calls to this WitnessDatabase.
    pub fn buildFallback(self: *Self) database.FallbackFns {
        return .{
            .ctx = @ptrCast(self),
            .basic = basicFallback,
            .code_by_hash = codeByHashFallback,
            .storage = storageFallback,
            .block_hash = blockHashFallback,
            .commit_tx = commitTxFallback,
            .discard_tx = discardTxFallback,
            .snapshot_frame = snapshotFrameFallback,
            .commit_frame = commitFrameFallback,
            .revert_frame = revertFrameFallback,
            .untrack_address = untrackAddressFallback,
            .force_track_address = forceTrackAddressFallback,
            .pre_commit_tx_slot = preCommitTxSlotFallback,
            .notify_storage_read = notifyStorageReadFallback,
            .is_tracked_address = isTrackedAddressFallback,
        };
    }

    fn basicFallback(ctx: *anyopaque, address: primitives.Address) anyerror!?state.AccountInfo {
        const self: *Self = @ptrCast(@alignCast(ctx));
        return self.basic(address);
    }

    fn codeByHashFallback(ctx: *anyopaque, code_hash: primitives.Hash) anyerror!bytecode.Bytecode {
        const self: *Self = @ptrCast(@alignCast(ctx));
        return self.codeByHash(code_hash);
    }

    fn storageFallback(ctx: *anyopaque, address: primitives.Address, index: primitives.StorageKey) anyerror!primitives.StorageValue {
        const self: *Self = @ptrCast(@alignCast(ctx));
        return self.storage(address, index);
    }

    fn blockHashFallback(ctx: *anyopaque, number: u64) anyerror!primitives.Hash {
        const self: *Self = @ptrCast(@alignCast(ctx));
        return self.blockHash(number);
    }

    fn commitTxFallback(ctx: *anyopaque) void {
        const self: *Self = @ptrCast(@alignCast(ctx));
        self.commitTxTracking();
    }

    fn discardTxFallback(ctx: *anyopaque) void {
        const self: *Self = @ptrCast(@alignCast(ctx));
        self.discardTxTracking();
    }

    fn snapshotFrameFallback(ctx: *anyopaque) void {
        const self: *Self = @ptrCast(@alignCast(ctx));
        self.snapshotFrameTracking();
    }

    fn commitFrameFallback(ctx: *anyopaque) void {
        const self: *Self = @ptrCast(@alignCast(ctx));
        self.commitFrameTracking();
    }

    fn revertFrameFallback(ctx: *anyopaque) void {
        const self: *Self = @ptrCast(@alignCast(ctx));
        self.revertFrameTracking();
    }

    fn untrackAddressFallback(ctx: *anyopaque, address: primitives.Address) void {
        const self: *Self = @ptrCast(@alignCast(ctx));
        self.untrackPendingAddress(address);
    }

    fn forceTrackAddressFallback(ctx: *anyopaque, address: primitives.Address) void {
        const self: *Self = @ptrCast(@alignCast(ctx));
        self.forceTrackPendingAddress(address);
    }

    fn preCommitTxSlotFallback(ctx: *anyopaque, address: primitives.Address, slot: primitives.StorageKey, committed_value: primitives.StorageValue) void {
        const self: *Self = @ptrCast(@alignCast(ctx));
        self.notifyStorageSlotCommit(address, slot, committed_value);
    }

    fn isTrackedAddressFallback(ctx: *anyopaque, address: primitives.Address) bool {
        const self: *Self = @ptrCast(@alignCast(ctx));
        return self.isTrackedAddress(address);
    }

    fn notifyStorageReadFallback(ctx: *anyopaque, address: primitives.Address, slot: primitives.StorageKey) void {
        const self: *Self = @ptrCast(@alignCast(ctx));
        // For newly-created accounts the pre-state value is implicitly 0.
        // Record it in pending_storage so it shows up in the access log.
        const already_committed = if (self.pre_storage.get(address)) |perm| perm.contains(slot) else false;
        const already_pending = if (self.pending_storage.get(address)) |pend| pend.contains(slot) else false;
        if (!already_committed and !already_pending) {
            const addr_entry = self.pending_storage.getOrPut(self.tracking_alloc, address) catch return;
            if (!addr_entry.found_existing) addr_entry.value_ptr.* = .{};
            addr_entry.value_ptr.*.put(self.tracking_alloc, slot, 0) catch {};
            if (self.frame_storage.items.len > 0) {
                self.frame_storage.items[self.frame_storage.items.len - 1].append(
                    self.tracking_alloc, .{ .addr = address, .slot = slot },
                ) catch {};
            }
        }
    }
};

// ─── Private helpers ───────────────────────────────────────────────────────────

fn u256ToHash(value: u256) primitives.Hash {
    var out: primitives.Hash = @splat(0);
    var n = value;
    var i: usize = 32;
    while (i > 0) {
        i -= 1;
        out[i] = @intCast(n & 0xff);
        n >>= 8;
    }
    return out;
}
