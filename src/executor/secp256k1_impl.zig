/// Default secp256k1 implementation for native tx signing in the executor.
///
/// This is the injection point for the "secp256k1_wrapper" named module in
/// native_executor_transition_mod.  zkVM builds (e.g. zevm-stateless-zisk)
/// override it by injecting their own accelerated module:
///
///   transition_mod.addImport("secp256k1_wrapper", your_zisk_secp256k1_module)
///
/// The injected module must export:
///   pub fn getContext() ?Secp256k1
///   pub const Secp256k1 = struct { ... sign(...), ecrecover(...) }
const std = @import("std");

const c = @cImport({
    @cInclude("secp256k1.h");
    @cInclude("secp256k1_recovery.h");
});

pub const Secp256k1 = struct {
    ctx: *c.secp256k1_context,

    pub fn init() Secp256k1 {
        const ctx = c.secp256k1_context_create(c.SECP256K1_CONTEXT_VERIFY | c.SECP256K1_CONTEXT_SIGN);
        std.debug.assert(ctx != null);
        return Secp256k1{ .ctx = ctx.? };
    }

    pub fn deinit(self: *Secp256k1) void {
        c.secp256k1_context_destroy(self.ctx);
        self.ctx = undefined;
    }

    /// Sign a 32-byte message hash with a private key.
    /// Returns the compact 64-byte signature and recovery ID, or null on failure.
    pub fn sign(self: Secp256k1, msg: [32]u8, seckey: [32]u8) ?struct { sig: [64]u8, recid: u8 } {
        var rec_sig: c.secp256k1_ecdsa_recoverable_signature = undefined;
        if (c.secp256k1_ecdsa_sign_recoverable(
            self.ctx,
            &rec_sig,
            &msg,
            &seckey,
            null,
            null,
        ) == 0) return null;

        var sig_bytes: [64]u8 = undefined;
        var recid: c_int = undefined;
        _ = c.secp256k1_ecdsa_recoverable_signature_serialize_compact(
            self.ctx,
            &sig_bytes,
            &recid,
            &rec_sig,
        );
        return .{ .sig = sig_bytes, .recid = @intCast(recid) };
    }

    /// Recover the Ethereum address from a signature and message hash.
    pub fn ecrecover(self: Secp256k1, msg: [32]u8, sig: [64]u8, recid: u8) ?[20]u8 {
        var recoverable_sig: c.secp256k1_ecdsa_recoverable_signature = undefined;
        const mut_recid: c_int = @intCast(recid);
        if (c.secp256k1_ecdsa_recoverable_signature_parse_compact(
            self.ctx,
            &recoverable_sig,
            &sig,
            mut_recid,
        ) == 0) return null;

        var pubkey: c.secp256k1_pubkey = undefined;
        if (c.secp256k1_ecdsa_recover(self.ctx, &pubkey, &recoverable_sig, &msg) == 0) return null;

        var pubkey_serialized: [65]u8 = undefined;
        var output_len: usize = 65;
        if (c.secp256k1_ec_pubkey_serialize(
            self.ctx,
            &pubkey_serialized,
            &output_len,
            &pubkey,
            c.SECP256K1_EC_UNCOMPRESSED,
        ) == 0) return null;

        var hash: [32]u8 = undefined;
        std.crypto.hash.sha3.Keccak256.hash(pubkey_serialized[1..], &hash, .{});
        var address: [20]u8 = undefined;
        @memcpy(&address, hash[12..32]);
        return address;
    }
};

var global_ctx: ?Secp256k1 = null;
var global_ctx_mutex = std.Thread.Mutex{};

/// Get or initialize the global secp256k1 context (thread-safe).
pub fn getContext() ?Secp256k1 {
    global_ctx_mutex.lock();
    defer global_ctx_mutex.unlock();
    if (global_ctx == null) {
        global_ctx = Secp256k1.init();
    }
    return global_ctx;
}
