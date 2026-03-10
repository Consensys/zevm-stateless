/// Return a human-readable name for a SpecId (e.g. .prague → "Prague").
pub fn specName(spec: primitives.SpecId) []const u8 {
    return switch (spec) {
        .frontier, .frontier_thawing => "Frontier",
        .homestead                   => "Homestead",
        .dao_fork                    => "DAO",
        .tangerine                   => "EIP150",
        .spurious_dragon             => "EIP158",
        .byzantium                   => "Byzantium",
        .constantinople              => "Constantinople",
        .petersburg                  => "Petersburg",
        .istanbul                    => "Istanbul",
        .muir_glacier                => "MuirGlacier",
        .berlin                      => "Berlin",
        .london                      => "London",
        .arrow_glacier               => "ArrowGlacier",
        .gray_glacier                => "GrayGlacier",
        .merge                       => "Paris",
        .shanghai                    => "Shanghai",
        .cancun                      => "Cancun",
        .prague                      => "Prague",
        .osaka                       => "Osaka",
        else                         => "Unknown",
    };
}

/// Mainnet hardfork schedule: block/timestamp → SpecId + block reward.
const std        = @import("std");
const primitives = @import("primitives");

/// Parse a fork name string (e.g. "Prague", "Cancun") into a SpecId.
/// Returns null if the name is not recognised.
pub fn specFromName(name: []const u8) ?primitives.SpecId {
    const map = .{
        .{ "Frontier",       primitives.SpecId.frontier },
        .{ "Homestead",      primitives.SpecId.homestead },
        .{ "EIP150",         primitives.SpecId.tangerine },
        .{ "EIP158",         primitives.SpecId.spurious_dragon },
        .{ "Byzantium",      primitives.SpecId.byzantium },
        .{ "Constantinople", primitives.SpecId.constantinople },
        .{ "Petersburg",     primitives.SpecId.petersburg },
        .{ "Istanbul",       primitives.SpecId.istanbul },
        .{ "Berlin",         primitives.SpecId.berlin },
        .{ "London",         primitives.SpecId.london },
        .{ "Paris",          primitives.SpecId.merge },
        .{ "Merge",          primitives.SpecId.merge },
        .{ "Shanghai",       primitives.SpecId.shanghai },
        .{ "Cancun",         primitives.SpecId.cancun },
        .{ "Prague",         primitives.SpecId.prague },
        .{ "Osaka",          primitives.SpecId.osaka },
    };
    inline for (map) |entry| {
        if (std.ascii.eqlIgnoreCase(name, entry[0])) return entry[1];
    }
    return null;
}

/// Return the SpecId for a mainnet block identified by its block number and timestamp.
/// Timestamp-based forks (post-Merge) take priority over block-based ones.
pub fn mainnetSpec(block_number: u64, timestamp: u64) primitives.SpecId {
    // Timestamp-based (post-Merge)
    if (timestamp >= 1_746_612_311) return .prague;
    if (timestamp >= 1_710_338_135) return .cancun;
    if (timestamp >= 1_681_338_455) return .shanghai;
    // Block-based (pre-Merge / Merge itself)
    if (block_number >= 15_537_394) return .merge;
    if (block_number >= 15_050_000) return .gray_glacier;
    if (block_number >= 13_773_000) return .arrow_glacier;
    if (block_number >= 12_965_000) return .london;
    if (block_number >= 12_244_000) return .berlin;
    if (block_number >= 9_200_000)  return .muir_glacier;
    if (block_number >= 9_069_000)  return .istanbul;
    if (block_number >= 7_280_000)  return .petersburg;
    if (block_number >= 4_370_000)  return .byzantium;
    if (block_number >= 2_675_000)  return .spurious_dragon;
    if (block_number >= 2_463_000)  return .tangerine;
    if (block_number >= 1_920_000)  return .dao_fork;
    if (block_number >= 1_150_000)  return .homestead;
    return .frontier;
}

/// Mining reward in wei; -1 means disabled (post-Merge).
pub fn blockReward(spec: primitives.SpecId) i64 {
    return switch (spec) {
        .frontier, .frontier_thawing,
        .homestead, .dao_fork,
        .tangerine, .spurious_dragon         => 5_000_000_000_000_000_000,
        .byzantium                           => 3_000_000_000_000_000_000,
        .constantinople, .petersburg,
        .istanbul, .muir_glacier, .berlin,
        .london, .arrow_glacier, .gray_glacier => 2_000_000_000_000_000_000,
        else                                 => -1, // post-Merge: no block reward
    };
}
