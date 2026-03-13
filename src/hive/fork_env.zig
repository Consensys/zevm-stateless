/// Hive fork schedule: parse HIVE_* environment variables → SpecId.
const std = @import("std");
const primitives = @import("primitives");

const VERY_HIGH: u64 = std.math.maxInt(u64);

pub const ForkSchedule = struct {
    homestead: u64 = VERY_HIGH,
    dao: u64 = VERY_HIGH,
    tangerine: u64 = VERY_HIGH,
    spurious: u64 = VERY_HIGH,
    byzantium: u64 = VERY_HIGH,
    constantinople: u64 = VERY_HIGH,
    petersburg: u64 = VERY_HIGH,
    istanbul: u64 = VERY_HIGH,
    berlin: u64 = VERY_HIGH,
    london: u64 = VERY_HIGH,
    merge_block: u64 = VERY_HIGH,
    shanghai_ts: u64 = VERY_HIGH,
    cancun_ts: u64 = VERY_HIGH,
    prague_ts: u64 = VERY_HIGH,
    osaka_ts: u64 = VERY_HIGH,
    chain_id: u64 = 1,

    pub fn specAt(self: ForkSchedule, block: u64, ts: u64) primitives.SpecId {
        if (ts >= self.osaka_ts) return .osaka;
        if (ts >= self.prague_ts) return .prague;
        if (ts >= self.cancun_ts) return .cancun;
        if (ts >= self.shanghai_ts) return .shanghai;
        if (block >= self.merge_block) return .merge;
        if (block >= self.london) return .london;
        if (block >= self.berlin) return .berlin;
        if (block >= self.istanbul) return .istanbul;
        if (block >= self.petersburg) return .petersburg;
        if (block >= self.constantinople) return .constantinople;
        if (block >= self.byzantium) return .byzantium;
        if (block >= self.spurious) return .spurious_dragon;
        if (block >= self.tangerine) return .tangerine;
        if (block >= self.dao) return .dao_fork;
        if (block >= self.homestead) return .homestead;
        return .frontier;
    }
};

pub fn loadFromEnv() ForkSchedule {
    var s = ForkSchedule{};
    s.homestead = envU64("HIVE_FORK_HOMESTEAD") orelse VERY_HIGH;
    s.dao = envU64("HIVE_FORK_DAO_BLOCK") orelse VERY_HIGH;
    s.tangerine = envU64("HIVE_FORK_TANGERINE") orelse VERY_HIGH;
    s.spurious = envU64("HIVE_FORK_SPURIOUS") orelse VERY_HIGH;
    s.byzantium = envU64("HIVE_FORK_BYZANTIUM") orelse VERY_HIGH;
    s.constantinople = envU64("HIVE_FORK_CONSTANTINOPLE") orelse VERY_HIGH;
    s.petersburg = envU64("HIVE_FORK_PETERSBURG") orelse VERY_HIGH;
    s.istanbul = envU64("HIVE_FORK_ISTANBUL") orelse VERY_HIGH;
    s.berlin = envU64("HIVE_FORK_BERLIN") orelse VERY_HIGH;
    s.london = envU64("HIVE_FORK_LONDON") orelse VERY_HIGH;
    s.merge_block = envU64("HIVE_FORK_MERGE") orelse VERY_HIGH;
    s.shanghai_ts = envU64("HIVE_SHANGHAI_TIMESTAMP") orelse VERY_HIGH;
    s.cancun_ts = envU64("HIVE_CANCUN_TIMESTAMP") orelse VERY_HIGH;
    s.prague_ts = envU64("HIVE_PRAGUE_TIMESTAMP") orelse VERY_HIGH;
    s.osaka_ts = envU64("HIVE_OSAKA_TIMESTAMP") orelse VERY_HIGH;
    s.chain_id = envU64("HIVE_CHAIN_ID") orelse 1;
    return s;
}

fn envU64(name: []const u8) ?u64 {
    const val = std.posix.getenv(name) orelse return null;
    return std.fmt.parseInt(u64, val, 10) catch null;
}
