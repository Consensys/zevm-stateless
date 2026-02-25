const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Build options — crypto libraries are disabled by default for zkVM targets
    const lib_options = b.addOptions();
    lib_options.addOption(bool, "enable_blst", false);
    lib_options.addOption(bool, "enable_mcl", false);
    const lib_options_module = lib_options.createModule();

    // zevm dependency
    const zevm_dep = b.dependency("zevm", .{
        .target = target,
        .optimize = optimize,
    });

    const primitives = zevm_dep.module("primitives");
    const bytecode = zevm_dep.module("bytecode");
    const state = zevm_dep.module("state");
    const database = zevm_dep.module("database");
    const context = zevm_dep.module("context");
    const interpreter = zevm_dep.module("interpreter");
    const precompile = zevm_dep.module("precompile");
    const handler = zevm_dep.module("handler");
    const inspector = zevm_dep.module("inspector");

    // Override precompile build_options to match our crypto settings
    precompile.addImport("build_options", lib_options_module);

    // Local modules
    const input_mod = b.addModule("input", .{
        .root_source_file = b.path("src/input.zig"),
        .target = target,
        .optimize = optimize,
    });
    input_mod.addImport("primitives", primitives);

    const output_mod = b.addModule("output", .{
        .root_source_file = b.path("src/output.zig"),
        .target = target,
        .optimize = optimize,
    });
    output_mod.addImport("primitives", primitives);

    const mpt_mod = b.addModule("mpt", .{
        .root_source_file = b.path("src/mpt/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    mpt_mod.addImport("primitives", primitives);
    mpt_mod.addImport("input", input_mod);

    const db_mod = b.addModule("db", .{
        .root_source_file = b.path("src/db/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    db_mod.addImport("primitives", primitives);
    db_mod.addImport("state", state);
    db_mod.addImport("bytecode", bytecode);
    db_mod.addImport("mpt", mpt_mod);
    db_mod.addImport("input", input_mod);

    const executor_mod = b.addModule("executor", .{
        .root_source_file = b.path("src/executor/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    executor_mod.addImport("primitives", primitives);
    executor_mod.addImport("context", context);
    executor_mod.addImport("handler", handler);
    executor_mod.addImport("mpt", mpt_mod);
    executor_mod.addImport("db", db_mod);
    executor_mod.addImport("input", input_mod);
    executor_mod.addImport("output", output_mod);

    const mod = b.addModule("zevm_stateless", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
    });
    mod.addImport("primitives", primitives);
    mod.addImport("input", input_mod);
    mod.addImport("output", output_mod);
    mod.addImport("mpt", mpt_mod);
    mod.addImport("db", db_mod);
    mod.addImport("executor", executor_mod);

    const exe = b.addExecutable(.{
        .name = "zevm_stateless",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zevm_stateless", .module = mod },
            },
        }),
    });

    exe.root_module.addImport("primitives", primitives);
    exe.root_module.addImport("bytecode", bytecode);
    exe.root_module.addImport("state", state);
    exe.root_module.addImport("database", database);
    exe.root_module.addImport("context", context);
    exe.root_module.addImport("interpreter", interpreter);
    exe.root_module.addImport("precompile", precompile);
    exe.root_module.addImport("handler", handler);
    exe.root_module.addImport("inspector", inspector);
    exe.root_module.addImport("input", input_mod);
    exe.root_module.addImport("output", output_mod);
    exe.root_module.addImport("mpt", mpt_mod);
    exe.root_module.addImport("db", db_mod);
    exe.root_module.addImport("executor", executor_mod);

    b.installArtifact(exe);

    const run_step = b.step("run", "Run the app");
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    run_step.dependOn(&run_cmd.step);
    if (b.args) |args| run_cmd.addArgs(args);

    const mod_tests = b.addTest(.{ .root_module = mod });
    const run_mod_tests = b.addRunArtifact(mod_tests);
    const exe_tests = b.addTest(.{ .root_module = exe.root_module });
    const run_exe_tests = b.addRunArtifact(exe_tests);

    // MPT integration tests in src/mpt/test.zig
    const mpt_test_mod = b.createModule(.{
        .root_source_file = b.path("src/mpt/test.zig"),
        .target = target,
        .optimize = optimize,
    });
    mpt_test_mod.addImport("primitives", primitives);
    mpt_test_mod.addImport("mpt", mpt_mod);
    mpt_test_mod.addImport("input", input_mod);
    const mpt_tests = b.addTest(.{ .root_module = mpt_test_mod });
    const run_mpt_tests = b.addRunArtifact(mpt_tests);

    // WitnessDatabase integration tests in src/db/test.zig
    const db_test_mod = b.createModule(.{
        .root_source_file = b.path("src/db/test.zig"),
        .target = target,
        .optimize = optimize,
    });
    db_test_mod.addImport("primitives", primitives);
    db_test_mod.addImport("state", state);
    db_test_mod.addImport("bytecode", bytecode);
    db_test_mod.addImport("mpt", mpt_mod);
    db_test_mod.addImport("input", input_mod);
    db_test_mod.addImport("db", db_mod);
    const db_tests = b.addTest(.{ .root_module = db_test_mod });
    const run_db_tests = b.addRunArtifact(db_tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_exe_tests.step);
    test_step.dependOn(&run_mpt_tests.step);
    test_step.dependOn(&run_db_tests.step);
}
