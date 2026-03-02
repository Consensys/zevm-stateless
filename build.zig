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

    const run_test_block_step = b.step("run-test-block", "Run against test/vectors/test_block*.json");
    const run_test_block_cmd = b.addRunArtifact(exe);
    run_test_block_cmd.step.dependOn(b.getInstallStep());
    run_test_block_cmd.addArgs(&.{
        "test/vectors/stateless/test_block.json",
        "test/vectors/stateless/test_block_witness.json",
    });
    run_test_block_step.dependOn(&run_test_block_cmd.step);

    // gen_example: generate examples/block.json and examples/witness.json
    const gen_example_exe = b.addExecutable(.{
        .name = "gen_example",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/gen_example.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "primitives", .module = primitives },
                .{ .name = "mpt",        .module = mpt_mod    },
            },
        }),
    });
    b.installArtifact(gen_example_exe);

    const gen_example_step = b.step("gen-example", "Generate examples/block.json and examples/witness.json");
    const run_gen_example = b.addRunArtifact(gen_example_exe);
    gen_example_step.dependOn(&run_gen_example.step);

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

    // ---------------------------------------------------------------------------
    // t8n — Ethereum State Transition Tool (execution-spec-tests compatible)
    //
    // Implements the geth evm t8n interface:
    //   t8n --input.alloc A --input.env E --input.txs T --state.fork F \
    //       --output.alloc out/alloc.json --output.result out/result.json
    //
    // Uses the local zevm branch (feat/gap-analysis) for EVM execution.
    // Links secp256k1 for transaction signing/recovery, OpenSSL for precompiles.
    // ---------------------------------------------------------------------------
    const zevm_local_dep = b.dependency("zevm_local", .{
        .target = target,
        .optimize = optimize,
        .blst = false,
        .mcl = false,
    });

    const local_primitives = zevm_local_dep.module("primitives");
    const local_state = zevm_local_dep.module("state");
    const local_bytecode = zevm_local_dep.module("bytecode");
    const local_database = zevm_local_dep.module("database");
    const local_context = zevm_local_dep.module("context");
    const local_handler = zevm_local_dep.module("handler");
    const local_precompile = zevm_local_dep.module("precompile");

    // mpt_builder: standalone trie builder (no external deps)
    const mpt_builder_mod = b.addModule("mpt_builder", .{
        .root_source_file = b.path("src/mpt/builder.zig"),
        .target = target,
        .optimize = optimize,
    });

    const t8n_exe = b.addExecutable(.{
        .name = "t8n",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/t8n/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "primitives",  .module = local_primitives  },
                .{ .name = "state",       .module = local_state       },
                .{ .name = "bytecode",    .module = local_bytecode    },
                .{ .name = "database",    .module = local_database    },
                .{ .name = "context",     .module = local_context     },
                .{ .name = "handler",     .module = local_handler     },
                .{ .name = "precompile",  .module = local_precompile  },
                .{ .name = "mpt_builder", .module = mpt_builder_mod   },
            },
        }),
    });
    // secp256k1_recovery.h and secp256k1.h are in the Homebrew include path.
    // OpenSSL headers and libraries are also required by zevm_local's precompile module.
    t8n_exe.addIncludePath(.{ .cwd_relative = "/opt/homebrew/include" });
    t8n_exe.linkSystemLibrary("secp256k1");
    t8n_exe.linkSystemLibrary("ssl");
    t8n_exe.linkSystemLibrary("crypto");
    t8n_exe.linkSystemLibrary("c");
    t8n_exe.linkSystemLibrary("m");

    b.installArtifact(t8n_exe);

    // zig build t8n [-- --input.alloc ... --state.fork Cancun ...]
    const run_t8n_step = b.step("t8n", "Run the t8n state transition tool");
    const run_t8n_cmd = b.addRunArtifact(t8n_exe);
    run_t8n_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_t8n_cmd.addArgs(args);
    run_t8n_step.dependOn(&run_t8n_cmd.step);

    // zig build fetch-fixtures — download execution-spec-tests v5.4.0 stable fixtures
    const fetch_fixtures_step = b.step("fetch-fixtures", "Download execution-spec-tests fixtures");
    const fetch_cmd = b.addSystemCommand(&.{
        "sh", "-c",
        "mkdir -p test/fixtures && " ++
        "echo 'Downloading execution-spec-tests v5.4.0 fixtures...' && " ++
        "curl -L --progress-bar " ++
        "https://github.com/ethereum/execution-spec-tests/releases/download/v5.4.0/fixtures_stable.tar.gz " ++
        "| tar xz -C test/fixtures/ && " ++
        "echo 'Done. Fixtures extracted to test/fixtures/'",
    });
    fetch_fixtures_step.dependOn(&fetch_cmd.step);
}
