const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Platform-aware crypto library prefix: Homebrew on macOS, /usr/local on Linux
    const is_linux = b.graph.host.result.os.tag == .linux;
    const crypto_prefix = if (is_linux) "/usr/local" else "/opt/homebrew";
    const crypto_include = b.fmt("{s}/include", .{crypto_prefix});
    const libblst_path   = b.fmt("{s}/lib/libblst.a", .{crypto_prefix});
    const libmcl_path    = b.fmt("{s}/lib/libmcl.a", .{crypto_prefix});

    // Build options — crypto libraries are disabled by default for zkVM targets
    const lib_options = b.addOptions();
    lib_options.addOption(bool, "enable_blst", false);
    lib_options.addOption(bool, "enable_mcl", false);
    const lib_options_module = lib_options.createModule();

    // Build options for native tools (spec-test-runner, t8n) — crypto enabled for correct precompile behavior
    const native_lib_options = b.addOptions();
    native_lib_options.addOption(bool, "enable_blst", true);
    native_lib_options.addOption(bool, "enable_mcl", true);
    const native_lib_options_module = native_lib_options.createModule();

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

    // mpt_nibbles: shared nibble utilities — standalone so mpt and mpt_builder can both use it
    const mpt_nibbles_mod = b.createModule(.{
        .root_source_file = b.path("src/mpt/nibbles.zig"),
        .target = target,
        .optimize = optimize,
    });

    const mpt_mod = b.addModule("mpt", .{
        .root_source_file = b.path("src/mpt/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    mpt_mod.addImport("primitives", primitives);
    mpt_mod.addImport("input", input_mod);
    mpt_mod.addImport("mpt_nibbles", mpt_nibbles_mod);

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

    // mpt_builder: standalone trie builder (shares nibbles with mpt via mpt_nibbles)
    const mpt_builder_mod = b.addModule("mpt_builder", .{
        .root_source_file = b.path("src/mpt/builder.zig"),
        .target = target,
        .optimize = optimize,
    });
    mpt_builder_mod.addImport("mpt_nibbles", mpt_nibbles_mod);

    const executor_mod = b.addModule("executor", .{
        .root_source_file = b.path("src/executor/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    executor_mod.addImport("primitives", primitives);
    executor_mod.addImport("state", state);
    executor_mod.addImport("bytecode", bytecode);
    executor_mod.addImport("database", database);
    executor_mod.addImport("context", context);
    executor_mod.addImport("handler", handler);
    executor_mod.addImport("precompile", precompile);
    executor_mod.addImport("mpt", mpt_mod);
    executor_mod.addImport("mpt_builder", mpt_builder_mod);
    executor_mod.addImport("db", db_mod);
    executor_mod.addImport("input", input_mod);
    executor_mod.addImport("output", output_mod);
    // Note: named executor sub-modules (executor_fork, executor_tx_decode, etc.)
    // are added further below, after those module variables are created.

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

    // Link crypto libraries required by native_executor_transition (secp256k1, OpenSSL, blst, mcl)
    exe.addIncludePath(.{ .cwd_relative = crypto_include });
    exe.linkSystemLibrary("secp256k1");
    exe.linkSystemLibrary("ssl");
    exe.linkSystemLibrary("crypto");
    exe.linkSystemLibrary("c");
    exe.linkSystemLibrary("m");
    exe.addObjectFile(.{ .cwd_relative = libblst_path });
    exe.addObjectFile(.{ .cwd_relative = libmcl_path });
    exe.linkLibCpp();

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

    // Enable blst and mcl for native tools: override build_options and expose headers
    local_precompile.addImport("build_options", native_lib_options_module);
    local_precompile.addIncludePath(.{ .cwd_relative = crypto_include });

    // ── Named executor modules for t8n / spec-test ───────────────────────────────
    // These expose executor/ source files as named imports so that t8n and spec-test
    // can import them without crossing module-root boundaries.

    // executor_types — canonical EVM type definitions; no external deps
    const executor_types_mod = b.createModule(.{
        .root_source_file = b.path("src/executor/types.zig"),
        .target = target,
        .optimize = optimize,
    });

    // executor_rlp_encode — RLP encoding primitives; shared by transition and output
    const executor_rlp_encode_mod = b.createModule(.{
        .root_source_file = b.path("src/executor/rlp_encode.zig"),
        .target = target,
        .optimize = optimize,
    });

    // native_executor_transition — transition logic using crypto-enabled local zevm
    const native_executor_transition_mod = b.createModule(.{
        .root_source_file = b.path("src/executor/transition.zig"),
        .target = target,
        .optimize = optimize,
    });
    native_executor_transition_mod.addImport("executor_types",      executor_types_mod);
    native_executor_transition_mod.addImport("executor_rlp_encode", executor_rlp_encode_mod);
    native_executor_transition_mod.addImport("primitives",          local_primitives);
    native_executor_transition_mod.addImport("state",          local_state);
    native_executor_transition_mod.addImport("bytecode",       local_bytecode);
    native_executor_transition_mod.addImport("database",       local_database);
    native_executor_transition_mod.addImport("context",        local_context);
    native_executor_transition_mod.addImport("handler",        local_handler);
    native_executor_transition_mod.addImport("precompile",     local_precompile);

    // native_executor_output — trie computations; uses executor_transition for type consistency
    const native_executor_output_mod = b.createModule(.{
        .root_source_file = b.path("src/executor/output.zig"),
        .target = target,
        .optimize = optimize,
    });
    native_executor_output_mod.addImport("executor_types",       executor_types_mod);
    native_executor_output_mod.addImport("executor_rlp_encode",  executor_rlp_encode_mod);
    native_executor_output_mod.addImport("mpt_builder",          mpt_builder_mod);

    // executor_fork — mainnet hardfork schedule (block/timestamp → SpecId + reward)
    const executor_fork_mod = b.createModule(.{
        .root_source_file = b.path("src/executor/fork.zig"),
        .target = target,
        .optimize = optimize,
    });
    executor_fork_mod.addImport("primitives", local_primitives);

    // native_executor_tx_decode — raw RLP tx bytes → TxInput (no ECDSA here)
    const native_executor_tx_decode_mod = b.createModule(.{
        .root_source_file = b.path("src/executor/tx_decode.zig"),
        .target = target,
        .optimize = optimize,
    });
    native_executor_tx_decode_mod.addImport("executor_types", executor_types_mod);
    native_executor_tx_decode_mod.addImport("mpt",            mpt_mod);

    // Deferred: wire executor_output into transition (output_mod created after transition_mod)
    native_executor_transition_mod.addImport("executor_output", native_executor_output_mod);

    // Wire named executor sub-modules into executor_mod (deferred — modules created above)
    executor_mod.addImport("executor_types",      executor_types_mod);
    executor_mod.addImport("executor_rlp_encode", executor_rlp_encode_mod);
    executor_mod.addImport("executor_transition", native_executor_transition_mod);
    executor_mod.addImport("executor_output",     native_executor_output_mod);
    executor_mod.addImport("executor_fork",       executor_fork_mod);
    executor_mod.addImport("executor_tx_decode",  native_executor_tx_decode_mod);

    // t8n_input — t8n JSON parsing + re-exports executor types; used by spec-test-runner
    const t8n_input_mod = b.createModule(.{
        .root_source_file = b.path("src/t8n/input.zig"),
        .target = target,
        .optimize = optimize,
    });
    t8n_input_mod.addImport("executor_types", executor_types_mod);

    const t8n_exe = b.addExecutable(.{
        .name = "t8n",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/t8n/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "primitives",          .module = local_primitives               },
                .{ .name = "state",               .module = local_state                    },
                .{ .name = "bytecode",            .module = local_bytecode                 },
                .{ .name = "database",            .module = local_database                 },
                .{ .name = "context",             .module = local_context                  },
                .{ .name = "handler",             .module = local_handler                  },
                .{ .name = "precompile",          .module = local_precompile               },
                .{ .name = "mpt_builder",         .module = mpt_builder_mod                },
                .{ .name = "executor_types",      .module = executor_types_mod             },
                .{ .name = "executor_transition", .module = native_executor_transition_mod },
                .{ .name = "executor_output",     .module = native_executor_output_mod     },
            },
        }),
    });
    // secp256k1_recovery.h and secp256k1.h are in the Homebrew include path.
    // OpenSSL headers and libraries are also required by zevm_local's precompile module.
    t8n_exe.addIncludePath(.{ .cwd_relative = crypto_include });
    t8n_exe.linkSystemLibrary("secp256k1");
    t8n_exe.linkSystemLibrary("ssl");
    t8n_exe.linkSystemLibrary("crypto");
    t8n_exe.linkSystemLibrary("c");
    t8n_exe.linkSystemLibrary("m");
    t8n_exe.addObjectFile(.{ .cwd_relative = libblst_path });
    t8n_exe.addObjectFile(.{ .cwd_relative = libmcl_path });
    t8n_exe.linkLibCpp();

    b.installArtifact(t8n_exe);

    // zig build t8n [-- --input.alloc ... --state.fork Cancun ...]
    const run_t8n_step = b.step("t8n", "Run the t8n state transition tool");
    const run_t8n_cmd = b.addRunArtifact(t8n_exe);
    run_t8n_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_t8n_cmd.addArgs(args);
    run_t8n_step.dependOn(&run_t8n_cmd.step);

    // ---------------------------------------------------------------------------
    // spec-test-runner — Native Zig runner for execution-spec-tests state fixtures
    //
    // Reads fixture JSONs from test/fixtures/fixtures/state_tests, builds TxInput
    // from indexed transaction fields + transaction.sender (no ECDSA), calls
    // transition() directly, and compares stateRoot + logsHash to expected values.
    //
    // Usage: zig build state-tests [-- --fork Cancun --file path/to/fixture.json -x]
    // Fixtures dir: spec-tests/fixtures/state_tests (download with: zig build fetch-fixtures)
    // ---------------------------------------------------------------------------
    const spec_test_exe = b.addExecutable(.{
        .name = "spec-test-runner",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/spec_test_runner.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "primitives",          .module = local_primitives               },
                .{ .name = "state",               .module = local_state                    },
                .{ .name = "bytecode",            .module = local_bytecode                 },
                .{ .name = "database",            .module = local_database                 },
                .{ .name = "context",             .module = local_context                  },
                .{ .name = "handler",             .module = local_handler                  },
                .{ .name = "precompile",          .module = local_precompile               },
                .{ .name = "mpt_builder",         .module = mpt_builder_mod                },
                .{ .name = "executor_types",      .module = executor_types_mod             },
                .{ .name = "executor_transition", .module = native_executor_transition_mod },
                .{ .name = "executor_output",     .module = native_executor_output_mod     },
                .{ .name = "t8n_input",           .module = t8n_input_mod                  },
            },
        }),
    });
    spec_test_exe.addIncludePath(.{ .cwd_relative = crypto_include });
    spec_test_exe.linkSystemLibrary("secp256k1");
    spec_test_exe.linkSystemLibrary("ssl");
    spec_test_exe.linkSystemLibrary("crypto");
    spec_test_exe.linkSystemLibrary("c");
    spec_test_exe.linkSystemLibrary("m");
    spec_test_exe.addObjectFile(.{ .cwd_relative = libblst_path });
    spec_test_exe.addObjectFile(.{ .cwd_relative = libmcl_path });
    spec_test_exe.linkLibCpp();

    b.installArtifact(spec_test_exe);

    const run_state_tests_step = b.step("state-tests", "Run execution-spec-tests state fixtures");
    const run_spec_tests_cmd = b.addRunArtifact(spec_test_exe);
    run_spec_tests_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_spec_tests_cmd.addArgs(args);
    run_state_tests_step.dependOn(&run_spec_tests_cmd.step);

    // ---------------------------------------------------------------------------
    // blockchain-test-runner — Ethereum blockchain test fixture runner
    //
    // Reads blockchain_tests JSON fixtures, executes each single-block test,
    // and validates post_state_root, receipts_root, and lastblockhash.
    //
    // Usage: zig build blockchain-tests [-- --fork Cancun --file path/to/fixture.json -x -q]
    // Fixtures dir: spec-tests/fixtures/blockchain_tests
    // ---------------------------------------------------------------------------

    // blockchain_test runner module
    const blockchain_test_runner_mod = b.createModule(.{
        .root_source_file = b.path("src/blockchain_test/runner.zig"),
        .target = target,
        .optimize = optimize,
    });
    blockchain_test_runner_mod.addImport("primitives",           local_primitives);
    blockchain_test_runner_mod.addImport("executor_types",       executor_types_mod);
    blockchain_test_runner_mod.addImport("executor_transition",  native_executor_transition_mod);
    blockchain_test_runner_mod.addImport("executor_output",      native_executor_output_mod);
    blockchain_test_runner_mod.addImport("executor_fork",        executor_fork_mod);
    blockchain_test_runner_mod.addImport("executor_tx_decode",   native_executor_tx_decode_mod);
    blockchain_test_runner_mod.addImport("mpt",                  mpt_mod);

    const bc_test_exe = b.addExecutable(.{
        .name = "blockchain-test-runner",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/blockchain_test_runner.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "primitives",          .module = local_primitives               },
                .{ .name = "state",               .module = local_state                    },
                .{ .name = "bytecode",            .module = local_bytecode                 },
                .{ .name = "database",            .module = local_database                 },
                .{ .name = "context",             .module = local_context                  },
                .{ .name = "handler",             .module = local_handler                  },
                .{ .name = "precompile",          .module = local_precompile               },
                .{ .name = "mpt_builder",         .module = mpt_builder_mod                },
                .{ .name = "executor_types",      .module = executor_types_mod             },
                .{ .name = "executor_transition", .module = native_executor_transition_mod },
                .{ .name = "executor_output",     .module = native_executor_output_mod     },
                .{ .name = "blockchain_test/runner.zig", .module = blockchain_test_runner_mod },
            },
        }),
    });
    bc_test_exe.addIncludePath(.{ .cwd_relative = crypto_include });
    bc_test_exe.linkSystemLibrary("secp256k1");
    bc_test_exe.linkSystemLibrary("ssl");
    bc_test_exe.linkSystemLibrary("crypto");
    bc_test_exe.linkSystemLibrary("c");
    bc_test_exe.linkSystemLibrary("m");
    bc_test_exe.addObjectFile(.{ .cwd_relative = libblst_path });
    bc_test_exe.addObjectFile(.{ .cwd_relative = libmcl_path });
    bc_test_exe.linkLibCpp();

    b.installArtifact(bc_test_exe);

    const run_bc_tests_step = b.step("blockchain-tests", "Run Ethereum blockchain test fixtures");
    const run_bc_tests_cmd = b.addRunArtifact(bc_test_exe);
    run_bc_tests_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_bc_tests_cmd.addArgs(args);
    run_bc_tests_step.dependOn(&run_bc_tests_cmd.step);

    // ---------------------------------------------------------------------------
    // all-spec-tests-runner — combined state + blockchain spec-test runner
    //
    // Spawns spec-test-runner and blockchain-test-runner as subprocesses and
    // prints a unified summary across both suites.
    //
    // Usage: zig build spec-tests [-- --fork Cancun -q]
    // ---------------------------------------------------------------------------
    const all_spec_exe = b.addExecutable(.{
        .name = "all-spec-tests-runner",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/all_spec_tests_runner.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    b.installArtifact(all_spec_exe);

    const run_spec_tests_step = b.step("spec-tests", "Run all spec-tests: state + blockchain");
    const run_all_spec_cmd = b.addRunArtifact(all_spec_exe);
    run_all_spec_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_all_spec_cmd.addArgs(args);
    run_spec_tests_step.dependOn(&run_all_spec_cmd.step);

    // ---------------------------------------------------------------------------
    // hive-rlp — Hive consume-rlp execution client
    //
    // Reads /genesis.json and /blocks/*.rlp at startup, executes the chain,
    // and serves eth_getBlockByNumber on :8545 for Hive validation.
    //
    // Usage: zig build hive-rlp
    // ---------------------------------------------------------------------------
    const hive_rlp_exe = b.addExecutable(.{
        .name = "hive-rlp",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/hive_rlp.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "primitives",          .module = local_primitives               },
                .{ .name = "state",               .module = local_state                    },
                .{ .name = "bytecode",            .module = local_bytecode                 },
                .{ .name = "database",            .module = local_database                 },
                .{ .name = "context",             .module = local_context                  },
                .{ .name = "handler",             .module = local_handler                  },
                .{ .name = "precompile",          .module = local_precompile               },
                .{ .name = "mpt_builder",         .module = mpt_builder_mod                },
                .{ .name = "mpt",                 .module = mpt_mod                        },
                .{ .name = "executor_types",      .module = executor_types_mod             },
                .{ .name = "executor_rlp_encode", .module = executor_rlp_encode_mod        },
                .{ .name = "executor_transition", .module = native_executor_transition_mod },
                .{ .name = "executor_output",     .module = native_executor_output_mod     },
                .{ .name = "executor_fork",       .module = executor_fork_mod              },
                .{ .name = "executor_tx_decode",  .module = native_executor_tx_decode_mod  },
            },
        }),
    });
    hive_rlp_exe.addIncludePath(.{ .cwd_relative = crypto_include });
    hive_rlp_exe.linkSystemLibrary("secp256k1");
    hive_rlp_exe.linkSystemLibrary("ssl");
    hive_rlp_exe.linkSystemLibrary("crypto");
    hive_rlp_exe.linkSystemLibrary("c");
    hive_rlp_exe.linkSystemLibrary("m");
    hive_rlp_exe.addObjectFile(.{ .cwd_relative = libblst_path });
    hive_rlp_exe.addObjectFile(.{ .cwd_relative = libmcl_path });
    hive_rlp_exe.linkLibCpp();

    b.installArtifact(hive_rlp_exe);

    const run_hive_rlp_step = b.step("hive-rlp", "Build and install the Hive consume-rlp client");
    run_hive_rlp_step.dependOn(b.getInstallStep());

    // zig build fetch-fixtures — download execution-spec-tests v5.4.0 develop fixtures
    const fetch_fixtures_step = b.step("fetch-fixtures", "Download execution-spec-tests fixtures");
    const fetch_cmd = b.addSystemCommand(&.{
        "sh", "-c",
        "rm -rf spec-tests/fixtures && " ++
        "mkdir -p spec-tests/fixtures && " ++
        "echo 'Downloading execution-spec-tests v5.4.0 fixtures...' && " ++
        "curl -fL " ++
        "https://github.com/ethereum/execution-spec-tests/releases/download/v5.4.0/fixtures_develop.tar.gz " ++
        "| tar xz --strip-components=1 -C spec-tests/fixtures/ && " ++
        "echo 'Done. Fixtures extracted to spec-tests/fixtures/'",
    });
    fetch_fixtures_step.dependOn(&fetch_cmd.step);
}
