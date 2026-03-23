# Testing

## zevm_stateless

```sh
# JSON (block + witness files)
./zig-out/bin/zevm_stateless --json test/vectors/stateless/json/test_block.json test/vectors/stateless/json/test_block_witness.json

# RLP binary
./zig-out/bin/zevm_stateless --rlp test/vectors/stateless/rlp/test_stateless_input.bin

# SSZ binary (Amsterdam)
./zig-out/bin/zevm_stateless --ssz test/vectors/stateless/ssz/slotnum_input.ssz
```

Or via build system:

```sh
zig build run-test-block
```

## t8n

```sh
./zig-out/bin/t8n \
  --input.alloc test/vectors/t8n/transfer_test/alloc.json \
  --input.env   test/vectors/t8n/transfer_test/env.json \
  --input.txs   test/vectors/t8n/transfer_test/txs.json \
  --output.result /dev/stdout

./zig-out/bin/t8n \
  --input.alloc test/vectors/t8n/tstore_test/alloc.json \
  --input.env   test/vectors/t8n/tstore_test/env.json \
  --input.txs   test/vectors/t8n/tstore_test/txs.json \
  --output.result /dev/stdout
```

Or via build system:

```sh
zig build t8n
```

## blockchain-test-runner

```sh
# Run all fixtures
zig build blockchain-tests

# Run a specific directory
./zig-out/bin/blockchain-test-runner --fixtures <path-to-dir>

# Run a single file
./zig-out/bin/blockchain-test-runner --fixtures <path-to-fixture.json>

# Filter by fork
./zig-out/bin/blockchain-test-runner --fork Cancun

# Quiet (summary only)
./zig-out/bin/blockchain-test-runner -q
```

## spec-test-runner / all-spec-tests-runner

```sh
zig build state-tests       # execution-spec-tests state fixtures
zig build spec-tests        # state + blockchain combined
```

## hive-rlp

Requires the [Hive](https://github.com/ethereum/hive) harness — no local test vectors.

```sh
./zig-out/bin/hive-rlp --help
```

## Unit tests

```sh
zig build test
```
