# zevm-stateless Hive Client

This directory contains the `hive-rlp` client — a minimal Ethereum node implementation
that satisfies the [ethereum/hive](https://github.com/ethereum/hive) `consume-rlp` simulator
interface. It is used to test zevm-stateless block import and JSON-RPC correctness.

## What it does

On startup the binary:
1. Reads fork schedule from hive environment variables (`HIVE_CHAIN_ID`,
   `HIVE_FORK_HOMESTEAD`, `HIVE_FORK_BERLIN`, `HIVE_SHANGHAI_TIMESTAMP`, etc.)
2. Parses `/genesis.json` (geth format) to build the genesis state and genesis block hash
3. Imports pre-built RLP blocks from `/blocks/0001.rlp`, `/blocks/0002.rlp`, … in order
4. Serves a minimal JSON-RPC endpoint on `:8545` (`eth_blockNumber`, `eth_getBlockByNumber`)

## Building the Docker image

The Dockerfile is a two-stage build. The Docker build **context must be the parent
directory** that contains both `zevm/` and `zevm-stateless/` as siblings, because the
build copies both trees:

```sh
# from the parent directory (e.g. ~/dev/stateless/)
docker build \
  -f zevm-stateless/src/hive/Dockerfile \
  --target runtime \
  -t zevm-stateless-hive:latest \
  .
```

The `.dockerignore` file lives at `src/hive/Dockerfile.dockerignore` (hive passes it as
the ignore file for this client).

Build dependencies installed inside the container:
- Zig 0.15.2 (downloaded from ziglang.org)
- [blst](https://github.com/supranational/blst) (BLS12-381, built from source)
- [mcl](https://github.com/herumi/mcl) (BN254, built from source with clang/libc++)

## Running with hive

Install hive and run the `consume-rlp` simulator against this client:

```sh
# clone hive
git clone https://github.com/ethereum/hive
cd hive

# build hive
go build .

# run consume-rlp against zevm-stateless
./hive --sim ethereum/consensus \
       --client zevm-stateless \
       --client.buildarg TARGETARCH=amd64
```

Hive builds the Docker image automatically using the `Dockerfile` in the client
directory. Ensure the image tag registered in hive's client list matches the one
produced by the build above.

## Environment variables injected by hive

| Variable | Description |
|---|---|
| `HIVE_CHAIN_ID` | EIP-155 chain ID |
| `HIVE_FORK_HOMESTEAD` | Block number activating Homestead |
| `HIVE_FORK_TANGERINE` | Block number activating EIP-150 |
| `HIVE_FORK_SPURIOUS` | Block number activating EIP-158 |
| `HIVE_FORK_BYZANTIUM` | Block number activating Byzantium |
| `HIVE_FORK_CONSTANTINOPLE` | Block number activating Constantinople |
| `HIVE_FORK_PETERSBURG` | Block number activating Petersburg |
| `HIVE_FORK_ISTANBUL` | Block number activating Istanbul |
| `HIVE_FORK_BERLIN` | Block number activating Berlin |
| `HIVE_FORK_LONDON` | Block number activating London |
| `HIVE_FORK_PARIS` | Block number activating Paris (The Merge) |
| `HIVE_SHANGHAI_TIMESTAMP` | Timestamp activating Shanghai |
| `HIVE_CANCUN_TIMESTAMP` | Timestamp activating Cancun |
| `HIVE_PRAGUE_TIMESTAMP` | Timestamp activating Prague |

## JSON-RPC surface

Only the methods required by `consume-rlp` are implemented:

| Method | Notes |
|---|---|
| `eth_blockNumber` | Returns the current chain head as a hex integer |
| `eth_getBlockByNumber` | Returns block by number (`"latest"` supported); `fullTransactions` param accepted but transactions are not included in the response |

## Source layout

| File | Role |
|---|---|
| `Dockerfile` | Two-stage Docker build |
| `fork_env.zig` | Parses hive fork env vars into a `ForkSchedule` |
| `genesis.zig` | Parses `/genesis.json` → genesis state + genesis hash |
| `chain.zig` | In-memory chain; imports RLP blocks sequentially |
| `rpc.zig` | Minimal HTTP/1.1 JSON-RPC server on `:8545` |
| `../../hive_rlp.zig` | Entry point (`hive-rlp` binary) |
