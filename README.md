# zevm-stateless

A Zig implementation of the guest program for the [ZK Proofs Ethereum](https://ethereum.org/en/roadmap/statelessness/) protocol. It uses [zevm](https://github.com/Consensys/zevm) as its EVM execution engine.

## Overview

This repository contains the logic required to run as a guest program in a ZK proving system, executing EVM blocks and producing outputs that can be verified by an on-chain verifier.

## Dependencies

- [Zig](https://ziglang.org/)
- [zevm](https://github.com/Consensys/zevm) — EVM implementation in Zig
