# Starfish

[![rustc](https://img.shields.io/badge/rustc-1.78+-blue?style=flat-square&logo=rust)](https://www.rust-lang.org)
[![license](https://img.shields.io/badge/license-Apache-blue.svg?style=flat-square)](LICENSE)

The code in this repository is a prototype of Starfish. 

The goal of the proposed improvement is to mitigate the Byzantine behavior, ensure the liveness of the consensus protocol, and provide the communication complexity (for one committed byte of transactions) linear with the number of validators.

## Quick Start

Run a dry-run test with N validators and TPS transactions per second:
