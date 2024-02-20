#!/bin/bash

export RUST_LOG='info,chorus=debug'

cargo build --release && \
    ./target/release/chorus ./sample/sample.config.toml
