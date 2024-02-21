#!/bin/bash

cargo build --release && \
    ./target/release/chorus ./sample/sample.config.toml
