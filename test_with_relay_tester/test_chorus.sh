#!/bin/bash

echo "Use ws://localhost:8080/ as the relay url"

cargo build --release
rm -rf ./data/
../target/release/chorus_init ./test_chorus.toml
../target/release/chorus_cmd ./test_chorus.toml add_user de16d3ed2d5ceb91d33e39dbe30585164e0c19f3f2e2a5b121def086b447a2e5 0
../target/release/chorus_cmd ./test_chorus.toml add_user 35d6bbcf17fc31a9c4f7a2f68aa40ad32c8f9de1ae77505dc5eb3722d8b2987d 0
../target/release/chorus ./test_chorus.toml
