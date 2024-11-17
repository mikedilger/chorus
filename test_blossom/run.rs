#!/bin/bash

pushd ..
cargo build --release || exit 1
popd
../target/release/chorus ./config.toml
