# Testing Chorus with relay-tester

First, git clone https://github.com/mikedilger/relay-tester and build that project
(cargo build --release).

Then copy that target/release/relay-tester binary into this directory.

Then run from two different shells, in this order:

shell1:  ./test_chorus.sh

shell2:  ./run_relay_tester.sh
