FROM alpine:latest

# Install system packages
RUN apk add --no-cache curl gcc musl-dev openssl-dev pkgconfig git make cmake

# Install rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

# Setup chorus user and directories
RUN adduser --system --home /opt/chorus --shell /bin/sh chorus && \
    mkdir -p /opt/chorus/etc /opt/chorus/src /opt/chorus/var /opt/chorus/sbin /opt/chorus/lib && \
    mkdir -p /opt/chorus/var/chorus /opt/chorus/var/www && \
    mkdir -p /opt/chorus/lib/systemd/system && \
    chown -R chorus /opt/chorus

# Clone chorus
WORKDIR /opt/chorus/src
RUN git clone https://github.com/mikedilger/chorus

# Build chorus
WORKDIR /opt/chorus/src/chorus
RUN git checkout latest && ~/.cargo/bin/cargo build --release
RUN install --mode=0700 --owner=chorus -t /opt/chorus/sbin/ \
    ./target/release/chorus \
    ./target/release/chorus_compress \
    ./target/release/chorus_dump \
    ./target/release/chorus_dump_approvals \
    ./target/release/chorus_moderate \
    ./target/release/chorus_cmd

COPY chorus.toml /opt/chorus/etc/chorus.toml
RUN chown chorus /opt/chorus/etc/chorus.toml

WORKDIR /opt/chorus
USER chorus
ENV RUST_BACKTRACE=1
ENV RUST_LOG=info

ENTRYPOINT ["/opt/chorus/sbin/chorus", "/opt/chorus/etc/chorus.toml"]