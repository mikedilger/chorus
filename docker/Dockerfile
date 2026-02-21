FROM rust:alpine as builder
RUN apk add --no-cache git
WORKDIR /root
RUN git clone https://github.com/mikedilger/chorus
WORKDIR /root/chorus
RUN git checkout latest
RUN cargo build --release
RUN strip ./target/release/* || true

FROM alpine:latest

# Install system packages
# RUN apk add --no-cache curl gcc musl-dev openssl-dev pkgconfig git make cmake

# Setup chorus user and directories
RUN adduser --system --home /opt/chorus --shell /bin/sh chorus && \
    mkdir -p /opt/chorus/etc /opt/chorus/src/chorus /opt/chorus/var /opt/chorus/sbin /opt/chorus/lib && \
    mkdir -p /opt/chorus/var/chorus /opt/chorus/var/www && \
    mkdir -p /opt/chorus/lib/systemd/system && \
    chown -R chorus /opt/chorus

COPY --from=builder /root/chorus/target/release/chorus /opt/chorus/sbin/chorus
COPY --from=builder /root/chorus/target/release/chorus_cmd /opt/chorus/sbin/chorus_cmd
COPY --from=builder /root/chorus/target/release/chorus_compress /opt/chorus/sbin/chorus_compress
COPY --from=builder /root/chorus/target/release/chorus_dump /opt/chorus/sbin/chorus_dump
COPY --from=builder /root/chorus/target/release/chorus_dump_approvals /opt/chorus/sbin/chorus_dump_approvals
COPY --from=builder /root/chorus/target/release/chorus_moderate /opt/chorus/sbin/chorus_moderate

RUN chown -R chorus /opt/chorus/sbin && chmod 0700 /opt/chorus/sbin/*

COPY chorus.toml /opt/chorus/etc/chorus.toml
RUN chown chorus /opt/chorus/etc/chorus.toml

VOLUME /opt/chorus/etc
VOLUME /opt/chorus/var

WORKDIR /opt/chorus
USER chorus
ENV RUST_BACKTRACE=1
ENV RUST_LOG=info
ENTRYPOINT ["/opt/chorus/sbin/chorus", "/opt/chorus/etc/chorus.toml"]
