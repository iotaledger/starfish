# syntax=docker/dockerfile:1
FROM rust:1.85-bookworm AS builder
RUN apt-get update && apt-get install -y clang libclang-dev lld \
    && rm -rf /var/lib/apt/lists/*
RUN mkdir -p ~/.cargo && \
    cat > ~/.cargo/config.toml <<'EOF'
[target.x86_64-unknown-linux-gnu]
linker = "clang"
rustflags = ["-C", "link-arg=-fuse-ld=lld"]
EOF
WORKDIR /app
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target,sharing=locked \
    cargo build --release --all-features --bin starfish && \
    cp target/release/starfish /usr/local/bin/starfish && \
    strip /usr/local/bin/starfish

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y libssl3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/bin/starfish /usr/local/bin/starfish
ENTRYPOINT ["starfish"]
