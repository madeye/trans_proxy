FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    nftables \
    iproute2 \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /app

# Cache dependencies by building with stub sources
COPY Cargo.toml Cargo.lock ./
COPY e2e/Cargo.toml e2e/
COPY test_servers/Cargo.toml test_servers/
RUN mkdir -p src e2e/src test_servers/src && \
    echo 'fn main() {}' > src/main.rs && \
    echo 'fn main() {}' > e2e/src/main.rs && \
    echo 'fn main() {}' > test_servers/src/main.rs && \
    cargo build --release --workspace 2>/dev/null || true && \
    rm -rf src e2e/src test_servers/src

COPY . .

RUN cargo build --release --workspace
RUN cargo test --release --workspace

CMD ["/app/target/release/trans_proxy", "--help"]
