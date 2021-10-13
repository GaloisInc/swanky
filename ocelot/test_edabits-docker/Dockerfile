# docker build -f docker/Dockerfile -t swanky .

FROM ubuntu:focal

RUN apt-get update
RUN apt-get install -y \
    build-essential \
    curl \
    net-tools \
    iputils-ping \
    iproute2
RUN apt-get update

# Get Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

ENV PATH="/root/.cargo/bin:${PATH}"

COPY . /root/swanky/.

WORKDIR /root/swanky/ocelot
RUN cargo build --release
RUN cargo run --release --example network_edabits -- --help
# RUN cargo test --release edabits 
