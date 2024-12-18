FROM rust:1.78.0 AS builder

COPY src/ src/
COPY Cargo.toml Cargo.toml
COPY Cargo.lock Cargo.lock

RUN rustup target add wasm32-wasip1

RUN cargo build --target=wasm32-wasip1 --release

##################################################

FROM envoyproxy/envoy:v1.31-latest

COPY --from=builder /target/wasm32-wasip1/release/basic_auth_plugin.wasm /etc/envoy/proxy-wasm-plugins/basic_auth_plugin.wasm

CMD [ "envoy", "-c", "/etc/envoy/envoy.yaml" ]
