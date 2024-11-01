FROM rust:latest AS builder

RUN update-ca-certificates

COPY . /build
WORKDIR /build

RUN for example in account auth_verify idp; \
do ( \
    cd "./examples/$example/"; \
    cargo build --profile dev; \
) done

FROM debian:bookworm-slim

ARG DEBIAN_FRONTEND=noninteractive
RUN apt update && \
    apt install -y --no-install-recommends curl openssl && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /oidc-rp

COPY --from=builder /build/target/debug/account ./
COPY --from=builder /build/target/debug/auth_verify ./
COPY --from=builder /build/target/debug/idp ./
