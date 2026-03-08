# Stage 1: build
FROM rust:slim AS builder
WORKDIR /app
COPY . .
RUN cargo build --release -p flodar

# Stage 2: runtime
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/flodar .
COPY --from=builder /app/flodar/flodar.toml .
EXPOSE 2055/udp
EXPOSE 9090/tcp
ENTRYPOINT ["./flodar"]
CMD ["--config", "flodar.toml"]
