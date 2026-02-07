# ============================
FROM lukemathwalker/cargo-chef:0.1.71-rust-bookworm AS chef
WORKDIR /app
RUN apt update && apt install lld clang -y

# ============================
FROM chef AS planner
COPY . .
# Compute a lock-like file for our project
RUN cargo chef prepare --recipe-path recipe.json

# ============================
FROM chef AS builder
ENV SQLX_OFFLINE=true
COPY --from=planner /app/recipe.json recipe.json
# Build project dependencies, not our application!
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
# Build project
RUN cargo build --release --bin server --bin db

# ============================
FROM debian:bookworm-slim AS runtime

# Set the working directory
WORKDIR /app

# Install runtime dependencies
RUN apt-get update -y \
  && apt-get install -y --no-install-recommends curl wget ca-certificates \
  # Clean up to keep the image size small
  && apt-get autoremove -y \
  && apt-get clean -y \
  && rm -rf /var/lib/apt/lists/*

# Copy the compiled binary from the builder stage
COPY --from=builder /app/target/release/server server
COPY --from=builder /app/target/release/db db

# Set environment variables
ENV PORT=8080
ENV APP_ENV=production
ENV RUST_LOG="server=info,tower_http=info,sqlx=info"

# Expose the port your app runs on
EXPOSE 8080

# Add health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/api/v1/health || exit 1

# Run the binary
ENTRYPOINT ["./server"]
