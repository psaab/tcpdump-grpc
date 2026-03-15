# ============================================================
# Stage 1: Build the Go binary
# ============================================================
FROM golang:1.25-bookworm AS builder

# Install protoc and Go protobuf plugins for code generation
RUN apt-get update && apt-get install -y --no-install-recommends \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@latest && \
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

WORKDIR /build

# Copy everything in first
COPY . .

# Generate protobuf Go code from .proto definitions
RUN protoc \
      --go_out=. --go_opt=paths=source_relative \
      --go-grpc_out=. --go-grpc_opt=paths=source_relative \
      proto/capture/capture.proto

# Resolve dependencies and generate go.sum
RUN go mod tidy

# Build both binaries
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags='-w -s -extldflags "-static"' \
    -o /build/tcpdump-grpc \
    ./cmd/tcpdump-grpc

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags='-w -s -extldflags "-static"' \
    -o /build/capture-client \
    ./cmd/capture-client

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags='-w -s -extldflags "-static"' \
    -o /build/mcp-server \
    ./cmd/mcp-server

# ============================================================
# Stage 2: Minimal runtime image
# ============================================================
FROM debian:bookworm-slim

# Install tcpdump and ca-certificates (for TLS), nothing else
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        tcpdump \
        libcap2-bin \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create a non-root user for the service.
# The capture capability is granted to the tcpdump binary, not the user.
RUN groupadd -r capturer && useradd -r -g capturer -s /sbin/nologin capturer

# Grant tcpdump the ability to capture without root.
# This is the key security measure: the container does NOT run as root,
# but tcpdump gets CAP_NET_RAW via file capabilities.
RUN setcap cap_net_raw+eip /usr/bin/tcpdump

# Copy the binaries
COPY --from=builder /build/tcpdump-grpc /usr/local/bin/tcpdump-grpc
COPY --from=builder /build/capture-client /usr/local/bin/capture-client
COPY --from=builder /build/mcp-server /usr/local/bin/mcp-server

# TLS certificates mount point
RUN mkdir -p /etc/tcpdump-grpc/tls && chown capturer:capturer /etc/tcpdump-grpc/tls

# Drop to non-root user
USER capturer

EXPOSE 50051

ENTRYPOINT ["/usr/local/bin/tcpdump-grpc"]
CMD ["-listen", ":50051", "-log-json"]
