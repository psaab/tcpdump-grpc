.PHONY: all proto build docker run clean tls test

all: proto build

# ── Protobuf code generation ─────────────────────────────
proto:
	protoc \
		--go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		proto/capture/capture.proto

# ── Build ────────────────────────────────────────────────
build: proto
	CGO_ENABLED=0 go build -ldflags='-w -s' -o bin/tcpdump-grpc ./cmd/tcpdump-grpc
	CGO_ENABLED=0 go build -ldflags='-w -s' -o bin/capture-client ./cmd/capture-client

# ── Docker ───────────────────────────────────────────────
docker:
	docker build -t tcpdump-grpc:latest .

run: docker tls
	docker compose up -d

stop:
	docker compose down

# ── TLS certificates (self-signed, for dev/lab) ─────────
tls:
	@mkdir -p tls
	@if [ ! -f tls/server.key ]; then \
		echo "Generating self-signed TLS certificates..."; \
		openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
			-keyout tls/server.key -out tls/server.crt \
			-days 365 -nodes \
			-subj "/CN=tcpdump-grpc" \
			-addext "subjectAltName=DNS:localhost,DNS:tcpdump-grpc,IP:127.0.0.1"; \
		echo "Certificates written to tls/"; \
	else \
		echo "TLS certificates already exist"; \
	fi

# ── Test ─────────────────────────────────────────────────
test:
	go test ./...

# ── Clean ────────────────────────────────────────────────
clean:
	rm -rf bin/ tls/
	rm -f proto/capture/*.pb.go
