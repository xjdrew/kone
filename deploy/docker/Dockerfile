FROM golang:1.27.3-bookworm AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS=linux
ARG TARGETARCH=amd64
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -tags with_gvisor -trimpath -ldflags="-s -w" -o /out/kone ./cmd/kone

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates iproute2 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/kone /usr/local/bin/kone
COPY configs/kone.example.toml /etc/kone/config.toml
COPY LICENSE LICENSE-MIT THIRD_PARTY_NOTICES.md /usr/share/doc/kone/
COPY licenses /usr/share/doc/kone/licenses/
ENTRYPOINT ["/usr/local/bin/kone"]
CMD ["-config", "/etc/kone/config.toml"]
