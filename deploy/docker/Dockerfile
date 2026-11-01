FROM golang:1.27.3-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && case "$(dpkg --print-architecture)" in \
        amd64) just_target=x86_64-unknown-linux-musl; just_sha=409044617b6f06517c1035e55ca38c8c856ff8b650e41bc2aa1ef82d5903a23e ;; \
        arm64) just_target=aarch64-unknown-linux-musl; just_sha=23871b1702bfd550fb5f901778fd4290ecf2ee034a45a889fbe96d89b188086d ;; \
        armhf) just_target=armv7-unknown-linux-musleabihf; just_sha=928e2a0fe5fcade06415c55210608efefe43e985a757ded3e219ac4a13b6ed0e ;; \
        *) echo 'Unsupported just bootstrap architecture' >&2; exit 1 ;; \
       esac \
    && curl --fail --location --retry 3 "https://github.com/casey/just/releases/download/1.59.0/just-1.59.0-${just_target}.tar.gz" -o /tmp/just.tar.gz \
    && printf '%s  /tmp/just.tar.gz\n' "$just_sha" | sha256sum --check --strict \
    && tar -xzf /tmp/just.tar.gz -C /usr/local/bin just \
    && rm /tmp/just.tar.gz
WORKDIR /src
COPY go.mod go.sum ./
COPY justfile ./
COPY scripts/ci/ ./scripts/ci/
RUN just ci go-deps
COPY . .
ARG TARGETOS=linux
ARG TARGETARCH=amd64
RUN just ci build-container

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates iproute2 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/kone /usr/local/bin/kone
COPY configs/kone.example.toml /etc/kone/config.toml
COPY LICENSE LICENSE-MIT /usr/share/doc/kone/
COPY licenses /usr/share/doc/kone/licenses/
ENTRYPOINT ["/usr/local/bin/kone"]
CMD ["-config", "/etc/kone/config.toml"]
