# Multi-stage build using Chainguard images.
#
# Build stage: cgr.dev/chainguard/go — minimal Go toolchain, no shell, no package manager.
# Runtime stage: cgr.dev/chainguard/static — distroless, read-only filesystem, non-root UID.
#
# Chainguard images are rebuilt daily with zero known CVEs and come with SLSA L3 provenance
# and Sigstore signatures that can be verified with:
#   cosign verify cgr.dev/chainguard/static --certificate-oidc-issuer https://token.actions.githubusercontent.com ...
#
# Usage:
#   docker build --build-arg BINARY=idp -t wimse-idp .
#   docker build --build-arg BINARY=workload-b -t wimse-workload-b .

ARG BINARY=idp

# ── Build stage ───────────────────────────────────────────────────────────────
FROM cgr.dev/chainguard/go:latest AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download -x

COPY . .

ARG BINARY
RUN CGO_ENABLED=0 GOOS=linux go build \
      -trimpath \
      -ldflags="-s -w" \
      -o /out/wimse-${BINARY} \
      ./cmd/${BINARY}

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM cgr.dev/chainguard/static:latest

# Chainguard static runs as non-root UID 65532 (nonroot) by default.
# No shell, no package manager, no libc — minimal attack surface.

ARG BINARY
COPY --from=builder /out/wimse-${BINARY} /usr/local/bin/wimse

EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/wimse"]
