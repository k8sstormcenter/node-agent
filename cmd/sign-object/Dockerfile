FROM --platform=$BUILDPLATFORM golang:1.25-trixie AS builder

ENV GO111MODULE=on CGO_ENABLED=0
WORKDIR /src
ARG TARGETOS TARGETARCH

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    go mod download

COPY . .
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /sign-object ./cmd/sign-object

# Pinned, non-root distroless static base (UID 65532) — minimal, reproducible.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:963fa6c544fe5ce420f1f54fb88b6fb01479f054c8056d0f74cc2c6000df5240
LABEL org.opencontainers.image.title="sign-object" \
      org.opencontainers.image.description="CLI to sign and verify Kubescape ApplicationProfile / NetworkNeighborhood / Rules objects (cosign, key-based or keyless)." \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/k8sstormcenter/node-agent"
COPY --from=builder /sign-object /usr/local/bin/sign-object
WORKDIR /work
ENTRYPOINT ["sign-object"]
