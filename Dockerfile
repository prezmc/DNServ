# syntax=docker/dockerfile:1
# The Go stage runs on the machine doing the build and cross-compiles for
# the target (amd64 or arm64), instead of compiling under emulation, which
# was 5-10x slower for the arm64 image. The cache mounts keep Go's module
# and build caches between local builds.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    export GOOS=$TARGETOS GOARCH=$TARGETARCH \
 && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/dnserv ./cmd/dnserv \
 && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/dnsbench ./cmd/dnsbench

# Alpine with Unbound for recursive and tunnel modes. Unbound runs as a
# child of dnserv, as the same unprivileged user, on loopback only.
FROM alpine:3.22 AS runtime
RUN apk upgrade --no-cache \
 && apk add --no-cache unbound dnssec-root ca-certificates tzdata \
 && addgroup -S -g 65532 dnserv && adduser -S -u 65532 -G dnserv -h /data dnserv \
 && mkdir -p /data /etc/dnserv && chown dnserv:dnserv /data
COPY --from=build /out/dnserv /out/dnsbench /usr/local/bin/
COPY dnserv.example.yaml /etc/dnserv/dnserv.example.yaml
ENV DNSERV_CONFIG=/data/dnserv.yaml
VOLUME /data
EXPOSE 53/udp 53/tcp 853/tcp 443/tcp 8080/tcp 8081/tcp
USER dnserv
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD ["/usr/local/bin/dnserv", "-healthcheck", "127.0.0.1:8080"]
ENTRYPOINT ["/usr/local/bin/dnserv"]
