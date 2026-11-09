# syntax=docker/dockerfile:1
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/dnserve ./cmd/dnserve \
 && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/dnsbench ./cmd/dnsbench

# Alpine with Unbound for recursive and tunnel modes. Unbound runs as a
# child of dnserve, as the same unprivileged user, on loopback only.
FROM alpine:3.22
RUN apk upgrade --no-cache \
 && apk add --no-cache unbound dnssec-root ca-certificates tzdata \
 && addgroup -S -g 65532 dnserve && adduser -S -u 65532 -G dnserve -h /data dnserve \
 && mkdir -p /data /etc/dnserve && chown dnserve:dnserve /data
COPY --from=build /out/dnserve /out/dnsbench /usr/local/bin/
COPY dnserve.example.yaml /etc/dnserve/dnserve.example.yaml
ENV DNSERVE_CONFIG=/data/dnserve.yaml
VOLUME /data
EXPOSE 53/udp 53/tcp 853/tcp 443/tcp 8080/tcp
USER dnserve
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD ["/usr/local/bin/dnserve", "-healthcheck", "127.0.0.1:8080"]
ENTRYPOINT ["/usr/local/bin/dnserve"]
