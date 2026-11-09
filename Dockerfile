# syntax=docker/dockerfile:1
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/dnserve ./cmd/dnserve \
 && mkdir -p /out/data

# Step 1b switches this to a small Alpine base with Unbound bundled.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/dnserve /usr/local/bin/dnserve
COPY --from=build --chown=65532:65532 /out/data /data
COPY --chown=65532:65532 dnserve.example.yaml /etc/dnserve/dnserve.example.yaml
ENV DNSERVE_CONFIG=/data/dnserve.yaml
VOLUME /data
EXPOSE 53/udp 53/tcp 8080/tcp
USER nonroot
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD ["/usr/local/bin/dnserve", "-healthcheck", "127.0.0.1:8080"]
ENTRYPOINT ["/usr/local/bin/dnserve"]
