# syntax=docker/dockerfile:1
FROM golang:1.24-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/ ./cmd/... \
 && mkdir -p /out/certs

# One small image, four binaries: ztgw (gateway), devca, mockidp, upstream (demo).
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/ztgw /out/devca /out/mockidp /out/upstream /usr/local/bin/
COPY --from=build --chown=65532:65532 /out/certs /certs
USER nonroot:nonroot
EXPOSE 8080 9090
ENTRYPOINT ["/usr/local/bin/ztgw"]
CMD ["-config", "/etc/ztg/config.yaml"]
