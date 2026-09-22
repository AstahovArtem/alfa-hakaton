# syntax=docker/dockerfile:1

# Build stage.
FROM golang:1.26-alpine AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build \
    -trimpath \
    -ldflags="-s -w -X main.version=$VERSION" \
    -o /out/pdn-shield ./cmd/pdn-shield

# Runtime stage.
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /
COPY --from=build /out/pdn-shield /pdn-shield
COPY --from=build /src/configs/config.yaml /etc/pdn-shield/config.yaml

USER nonroot
EXPOSE 8080
ENTRYPOINT ["/pdn-shield"]
CMD ["-config", "/etc/pdn-shield/config.yaml"]