# Build stage
FROM golang:1.25-alpine AS builder

# ca-certificates copied into the final image for outbound HTTPS (SSL Labs,
# importer APIs, webhooks).
RUN apk add --no-cache ca-certificates

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Pure-Go build (modernc.org/sqlite, lib/pq) — no CGO, fully static.
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /perimeter .

# Run stage
FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /perimeter /perimeter

EXPOSE 3000
USER 10001:10001
ENTRYPOINT ["/perimeter"]
