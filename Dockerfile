FROM golang:1.25-alpine AS builder

RUN apk add --no-cache gcc musl-dev sqlite-dev

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 go build -o /arc-relay ./cmd/arc-relay

FROM alpine:3.21

RUN apk add --no-cache ca-certificates sqlite-libs git

COPY --from=builder /arc-relay /usr/local/bin/arc-relay

RUN mkdir -p /data

# Default DB path inside the container - matches the /data volume mount
ENV ARC_RELAY_DB_PATH=/data/arc-relay.db

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/arc-relay"]
