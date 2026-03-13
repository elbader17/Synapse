FROM golang:1.21-alpine AS builder

# Install dependencies
RUN apk add --no-cache git make

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/server ./cmd/api

# Production image
FROM alpine:3.19

RUN apk --no-cache add ca-certificates

WORKDIR /app

COPY --from=builder /app/server .
COPY --from=builder /app/internal/infrastructure/database/migrations ./migrations

EXPOSE 8080

CMD ["./server"]