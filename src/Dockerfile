FROM golang:1.24-alpine AS builder

WORKDIR /app
COPY . .
RUN go mod tidy && \
    CGO_ENABLED=0 GOOS=linux go build -o eth-sentry .

FROM alpine:latest
RUN apk --no-cache add ca-certificates tzdata
WORKDIR /root/
COPY --from=builder /app/eth-sentry .
CMD ["./eth-sentry"]
