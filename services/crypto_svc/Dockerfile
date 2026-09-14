FROM golang:1.27-alpine AS builder
WORKDIR /app
COPY go.work ./
COPY common/ ./common/
COPY crypto_svc/ ./crypto_svc/
WORKDIR /app/crypto_svc
RUN go mod download
RUN go build -o /crypto .

FROM alpine:3.20
WORKDIR /app
COPY --from=builder /crypto .
COPY --from=builder /app/crypto_svc/docker-entrypoint.sh .
RUN chmod +x docker-entrypoint.sh
EXPOSE 8001 50051
ENTRYPOINT ["./docker-entrypoint.sh"]
