.PHONY: run build test vet proto docker-build up down logs

run:
	go run .

build:
	go build -o crypto .

test:
	go test ./...

vet:
	go vet ./...

proto:
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		proto/crypto/v1/crypto.proto
	@mkdir -p gen/crypto/v1
	@mv proto/crypto/v1/crypto.pb.go proto/crypto/v1/crypto_grpc.pb.go gen/crypto/v1/

docker-build:
	docker build -t crypto-svc .

up:
	docker compose -f ../../docker-compose.yml up --build -d

down:
	docker compose -f ../../docker-compose.yml down

logs:
	docker compose -f ../../docker-compose.yml logs -f crypto