.PHONY: run build test test-race vet lint fmt-check proto proto-check standalone docker-build up down logs

run:
	go run .

build:
	go build -o crypto .

test:
	go test ./...

test-race:
	go test -race -count=1 ./...

vet:
	go vet ./...

lint: fmt-check vet
	govulncheck ./...

fmt-check:
	@test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)

proto:
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		proto/crypto/v1/crypto.proto
	@mkdir -p gen/crypto/v1
	@mv proto/crypto/v1/crypto.pb.go proto/crypto/v1/crypto_grpc.pb.go gen/crypto/v1/

proto-check: proto
	@test -z "$$(git status --porcelain -- gen/crypto/v1)" || \
		(git status --short -- gen/crypto/v1 && exit 1)

standalone:
	cd ../common && GOWORK=off go test ./...
	GOWORK=off go test ./...
	GOWORK=off go build ./...

docker-build:
	docker build -t crypto-svc .

up:
	docker compose -f ../../docker-compose.yml up --build -d

down:
	docker compose -f ../../docker-compose.yml down

logs:
	docker compose -f ../../docker-compose.yml logs -f crypto
