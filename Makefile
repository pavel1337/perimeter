.PHONY: generate run lint test build

generate:
	go generate ./ent

run:
	@if [ -f .env ]; then set -a; . ./.env; set +a; fi; \
	go run main.go --targets targets.lst

lint:
	golangci-lint run ./...
	golangci-lint fmt --diff

test:
	go test ./...

build:
	CGO_ENABLED=0 go build -o perimeter .
