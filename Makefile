.PHONY: build test vet lint run accuracy

build:
	go build -o bin/pdn-shield ./cmd/pdn-shield

test:
	go test ./...

vet:
	go vet ./...

lint:
	gofmt -l .

run:
	go run ./cmd/pdn-shield

accuracy:
	go test -v -run TestAccuracy ./internal/pii