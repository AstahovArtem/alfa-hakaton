.PHONY: build test vet lint run accuracy docker-build deploy k8s-apply load-test compose-up compose-down

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

docker-build:
	docker build --platform $(PLATFORM) -t pdn-shield:$(TAG) .

deploy:
	bash deploy/scripts/build-and-load.sh

k8s-apply:
	kubectl apply -k deploy/k8s

load-test:
	go run ./loadtest -url $(URL) -rps $(RPS) -duration $(DURATION) -system $(SYSTEM) -api-key $(API_KEY)

compose-up:
	docker compose up -d --build

compose-down:
	docker compose down