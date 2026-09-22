.PHONY: build test vet lint run accuracy docker-build deploy k8s-apply load-test compose-up compose-down platform-bootstrap platform-render zip

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

# Bootstrap the whole platform stand (k3s, cert-manager, monitoring, headlamp).
# Requires DOMAIN, ACME_EMAIL, GRAFANA_ADMIN_PASSWORD; optional REMOTE=root@ip.
platform-bootstrap:
	bash deploy/platform/bootstrap.sh

# Render *.tpl.yaml templates into /tmp for inspection (no cluster changes).
platform-render:
	DOMAIN=$${DOMAIN:-alfa-hakaton-prod.ru} \
	ACME_EMAIL=$${ACME_EMAIL:-admin@example.com} \
	SERVER_IP=$${SERVER_IP:-127.0.0.1} \
	GRAFANA_ADMIN_PASSWORD=$${GRAFANA_ADMIN_PASSWORD:-render-only} \
	bash deploy/platform/bootstrap.sh --dry-run

# Package tracked sources into a zip for submission. Excludes docs binaries.
zip:
	git ls-files | grep -vE '^docs/.*\.(pdf|txt)$$' | zip pdn-shield-src.zip -@