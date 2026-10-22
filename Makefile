# ZRO build helpers. `make help` lists the targets.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
PKG      = github.com/cubis/zro/pkg/version
LDFLAGS  = -s -w -X $(PKG).Version=$(VERSION) -X $(PKG).Commit=$(COMMIT) -X $(PKG).Date=$(DATE)

.PHONY: help build build-sqlite test race vet fmt fmt-check vuln proto docker clean

help: ## Show this help
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-10s %s\n", $$1, $$2}'

build: ## Build the static bin/zro (what the image ships; PostgreSQL only, no SQLite)
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/zro ./cmd/zro

build-sqlite: ## Build bin/zro-sqlite with cgo, for local trials on SQLite (the static build needs PostgreSQL)
	CGO_ENABLED=1 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/zro-sqlite ./cmd/zro

test: ## Run the tests
	go test ./...

race: ## Run the tests with the race detector (what CI runs)
	go test -race -count=1 ./...

vet: ## go vet
	go vet ./...

fmt: ## Format the code
	gofmt -w cmd pkg test api

fmt-check: ## Fail if any file is not gofmt-clean
	@test -z "$$(gofmt -l cmd pkg test api)" || (gofmt -l cmd pkg test api; echo "run 'make fmt'"; exit 1)

vuln: ## Scan dependencies and code for known vulnerabilities
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

proto: ## Regenerate the gRPC stubs (needs protoc, protoc-gen-go, protoc-gen-go-grpc)
	cd api/proto/v1 && protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative control.proto

docker: ## Build the container image
	docker build --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) --build-arg DATE=$(DATE) -t ghcr.io/sombochea/zro:$(VERSION) .

clean: ## Remove build output
	rm -rf bin
