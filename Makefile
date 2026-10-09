BINARY  := envguardian
PKG     := github.com/YehiaGewily/envguardian
CMD     := ./cmd/envguardian

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X main.version=$(VERSION) \
	-X main.commit=$(COMMIT) \
	-X main.date=$(DATE)

.PHONY: build test test-diff lint fuzz snapshot clean

## build: compile the CLI with version metadata
build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) $(CMD)

## test: run the test suite with race detector
test:
	go test -race ./...

## test-diff: run the differential conformance test against joho/godotenv
test-diff:
	go test -tags differential -run TestDifferentialGodotenv ./internal/dotenv

## lint: run golangci-lint (install: https://golangci-lint.run)
lint:
	golangci-lint run ./...

## fuzz: run the dotenv parser for 60s and every other fuzz target for 20s
fuzz:
	go test -run '^$$' -fuzz '^FuzzParse$$' -fuzztime 60s ./internal/dotenv
	go test -run '^$$' -fuzz '^FuzzParse$$' -fuzztime 20s ./internal/config
	go test -run '^$$' -fuzz '^FuzzParseRecipients$$' -fuzztime 20s ./internal/keys
	go test -run '^$$' -fuzz '^FuzzParseLock$$' -fuzztime 20s ./internal/crypt
	go test -run '^$$' -fuzz '^FuzzParse$$' -fuzztime 20s ./internal/rotation
	go test -run '^$$' -fuzz '^FuzzMergeDotenv$$' -fuzztime 20s ./internal/gitint

## snapshot: build unpublished release artifacts locally
snapshot:
	goreleaser release --snapshot --clean

## clean: remove build artifacts
clean:
	rm -f $(BINARY)
	go clean
