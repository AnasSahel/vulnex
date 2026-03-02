BINARY   := vulnex
MODULE   := github.com/trustin-tech/vulnex
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE     ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS  := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

.PHONY: build test lint install release clean vet

## build: Compile the binary
build:
	CGO_ENABLED=0 go build -ldflags '$(LDFLAGS)' -o $(BINARY) .

## test: Run all tests
test:
	go test -race -count=1 ./...

## lint: Run golangci-lint
lint:
	golangci-lint run ./...

## vet: Run go vet
vet:
	go vet ./...

## install: Install the binary to $GOPATH/bin
install:
	go install -ldflags '$(LDFLAGS)' .

## release: Create a release using GoReleaser (snapshot, no publish)
release:
	goreleaser release --snapshot --clean

## clean: Remove build artifacts
clean:
	rm -f $(BINARY)
	rm -rf dist/
