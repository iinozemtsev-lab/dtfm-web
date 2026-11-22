.PHONY: all build vet test test-js clean cross

BINARY_DIR := bin
GO_FLAGS := CGO_ENABLED=0

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null)
ifeq ($(strip $(VERSION)),)
VERSION := dev
endif

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
TEST_LDFLAGS := -ldflags="-linkmode=external"
else
TEST_LDFLAGS :=
endif

BUILD_FLAGS := -trimpath -ldflags="-s -w -X 'main.version=$(VERSION)'"
PLATFORMS := darwin/arm64 darwin/amd64 linux/amd64 linux/arm64

all: vet test build

build:
	mkdir -p $(BINARY_DIR)
	$(GO_FLAGS) go build $(BUILD_FLAGS) -o $(BINARY_DIR)/lmdtfy-web ./cmd/lmdtfy-web

vet:
	go vet ./...

cross:
	mkdir -p $(BINARY_DIR)/dist
	@for platform in $(PLATFORMS); do \
		os=$${platform%/*}; \
		arch=$${platform#*/}; \
		echo "Building lmdtfy-web for $${os}-$${arch}..."; \
		GOOS=$${os} GOARCH=$${arch} $(GO_FLAGS) go build $(BUILD_FLAGS) -o $(BINARY_DIR)/dist/lmdtfy-web-$${os}-$${arch} ./cmd/lmdtfy-web || exit 1; \
	done

test-js:
	node --test extension/test/e2ee.test.mjs extension/test/content.test.mjs extension/test/background.test.mjs

test: test-js
	go test -v -race $(TEST_LDFLAGS) ./...

clean:
	rm -rf $(BINARY_DIR) dist artifacts
