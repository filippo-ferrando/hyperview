# hyperview build. The eBPF object is generated with bpf2go and committed,
# so building only needs Go; `make bpf` (clang + libbpf headers) is needed
# only after changing internal/bpf/src.

GO      ?= go
NFPM    ?= $(GO) run github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.47.0
ARCHES  ?= amd64 arm64
FORMATS ?= deb rpm archlinux apk

# Version from the nearest v* tag; untagged trees get 0.0.0-dev+<commit>.
VERSION ?= $(shell v=$$(git describe --tags --match 'v*' 2>/dev/null | sed 's/^v//'); \
	if [ -n "$$v" ]; then echo "$$v"; \
	else echo "0.0.0-dev+$$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"; fi)
LDFLAGS := -s -w -X main.version=$(VERSION)

PREFIX  ?= /usr
DESTDIR ?=

.PHONY: all build build-all bpf check-bpf test vet lint package install clean

all: build

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/hyperview ./cmd/hyperview

# Static binaries for every target architecture: bin/hyperview-<arch>.
build-all:
	@for a in $(ARCHES); do \
		echo "build linux/$$a"; \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$a $(GO) build -trimpath -ldflags "$(LDFLAGS)" \
			-o bin/hyperview-$$a ./cmd/hyperview || exit 1; \
	done

# Regenerate the eBPF object and Go bindings (one little-endian object
# serves both amd64 and arm64).
bpf:
	$(GO) generate ./internal/bpf

# Fails when the committed eBPF object is out of date with its source.
check-bpf: bpf
	git diff --exit-code -- internal/bpf

test:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...
	@test -z "$$(gofmt -l .)" || { echo "gofmt needed:"; gofmt -l .; exit 1; }

lint: vet
	@command -v golangci-lint >/dev/null && golangci-lint run ./... || echo "golangci-lint not installed, ran go vet only"

# deb, rpm, Arch and Alpine packages for every architecture in dist/.
package: build-all
	@mkdir -p dist bin/stage
	@for a in $(ARCHES); do \
		cp bin/hyperview-$$a bin/stage/hyperview; \
		for f in $(FORMATS); do \
			ARCH=$$a VERSION=$(VERSION) $(NFPM) package --config packaging/nfpm.yaml \
				--packager $$f --target dist/ || exit 1; \
		done; \
	done

install: build
	install -Dm755 bin/hyperview $(DESTDIR)$(PREFIX)/bin/hyperview
	install -Dm644 packaging/hyperview.service $(DESTDIR)$(PREFIX)/lib/systemd/system/hyperview.service
	@if [ ! -e $(DESTDIR)/etc/hyperview/config.toml ]; then \
		install -Dm644 packaging/config.toml $(DESTDIR)/etc/hyperview/config.toml; fi

clean:
	rm -rf bin/ dist/
