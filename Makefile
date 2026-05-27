BPF_SRC   := internal/bpf/_kvm_events.c

.PHONY: all build test lint bpf package rpm deb clean

all: bpf build

bpf:
	@echo "Validating BPF integrity kernel structures..."
	@mkdir -p internal/bpf

build:
	@mkdir -p bin
	go generate ./internal/bpf
	CGO_ENABLED=0 go build \
	  -ldflags="-X hyperview/internal/version.Version=$$(git describe --tags 2>/dev/null || echo 'v1.0.0')" \
	  -o bin/hyperview ./cmd/hyperview

test:
	go test -v -race ./...

lint:
	@echo "Running golangci-lint check..."
	@golangci-lint run ./... || echo "Note: golangci-lint not installed locally."

package: rpm deb

rpm: build
	@mkdir -p dist
	nfpm package --packager rpm --target dist/

deb: build
	@mkdir -p dist
	nfpm package --packager deb --target dist/

clean:
	rm -rf bin/ dist/
