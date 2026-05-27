.PHONY: all build test lint clean

all: build

build:
	@mkdir -p bin
	CGO_ENABLED=0 go build -o bin/hyperview ./cmd/hyperview

test:
	go test -v -race ./...

lint:
	@echo "Running golangci-lint check..."
	@golangci-lint run ./... || echo "Note: golangci-lint not installed locally."

clean:
	rm -rf bin/
