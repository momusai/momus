.PHONY: build test lint fmt install demo clean

BIN := bin/momus

build:
	@mkdir -p bin
	go build -ldflags "-s -w -X main.version=$$(git describe --tags --always 2>/dev/null || echo dev)" -o $(BIN) ./cmd/momus

install:
	go install ./cmd/momus

test:
	go test ./...

lint:
	go vet ./...
	@which golangci-lint > /dev/null && golangci-lint run || echo "install golangci-lint for full linting"

fmt:
	gofmt -w .

demo: build
	@echo "==> starting vulnerable echo target in background"
	@go run ./examples/vulnerable-echo &
	@sleep 1
	@echo "==> scanning target"
	@./$(BIN) scan http://localhost:8000 --pack packs/core
	@pkill -f "vulnerable-echo" 2>/dev/null || true

clean:
	rm -rf bin dist coverage.out
