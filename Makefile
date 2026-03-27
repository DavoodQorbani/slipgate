VERSION ?= 1.3.1
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS  = -X github.com/anonvector/slipgate/internal/version.Version=$(VERSION) \
           -X github.com/anonvector/slipgate/internal/version.Commit=$(COMMIT)

.PHONY: build clean test install release

build:
	go build -ldflags "$(LDFLAGS)" -o slipgate .

build-linux:
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o slipgate-linux-amd64 .
	GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o slipgate-linux-arm64 .

clean:
	rm -f slipgate slipgate-linux-*

test:
	go test ./...

install: build
	sudo cp slipgate /usr/local/bin/
	@echo "Installed to /usr/local/bin/slipgate"

release: clean build-linux
	@echo "Built release binaries"
	@ls -la slipgate-linux-*
