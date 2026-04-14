.PHONY: build install uninstall test demo clean

# Build the binary
build:
	go build -o agentpay .

# Build + install as Claude Code plugin (one command)
install: build
	./agentpay install

# Remove from Claude Code
uninstall:
	./agentpay uninstall

# Run tests with race detector
test:
	go test -race -count=1 ./...

# Run the demo
demo: build
	./agentpay demo

# Clean build artifacts
clean:
	rm -f agentpay
