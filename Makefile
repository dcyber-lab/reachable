.PHONY: build test lint e2e

build:
	go build -o reachable .

test:
	go vet ./...
	go test ./...

lint:
	shellcheck -s bash -S warning internal/probe/scripts/*.sh
	shellcheck -S warning test/e2e/*.sh

# Needs root: builds network namespaces. See test/e2e/e2e.sh.
e2e: build
	sudo REACHABLE=$(CURDIR)/reachable test/e2e/e2e.sh
