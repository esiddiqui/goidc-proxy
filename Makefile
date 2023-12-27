.DEFAULT_GOAL = build 

setup:
ifeq (,$(wildcard bin/golangci-lint))
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s v1.55.1
endif
	go mod tidy
.PHONY: setup

clean:
	rm -f goidc-proxy
.PHONY: clean

build: 
	go build -o goidc-proxy
.PHONY: build

test:
	go test ./... -v 
.PHONY: test

lint:
	./bin/golangci-lint --concurrency 4 run ./...
.PHONY: lint

all: clean lint build test 
.PHONY: all
