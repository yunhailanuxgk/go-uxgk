# This Makefile is meant to be used by people that do not usually work
# with Go source code. If you know what GOPATH is then you probably
# don't need to bother with make.
.PHONY: uxgk

GOBIN = $(shell pwd)/build/bin
GO ?= latest

uxgk:
	build/env.sh go run build/ci.go install ./cmd/uxgk
	@echo "Done building."
	@echo "Run \"$(GOBIN)/uxgk\" to launch uxgk."

lint: ## Run linters.
	build/env.sh go run build/ci.go lint

clean:
	./build/clean_go_build_cache.sh
