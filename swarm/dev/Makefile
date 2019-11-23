.PHONY: build cluster test

default: build

build:
	go build -o bin/swarm    github.com/yunhailanuxgk/go-uxgk/cmd/swarm
	go build -o bin/geth     github.com/yunhailanuxgk/go-uxgk/cmd/geth
	go build -o bin/bootnode github.com/yunhailanuxgk/go-uxgk/cmd/bootnode

cluster: build
	scripts/boot-cluster.sh

test:
	go test -v github.com/yunhailanuxgk/go-uxgk/swarm/...
