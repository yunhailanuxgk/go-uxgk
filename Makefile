# This Makefile is meant to be used by people that do not usually work
# with Go source code. If you know what GOPATH is then you probably
# don't need to bother with make.

.PHONY: uxgk android ios uxgk-cross swarm evm all test clean
.PHONY: uxgk-linux uxgk-linux-386 uxgk-linux-amd64 uxgk-linux-mips64 uxgk-linux-mips64le
.PHONY: uxgk-linux-arm uxgk-linux-arm-5 uxgk-linux-arm-6 uxgk-linux-arm-7 uxgk-linux-arm64
.PHONY: uxgk-darwin uxgk-darwin-386 uxgk-darwin-amd64
.PHONY: uxgk-windows uxgk-windows-386 uxgk-windows-amd64

GOBIN = $(shell pwd)/build/bin
GO ?= latest

uxgk:
	build/env.sh go run build/ci.go install ./cmd/uxgk
	@echo "Done building."
	@echo "Run \"$(GOBIN)/uxgk\" to launch uxgk."

swarm:
	build/env.sh go run build/ci.go install ./cmd/swarm
	@echo "Done building."
	@echo "Run \"$(GOBIN)/swarm\" to launch swarm."

all:
	build/env.sh go run build/ci.go install

android:
	build/env.sh go run build/ci.go aar --local
	@echo "Done building."
	@echo "Import \"$(GOBIN)/uxgk.aar\" to use the library."

ios:
	build/env.sh go run build/ci.go xcode --local
	@echo "Done building."
	@echo "Import \"$(GOBIN)/Smc.framework\" to use the library."

test: all
	build/env.sh go run build/ci.go test

clean:
	rm -fr build/_workspace/pkg/ $(GOBIN)/*

# The devtools target installs tools required for 'go generate'.
# You need to put $GOBIN (or $GOPATH/bin) in your PATH to use 'go generate'.

devtools:
	env GOBIN= go get -u golang.org/x/tools/cmd/stringer
	env GOBIN= go get -u github.com/jteeuwen/go-bindata/go-bindata
	env GOBIN= go get -u github.com/fjl/gencodec
	env GOBIN= go install ./cmd/abigen

# Cross Compilation Targets (xgo)

uxgk-cross: uxgk-linux uxgk-darwin uxgk-windows uxgk-android uxgk-ios
	@echo "Full cross compilation done:"
	@ls -ld $(GOBIN)/uxgk-*

uxgk-linux: uxgk-linux-386 uxgk-linux-amd64 uxgk-linux-arm uxgk-linux-mips64 uxgk-linux-mips64le
	@echo "Linux cross compilation done:"
	@ls -ld $(GOBIN)/uxgk-linux-*

uxgk-linux-386:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/386 -v ./cmd/uxgk
	@echo "Linux 386 cross compilation done:"
	@ls -ld $(GOBIN)/uxgk-linux-* | grep 386

uxgk-linux-amd64:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/amd64 -v ./cmd/uxgk
	@echo "Linux amd64 cross compilation done:"
	@ls -ld $(GOBIN)/uxgk-linux-* | grep amd64

uxgk-linux-arm: uxgk-linux-arm-5 uxgk-linux-arm-6 uxgk-linux-arm-7 uxgk-linux-arm64
	@echo "Linux ARM cross compilation done:"
	@ls -ld $(GOBIN)/uxgk-linux-* | grep arm

uxgk-linux-arm-5:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/arm-5 -v ./cmd/uxgk
	@echo "Linux ARMv5 cross compilation done:"
	@ls -ld $(GOBIN)/uxgk-linux-* | grep arm-5

uxgk-linux-arm-6:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/arm-6 -v ./cmd/uxgk
	@echo "Linux ARMv6 cross compilation done:"
	@ls -ld $(GOBIN)/uxgk-linux-* | grep arm-6

uxgk-linux-arm-7:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/arm-7 -v ./cmd/uxgk
	@echo "Linux ARMv7 cross compilation done:"
	@ls -ld $(GOBIN)/uxgk-linux-* | grep arm-7

uxgk-linux-arm64:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/arm64 -v ./cmd/uxgk
	@echo "Linux ARM64 cross compilation done:"
	@ls -ld $(GOBIN)/uxgk-linux-* | grep arm64

uxgk-linux-mips:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/mips --ldflags '-extldflags "-static"' -v ./cmd/uxgk
	@echo "Linux MIPS cross compilation done:"
	@ls -ld $(GOBIN)/uxgk-linux-* | grep mips

uxgk-linux-mipsle:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/mipsle --ldflags '-extldflags "-static"' -v ./cmd/uxgk
	@echo "Linux MIPSle cross compilation done:"
	@ls -ld $(GOBIN)/uxgk-linux-* | grep mipsle

uxgk-linux-mips64:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/mips64 --ldflags '-extldflags "-static"' -v ./cmd/uxgk
	@echo "Linux MIPS64 cross compilation done:"
	@ls -ld $(GOBIN)/uxgk-linux-* | grep mips64

uxgk-linux-mips64le:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/mips64le --ldflags '-extldflags "-static"' -v ./cmd/uxgk
	@echo "Linux MIPS64le cross compilation done:"
	@ls -ld $(GOBIN)/uxgk-linux-* | grep mips64le

uxgk-darwin: uxgk-darwin-386 uxgk-darwin-amd64
	@echo "Darwin cross compilation done:"
	@ls -ld $(GOBIN)/uxgk-darwin-*

uxgk-darwin-386:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=darwin/386 -v ./cmd/uxgk
	@echo "Darwin 386 cross compilation done:"
	@ls -ld $(GOBIN)/uxgk-darwin-* | grep 386

uxgk-darwin-amd64:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=darwin/amd64 -v ./cmd/uxgk
	@echo "Darwin amd64 cross compilation done:"
	@ls -ld $(GOBIN)/uxgk-darwin-* | grep amd64

uxgk-windows: uxgk-windows-386 uxgk-windows-amd64
	@echo "Windows cross compilation done:"
	@ls -ld $(GOBIN)/uxgk-windows-*

uxgk-windows-386:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=windows/386 -v ./cmd/uxgk
	@echo "Windows 386 cross compilation done:"
	@ls -ld $(GOBIN)/uxgk-windows-* | grep 386

uxgk-windows-amd64:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=windows/amd64 -v ./cmd/uxgk
	@echo "Windows amd64 cross compilation done:"
	@ls -ld $(GOBIN)/uxgk-windows-* | grep amd64
