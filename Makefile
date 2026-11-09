# Optional convenience wrapper. The portable entry point is `go run build.go`,
# which works on Windows without make. Use this only if you have make.
#
#   make            -> go run build.go
#   make release    -> go run build.go release
#   make test       -> go run build.go test
#   make clean      -> go run build.go clean
#   make windows    -> go run build.go -targets=windows

VERSION ?=

.PHONY: all build release test vet fmt clean windows linux version

all: build

build:
	go run build.go $(if $(VERSION),-version=$(VERSION),)

windows:
	go run build.go -targets=windows $(if $(VERSION),-version=$(VERSION),)

linux:
	go run build.go -targets=linux,linux-arm64 $(if $(VERSION),-version=$(VERSION),)

release:
	go run build.go release $(if $(VERSION),-version=$(VERSION),)

test:
	go run build.go test

vet:
	go run build.go vet

fmt:
	go run build.go fmt

clean:
	go run build.go clean

version:
	go run build.go version