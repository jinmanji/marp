BINARY := marp
GOFLAGS_BUILD := -ldflags="-s -w"

.PHONY: all build test vet fmt tidy clean run docker alpine-image

all: fmt vet test build

build:
	CGO_ENABLED=0 go build $(GOFLAGS_BUILD) -o $(BINARY) .

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

tidy:
	go mod tidy

clean:
	rm -f $(BINARY)

run: build
	./$(BINARY)

VERSION ?= dev

# 构建 Alpine 镜像（Alpine/musl）
docker alpine-image:
	docker build -f Dockerfile.alpine -t $(BINARY):alpine --build-arg VERSION=$(VERSION) .
