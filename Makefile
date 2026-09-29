BINARY := warp-masque-proxy
GOFLAGS_BUILD := -ldflags="-s -w"

.PHONY: all build test vet fmt tidy clean run

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
