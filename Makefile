GO ?= go
VERSION ?= dev
LDFLAGS = -s -w -X main.version=$(VERSION)

.PHONY: build check release clean
build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o hostdesk ./cmd/hostdesk

check:
	$(GO) vet ./...
	$(GO) test ./...
	sh -n install.sh

release:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o dist/hostdesk-linux-amd64 ./cmd/hostdesk
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o dist/hostdesk-linux-arm64 ./cmd/hostdesk
	cp THIRD_PARTY_NOTICES.txt dist/THIRD_PARTY_NOTICES.txt
	cd dist && sha256sum hostdesk-linux-amd64 hostdesk-linux-arm64 THIRD_PARTY_NOTICES.txt > SHA256SUMS

clean:
	rm -f hostdesk
	rm -rf dist
