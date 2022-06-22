HASH := $(shell git rev-parse --short HEAD)
COMMIT_DATE := $(shell git show -s --format=%ci ${HASH})
BUILD_DATE := $(shell date '+%Y-%m-%d %H:%M:%S')
VERSION := ${HASH} (${COMMIT_DATE})

BUILDDIR ?= .
SRCDIR ?= .

.PHONY: help
help:
	@echo "make [TARGETS...]"
	@echo
	@echo "This is the maintenance makefile of photon-mgmtd. The following"
	@echo "targets are available:"
	@echo
	@echo "    help:               Print this usage information."
	@echo "    build:              Builds project"
	@echo "    install:            Installs binary, configuration and unit files"
	@echo "    clean:              Cleans the build"

$(BUILDDIR)/:
	mkdir -p "$@"

$(BUILDDIR)/%/:
	mkdir -p "$@"

.PHONY: build
build:
	- mkdir -p bin
	go build -buildmode=pie -ldflags="-w -X 'main.buildVersion=${VERSION}' -X 'main.buildDate=${BUILD_DATE}'" -o bin/photon-mgmtd ./cmd/photon-mgmt
	go build -buildmode=pie -ldflags="-w -X 'main.buildVersion=${VERSION}' -X 'main.buildDate=${BUILD_DATE}'" -o bin/pmctl ./cmd/pmctl
	go build -buildmode=pie -ldflags="-w -X 'main.buildVersion=${VERSION}' -X 'main.buildDate=${BUILD_DATE}'" -o bin/jwtctl ./cmd/jwtctl

.PHONY: install
install:
	- mkdir -p $(DESTDIR)/usr/bin/
	install bin/photon-mgmtd $(DESTDIR)/usr/bin/
	install bin/pmctl $(DESTDIR)/usr/bin/
	install bin/jwtctl $(DESTDIR)/usr/bin/

	- mkdir -p $(DESTDIR)/etc/photon-mgmt
	install -vdm 755 $(DESTDIR)/etc/photon-mgmt
	install -m 755 distribution/photon-mgmt.toml $(DESTDIR)/etc/photon-mgmt

	- mkdir -p $(DESTDIR)/lib/systemd/system/
	install -m 0644 units/photon-mgmtd.service $(DESTDIR)/lib/systemd/system/
	systemctl daemon-reload

PHONY: clean
clean:
	go clean
	rm -rf bin
