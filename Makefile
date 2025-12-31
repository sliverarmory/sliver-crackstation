#
# Makefile for Sliver Crackstation
#

GO ?= go
ARTIFACT_SUFFIX ?= 
ENV =
TAGS = -tags osusergo,netgo

VERSION ?= $(shell git describe --abbrev=0 || echo "v0.0.0")
VERSION_PKG = github.com/sliverarmory/sliver-crackstation/assets
LDFLAGS = -ldflags "-s -w"

#
# Prerequisites 
#
# https://stackoverflow.com/questions/5618615/check-if-a-program-exists-from-a-makefile
EXECUTABLES = $(GO) uname cut
K := $(foreach exec,$(EXECUTABLES),\
        $(if $(shell which $(exec)),some string,$(error "No $(exec) in PATH")))

GO_VERSION = $(shell $(GO) version)
GO_MAJOR_VERSION = $(shell $(GO) version | cut -c 14- | cut -d' ' -f1 | cut -d'.' -f1)
GO_MINOR_VERSION = $(shell $(GO) version | cut -c 14- | cut -d' ' -f1 | cut -d'.' -f2)
MIN_SUPPORTED_GO_MAJOR_VERSION = 1
MIN_SUPPORTED_GO_MINOR_VERSION = 25
GO_VERSION_VALIDATION_ERR_MSG = Golang version is not supported, please update to at least $(MIN_SUPPORTED_GO_MAJOR_VERSION).$(MIN_SUPPORTED_GO_MINOR_VERSION)


#
# Targets
#
.PHONY: default
default: clean
	$(ENV) $(GO) build -mod=vendor -trimpath $(TAGS) $(LDFLAGS) -o sliver-crackstation$(ARTIFACT_SUFFIX) .

.PHONY: macos-amd64
macos: clean validate-go-version
	GOOS=darwin GOARCH=amd64 $(ENV) $(GO) build -mod=vendor -trimpath $(TAGS) $(LDFLAGS) -o sliver-crackstation$(ARTIFACT_SUFFIX) .

.PHONY: macos-arm64
macos-arm64: clean validate-go-version
	GOOS=darwin GOARCH=arm64 $(ENV) $(GO) build -mod=vendor -trimpath $(TAGS) $(LDFLAGS) -o sliver-crackstation$(ARTIFACT_SUFFIX) .

.PHONY: windows
windows: clean validate-go-version
	GOOS=windows GOARCH=amd64 $(ENV) $(GO) build -mod=vendor -trimpath $(TAGS) $(LDFLAGS) -o sliver-crackstation$(ARTIFACT_SUFFIX).exe .

.PHONY: linux
linux: clean validate-go-version
	GOOS=linux GOARCH=amd64 $(ENV) $(GO) build -mod=vendor -trimpath $(TAGS) $(LDFLAGS) -o sliver-crackstation$(ARTIFACT_SUFFIX) .

validate-go-version:
	@if [ $(GO_MAJOR_VERSION) -gt $(MIN_SUPPORTED_GO_MAJOR_VERSION) ]; then \
		exit 0 ;\
	elif [ $(GO_MAJOR_VERSION) -lt $(MIN_SUPPORTED_GO_MAJOR_VERSION) ]; then \
		echo '$(GO_VERSION_VALIDATION_ERR_MSG)';\
		exit 1; \
	elif [ $(GO_MINOR_VERSION) -lt $(MIN_SUPPORTED_GO_MINOR_VERSION) ] ; then \
		echo '$(GO_VERSION_VALIDATION_ERR_MSG)';\
		exit 1; \
	fi


clean-all: clean
	rm -f ./assets/darwin/amd64/*.zip
	rm -f ./assets/darwin/arm64/*.zip
	rm -f ./assets/linux/amd64/*.zip
	rm -f ./assets/windows/amd64/*.zip

clean:
	rm -f sliver-crackstation$(ARTIFACT_SUFFIX)
	rm -f sliver-crackstation$(ARTIFACT_SUFFIX).exe
