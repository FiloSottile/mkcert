# Check mandatory envvars
ifndef GOOS
$(error GOOS is not set)
endif
ifndef GOARCH
$(error GOARCH is not set)
endif

PROJDIR=$(dir $(realpath $(firstword $(MAKEFILE_LIST))))

# change to project dir so we can express all as relative paths
$(shell cd $(PROJDIR))

PKG := github.com/FiloSottile/mkcert

OUT      := mkcert-${GOOS}-${GOARCH}
VERSION  := $(shell git describe --tags)
PKG_LIST := $(shell go list ${PKG}/... | grep -v /vendor/)
GO_FILES := $(shell find . -name '*.go' | grep -v /vendor/)
LD_FLAGS := "-w -X main.Version=$(VERSION)"

all: build

build:
	GO111MODULE=on go build -i -v -o ${OUT} -ldflags $(LD_FLAGS) ${PKG}

test:
	@go test -short ${PKG_LIST}

vet:
	@go vet ${PKG_LIST}

lint:
	@for file in ${GO_FILES} ;  do \
		golint $$file ; \
	done

static: vet lint
	go build -i -v -o ${OUT}-v${VERSION} -tags netgo -ldflags="-extldflags \"-static\" -s ${LD_FLAGS}" ${PKG}

clean:
	-@rm ${OUT}

.PHONY: build static vet lint
