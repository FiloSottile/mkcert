## build			:	build mkcert executable.
.PHONY: build
build:
	@go build -ldflags="-s -w" .

## cross-build		:	cross-build mkcert.
.PHONY: cross-build
cross-build: cross-deps
	@gox -os="linux darwin windows" -arch="amd64" -output="./dist/{{.Dir}}_{{.OS}}_{{.Arch}}" .

## cross-deps		:	download and install gox, a simple Golang cross compilation tool.
.PHONY: cross-deps
cross-deps:
	@go get github.com/mitchellh/gox

## docker-build		:	build docker container.
.PHONY: docker-build
docker-build:
	@docker build -t mkcert:alpine3.10-go1.13 .

## docker-run		:	run docker container.
.PHONY: docker-run
docker-run:
	@docker run -ti -v $(PWD)/data:/opt/mkcert/data mkcert:alpine3.10-go1.13 $(filter-out $@,$(MAKECMDGOALS))

## docker-demo		:	run docker container with demo certificate.
.PHONY: docker-demo
docker-demo:
	@docker run -ti -v $(PWD)/data:/opt/mkcert/data mkcert example.com "*.example.com" example.test localhost 127.0.0.1 ::1

## help			:	Print commands help.
.PHONY: help
help : Makefile
	@sed -n 's/^##//p' $<

# https://stackoverflow.com/a/6273809/1826109
%:
	@:
