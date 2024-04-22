FROM golang:1.21-alpine as builder

WORKDIR /usr/src/app

COPY . ./
RUN go mod download && go mod verify

COPY . .
RUN go build -v -o /usr/local/bin/mkcert ./...

FROM golang:1.21-alpine
COPY --from=builder /usr/local/bin/mkcert /usr/local/bin/mkcert

RUN mkdir /.local && chmod 777 /.local

WORKDIR /tmp/certs

ENTRYPOINT ["/usr/local/bin/mkcert"]
CMD ["--help"]