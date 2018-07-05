# Multi Stage Build

# Stage 1: create executable
FROM golang as buildImage

WORKDIR /go/src/github.com/FiloSottile/mkcert

COPY . /go/src/github.com/FiloSottile/mkcert

RUN CGO_ENABLED=0 go build


# Stage 2: create release image

FROM scratch as releaseImage

COPY --from=buildImage /go/src/github.com/FiloSottile/mkcert/mkcert ./mkcert

VOLUME /root/.local/share/mkcert

ENTRYPOINT [ "/mkcert" ]
