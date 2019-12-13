FROM golang:1.13-alpine AS builder

RUN apk add --no-cache make

COPY .  /go/src/github.com/FiloSottile/mkcert
WORKDIR /go/src/github.com/FiloSottile/mkcert

RUN cd /go/src/github.com/FiloSottile/mkcert \
	&& go build -v

FROM alpine:3.10 AS runtime

# Install tini to /usr/local/sbin
ADD https://github.com/krallin/tini/releases/download/v0.18.0/tini-muslc-amd64 /usr/local/sbin/tini

# Install runtime dependencies & create runtime user
RUN apk --no-cache --no-progress add ca-certificates git libssh2 openssl \
 && chmod +x /usr/local/sbin/tini && mkdir -p /opt \
 && adduser -D mkcert -h /opt/mkcert -s /bin/sh \
 && su mkcert -c 'cd /opt/mkcert; mkdir -p bin config data'

# Switch to user context
USER mkcert
WORKDIR /opt/mkcert/data

# Copy mkcert binary to /opt/mkcert/bin
COPY --from=builder /go/src/github.com/FiloSottile/mkcert/mkcert /opt/mkcert/bin/mkcert

ENV PATH $PATH:/opt/mkcert/bin

# Container configuration
VOLUME ["/opt/mkcert/data"]
ENTRYPOINT ["tini", "-g", "--", "/opt/mkcert/bin/mkcert"]
