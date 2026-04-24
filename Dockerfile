FROM golang:1.22-alpine AS builder

RUN apk add --no-cache gcc musl-dev

WORKDIR /src
COPY go.mod ./
COPY cmd/ cmd/
COPY internal/ internal/

RUN go build -o /stash-mullvad-proxy ./cmd/server

# ---

FROM alpine:3.20

RUN apk add --no-cache \
    wireguard-tools \
    iproute2 \
    iptables

COPY --from=builder /stash-mullvad-proxy /usr/local/bin/stash-mullvad-proxy

VOLUME /data
EXPOSE 11000 11001

ENTRYPOINT ["stash-mullvad-proxy"]
