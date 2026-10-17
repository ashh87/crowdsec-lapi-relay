FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /lapi-relay . && mkdir -p /queue

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /lapi-relay /usr/local/bin/lapi-relay
COPY --from=build --chown=65532:65532 /queue /var/lib/lapi-relay
# Mount the config read-only at /etc/lapi-relay/config.json and a volume for
# the queue. Inside a container the relay must listen on 0.0.0.0, so set
# "allow_public_listen": true and publish the port on a private address only,
# e.g. -p 127.0.0.1:8081:8081 or -p <private-ip>:8081:8081.
VOLUME /var/lib/lapi-relay
USER nonroot
ENTRYPOINT ["/usr/local/bin/lapi-relay", "-c", "/etc/lapi-relay/config.json"]
