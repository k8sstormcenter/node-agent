FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN git config --global --add safe.directory /src && \
    CGO_ENABLED=0 go build -o /sign-object ./cmd/sign-object

FROM alpine:3.21
COPY --from=builder /sign-object /usr/local/bin/sign-object
WORKDIR /work
ENTRYPOINT ["sign-object"]
