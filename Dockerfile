FROM golang:1.16
ARG PWD
WORKDIR $PWD
COPY go.mod go.sum $PWD/
RUN go version && \
    go mod download

