FROM golang:1.16
WORKDIR /github.com/platsec-scp-generator/
COPY ./platsec-scp-generator/* ./
RUN go build -o awsscp main.go


