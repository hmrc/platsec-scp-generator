DOCKER_RUN = docker run --interactive -rm platsecscpgenerator:local

format:
	go fmt ./scp

build:
	go build -o	awsscp main.go

test:
	go test -cover -v ./scp
