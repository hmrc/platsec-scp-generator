DOCKER_RUN = docker run \
	--interactive \
	--rm \
	--volume "${PWD}:${PWD}" \
	--workdir "${PWD}" \
	platsecscpgenerator:local

.PHONY: build
build:
	@docker build \
		--build-arg PWD \
		--tag platsecscpgenerator:local \
		. > /dev/null

.PHONY: format
format: build
	@$(DOCKER_RUN) go fmt ./scp

.PHONY: test
test: build
	@$(DOCKER_RUN) go test -cover -v ./scp

.PHONY: lint
lint:
	@docker run\
 		--rm \
		--volume "${PWD}:${PWD}" \
    	--workdir "${PWD}" \
        golangci/golangci-lint:v1.39.0 golangci-lint run
