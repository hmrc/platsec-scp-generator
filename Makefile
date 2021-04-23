DOCKER_RUN = docker run \
	--interactive \
	--rm \
	--volume "${PWD}:${PWD}" \
	--workdir "${PWD}" \
	platsecscpgenerator:local

GO_LINT = docker run\
 		--rm \
		--volume "${PWD}:${PWD}" \
		--workdir "${PWD}" \
		golangci/golangci-lint:v1.39.0 golangci-lint

.PHONY: build
build:
	@docker build \
		--build-arg PWD \
		--tag platsecscpgenerator:local \
		. > /dev/null

.PHONY: fmt
fmt: build
	@$(DOCKER_RUN) gofmt -l -s -w .

.PHONY: fmt-check
fmt-check: build
	@$(DOCKER_RUN) gofmt -l -s -d .

.PHONY: test
test: build
	@$(DOCKER_RUN) go test -cover -v .

.PHONY: lint-fix
lint-fix:
	@$(GO_LINT) run --fix --issues-exit-code 0

.PHONY: lint-check
lint-check:
	@$(GO_LINT) run
