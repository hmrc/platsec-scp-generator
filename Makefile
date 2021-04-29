DOCKER = docker run \
	--interactive \
	--rm \
	--volume "${PWD}:${PWD}" \
	--workdir "${PWD}"

.PHONY: bash go gofmt golangci-lint
bash go gofmt golangci-lint:
	@docker build \
		--tag $@ \
		--build-arg "user_id=$(shell id -u)" \
		--build-arg "group_id=$(shell id -g)" \
		--build-arg "home=${HOME}" \
		--build-arg "workdir=${PWD}" \
		--target $@ . \
		>/dev/null

.PHONY: fmt
fmt: gofmt
	@$(DOCKER) gofmt -l -s -w .

.PHONY: fmt-check
fmt-check: gofmt
	@$(DOCKER) gofmt -l -s -d .

.PHONY: test
test: go bash
	@$(DOCKER) go test -cover .
	@$(DOCKER) bash e2e.test.sh

.PHONY: lint
lint: golangci-lint
	@$(DOCKER) golangci-lint run --fix --issues-exit-code 0

.PHONY: lint-check
lint-check: golangci-lint
	@$(DOCKER) golangci-lint run --color always
