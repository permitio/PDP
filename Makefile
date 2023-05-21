.PHONY: help build prepare

.DEFAULT_GOAL := help

# DOCKER TASKS
# Build the container
build: ## Build the container
	@docker build -t permitio/pdp-v2 .

build-local: ## Build the container
	@docker build -t permitio/pdp-v2:local .

prepare:
ifndef VERSION
	$(error You must set the VERSION variable to build a release image)
endif

	echo $(VERSION) >permit_pdp_version
	./build_opal_bundle.sh

build-release-prod: prepare
	@docker buildx build --platform linux/arm64,linux/amd64 -t permitio/pdp-v2:$(VERSION) --push .

build-release-local-amd: prepare
	@docker buildx build --platform linux/amd64 -t permitio/pdp-v2:$(VERSION) . --load

build-release-local-arm: prepare
	@docker buildx build --platform linux/arm64 -t permitio/pdp-v2:$(VERSION) . --load

build-release-local: prepare
	@docker build -t permitio/pdp-v2:$(VERSION) .

run: ## Run the container locally
	@docker run -it \
		-e "OPAL_SERVER_URL=http://host.docker.internal:7002" \
		-e "PDP_CONTROL_PLANE=http://host.docker.internal:8000" \
		-e "PDP_API_KEY=$(DEV_MODE_CLIENT_TOKEN)" \
		-p 7000:7000 \
		-p 8181:8181 \
		permitio/pdp

run-against-prod: ## Run the container against prod
	@docker run -it \
    -e "PDP_PRINT_CONFIG_ON_STARTUP=true" \
		-e "PDP_API_KEY=$(AUTPDP_PROD_CLIENT_TOKEN)" \
		-e "OPAL_CLIENT_TOKEN=$(OPAL_PROD_CLIENT_TOKEN)" \
		-p 7000:7000 \
		-p 8181:8181 \
		permitio/pdp
