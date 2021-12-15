.PHONY: help build

.DEFAULT_GOAL := help

# DOCKER TASKS
# Build the container
build: ## Build the container
	@docker build -t permitio/pdp .

build-local: ## Build the container
	@docker build -t permitio/pdp:local .

run: ## Run the container locally
	@docker run -it \
		-e "OPAL_SERVER_URL=http://host.docker.internal:7002" \
		-e "HORIZON_BACKEND_URL=http://host.docker.internal:8000" \
		-e "HORIZON_CLIENT_TOKEN=$(DEV_MODE_CLIENT_TOKEN)" \
		-p 7000:7000 \
		-p 8181:8181 \
		permitio/pdp

run-against-prod: ## Run the container against prod
	@docker run -it \
    -e "HORIZON_PRINT_CONFIG_ON_STARTUP=true" \
		-e "HORIZON_CLIENT_TOKEN=$(AUTHORIZON_PROD_CLIENT_TOKEN)" \
		-e "OPAL_CLIENT_TOKEN=$(OPAL_PROD_CLIENT_TOKEN)" \
		-p 7000:7000 \
		-p 8181:8181 \
		permitio/pdp
