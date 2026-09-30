.PHONY: help build prepare build-amd64 build-arm64 cargo-run

.DEFAULT_GOAL := help

VERSION ?= next
# build_opal_bundle.sh skips the permit-opa tarball when PDP_VANILLA=true, so the image
# must then build with OPA_BUILD=vanilla (the Dockerfile's default, permit, needs it).
OPA_BUILD ?= $(if $(filter true,$(PDP_VANILLA)),vanilla,permit)

prepare:
ifndef VERSION
	$(error You must set VERSION variable to build local image)
endif

	./build_opal_bundle.sh

run-prepare:
ifndef API_KEY
	$(error You must set API_KEY variable to run pdp locally)
endif
ifndef VERSION
	$(error You must set VERSION variable to run pdp locally)
endif

build-amd64: prepare
	@docker buildx build --platform linux/amd64 -t permitio/pdp-v2:$(VERSION) --build-arg OPA_BUILD=$(OPA_BUILD) . --load

build-arm64: prepare
	@docker buildx build --platform linux/arm64 -t permitio/pdp-v2:$(VERSION) --build-arg OPA_BUILD=$(OPA_BUILD) . --load

build: prepare
	@docker buildx build -t permitio/pdp-v2:$(VERSION) --build-arg OPA_BUILD=$(OPA_BUILD) . --load

build-latest: prepare
	@docker buildx build -t permitio/pdp-v2:latest --build-arg OPA_BUILD=$(OPA_BUILD) . --load

run: run-prepare
	@docker run -it --rm -p 7766:7000 --env PDP_API_KEY=$(API_KEY) --env PDP_DEBUG=true permitio/pdp-v2:$(VERSION)

run-on-background: run-prepare
	@docker run -it --rm -d -p 7766:7000  --env PDP_API_KEY=$(API_KEY) --env PDP_DEBUG=true permitio/pdp-v2:$(VERSION)

cargo-run:
	cargo run --bin pdp-server --package pdp-server -- --port 7766
