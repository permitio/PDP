.PHONY: help build prepare

.DEFAULT_GOAL := help

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
	@docker buildx build --platform linux/amd64 -t permitio/pdp-v2:$(VERSION) . --load

build-arm64: prepare
	@docker buildx build --build-arg ALLOW_MISSING_FACTSTORE=false --platform linux/arm64 -t permitio/pdp-v2:$(VERSION) . --load

run: run-prepare
	@docker run -p 7766:7000 --env PDP_API_KEY=$(API_KEY) --env PDP_DEBUG=true permitio/pdp-v2:$(VERSION)

run-on-background: run-prepare
	@docker run -d -p 7766:7000 --env PDP_API_KEY=$(API_KEY) --env PDP_DEBUG=true permitio/pdp-v2:$(VERSION)
