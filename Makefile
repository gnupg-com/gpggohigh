# Allow to override the GO compiler version
# e.g. make GO=/usr/lib/go-1.22/bin/go
GO = go

.PHONY: help
help:
	@echo "Targets:"
	@echo "  build:     build the library"
	@echo "  build-all: build the library and all examples"

.PHONY: build
build:
	GOAMD64=v2 \
	$(GO) build -v -trimpath

.PHONY: build-all
build-all: build
	for d in example/*; do \
		if [ -d "$$d" ]; then \
			$(GO) build -v -trimpath ./$$d; \
		fi; \
	done

# EOF