SPEC_TEST_VERSION = v5.4.0
SPEC_TEST_DIR = spec-tests

ZIG_BUILD_CMD = zig build

ARGS ?=

.PHONY: spec-tests fetch-fixtures

# Download execution-spec-tests fixtures; marker file tracks successful download
$(SPEC_TEST_DIR)/.fixtures-$(SPEC_TEST_VERSION):
	@echo "Downloading execution-spec-tests $(SPEC_TEST_VERSION)..."
	rm -rf $(SPEC_TEST_DIR)/fixtures
	mkdir -p $(SPEC_TEST_DIR)/fixtures
	curl -fL "https://github.com/ethereum/execution-spec-tests/releases/download/$(SPEC_TEST_VERSION)/fixtures_develop.tar.gz" \
		| tar xz --strip-components=1 -C $(SPEC_TEST_DIR)/fixtures/
	touch $@
	@echo "Downloaded execution-spec-tests $(SPEC_TEST_VERSION)"

fetch-fixtures: $(SPEC_TEST_DIR)/.fixtures-$(SPEC_TEST_VERSION)

# Build and run spec tests
spec-tests: $(SPEC_TEST_DIR)/.fixtures-$(SPEC_TEST_VERSION)
	@echo "Building spec-test-runner..."
	@$(ZIG_BUILD_CMD) install
	@echo "Running spec tests..."
	@./zig-out/bin/spec-test-runner --fixtures $(SPEC_TEST_DIR)/fixtures/state_tests $(ARGS)
