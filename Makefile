# Luarocks path for amalg and other tools
LUAROCKS_PATH := $(shell luarocks path --lr-path 2>/dev/null)

# Lua path for local modules (src, vendor)
LUA_PATH_LOCAL := ./?.lua;./?/init.lua;./src/?.lua;./src/?/init.lua;./vendor/?.lua;$(LUAROCKS_PATH)

# Default target
.PHONY: all
all: format lint test build

# Run tests
.PHONY: test
test:
	./run_tests.sh

# Run test matrix
.PHONY: test-matrix
test-matrix:
	./run_tests_matrix.sh

# Run specific test suite for test matrix
.PHONY: test-matrix-%
test-matrix-%:
	./run_tests_matrix.sh $*

# Run specific test suite
.PHONY: test-%
test-%:
	./run_tests.sh $*

# Run benchmarks
.PHONY: bench
bench:
	./run_benchmarks.sh

# Run bench matrix
.PHONY: bench-matrix
bench-matrix:
	./run_benchmarks_matrix.sh

# Run specific bench suite for bench matrix
.PHONY: bench-matrix-%
bench-matrix-%:
	./run_benchmarks_matrix.sh $*

# Run specific benchmark suite
.PHONY: bench-%
bench-%:
	./run_benchmarks.sh $*

build/amalg.cache: src/crypto/init.lua
	@echo "Generating amalgamation cache..."
	@mkdir -p build
	@if command -v amalg.lua >/dev/null 2>&1; then \
		LUA_PATH="$(LUA_PATH_LOCAL)" lua -lamalg src/crypto/init.lua && mv amalg.cache build || exit 1; \
		echo "Generated amalg.cache"; \
	else \
		echo "Error: amalg not found."; \
		echo "Please install amalg: luarocks install amalg"; \
		echo "Or run: make install-deps"; \
		exit 1; \
	fi

# Build single-file distributions
.PHONY: build
build: build/amalg.cache
	@echo "Building single-file distribution..."
	@if command -v amalg.lua >/dev/null 2>&1; then \
		LUA_PATH="$(LUA_PATH_LOCAL)" amalg.lua -o build/crypto.lua -C ./build/amalg.cache -i "bitn" || exit 1;\
		echo "Built build/crypto.lua (core; bitn excluded, expected on the path)"; \
		LUA_PATH="$(LUA_PATH_LOCAL)" amalg.lua -o build/crypto-portable.lua -C ./build/amalg.cache || exit 1; \
		echo "Built build/crypto-portable.lua (portable; all dependencies bundled)"; \
		VERSION=$$(git describe --exact-match --tags 2>/dev/null || echo "dev"); \
		if [ "$$VERSION" != "dev" ]; then \
			echo "Injecting version $$VERSION..."; \
			sed -i.bak 's/VERSION = "dev"/VERSION = "'$$VERSION'"/' build/crypto.lua && rm build/crypto.lua.bak; \
			sed -i.bak 's/VERSION = "dev"/VERSION = "'$$VERSION'"/' build/crypto-portable.lua && rm build/crypto-portable.lua.bak; \
		fi; \
		echo "Testing version function..."; \
		CORE_VERSION=$$(LUA_PATH="$(LUA_PATH_LOCAL)" lua -e 'local b = require("build.crypto"); print(b.version())' 2>/dev/null || echo "test failed"); \
		PORTABLE_VERSION=$$(LUA_PATH="$(LUA_PATH_LOCAL)" lua -e 'local b = require("build.crypto-portable"); print(b.version())' 2>/dev/null || echo "test failed"); \
		if [ "$$CORE_VERSION" = "$$VERSION" ] && [ "$$PORTABLE_VERSION" = "$$VERSION" ]; then \
			echo "Version correctly set to: $$VERSION (core + portable)"; \
		else \
			echo "Version test failed. Expected: $$VERSION, core: $$CORE_VERSION, portable: $$PORTABLE_VERSION"; \
		fi; \
	else \
		echo "Error: amalg not found."; \
		echo "Please install amalg: luarocks install amalg"; \
		echo "Or run: make install-deps"; \
		exit 1; \
	fi

# Install all development dependencies
.PHONY: install-deps
install-deps:
	@echo "Installing development dependencies..."
	@echo ""
	@echo "=== Installing system tools ==="
	@if command -v brew >/dev/null 2>&1; then \
		echo "Using Homebrew to install tools..."; \
		brew install lua-language-server stylua || true; \
	else \
		echo "Please install the following manually:"; \
		echo "  - lua-language-server: https://github.com/LuaLS/lua-language-server/releases"; \
		echo "  - stylua: https://github.com/JohnnyMorganz/StyLua/releases"; \
		echo "  - luarocks: https://github.com/luarocks/luarocks/wiki/Download"; \
	fi
	@echo ""
	@echo "=== Installing Lua tools ==="
	@if command -v luarocks >/dev/null 2>&1; then \
		echo "Using LuaRocks to install tools..."; \
		luarocks install luacheck || exit 1; \
		luarocks install amalg || exit 1; \
	else \
		echo "luarocks not found. Please install it first."; \
		echo "  macOS: brew install luarocks"; \
		echo "  Linux: apt-get install luarocks"; \
		exit 1; \
	fi

# Format Lua code with stylua
.PHONY: format
format:
	@if command -v stylua >/dev/null 2>&1; then \
		echo "Running stylua..."; \
		stylua --indent-type Spaces --column-width 120 --line-endings Unix \
			--indent-width 2 --quote-style AutoPreferDouble \
			src/ 2>/dev/null; \
	else \
		echo "stylua not found. Install with: make install-deps"; \
		exit 1; \
	fi

# Check Lua formatting
.PHONY: format-check
format-check:
	@if command -v stylua >/dev/null 2>&1; then \
		echo "Running stylua check..."; \
		stylua --check --indent-type Spaces --column-width 120 --line-endings Unix \
			--indent-width 2 --quote-style AutoPreferDouble \
			src/; \
	else \
		echo "stylua not found. Install with: make install-deps"; \
		exit 1; \
	fi

# Lint the code with luacheck
.PHONY: lint
lint:
	@if command -v luacheck >/dev/null 2>&1; then \
		echo "Running luacheck..."; \
		luacheck src/; \
	else \
		echo "luacheck not found. Install with: make install-deps"; \
		exit 1; \
	fi

# Type-check annotations with the Lua language server
#
# `install-deps` already installs lua-language-server, but nothing ran it, so
# the LuaCATS annotations were only checked by whoever happened to have the
# server wired into their editor. It catches a different class of problem than
# luacheck -- duplicate or undefined `@alias`, return counts that disagree with
# `@return`, fields missing from a `@class` -- so it is a separate target.
#
# Part of `check`, so CI enforces it. The type-narrowing and
# deliberate-bad-argument findings that held it out are resolved: the narrowing
# ones were real defects, and the bad-argument ones are negative tests carrying
# a scoped `@diagnostic` bypass.
#
# Checks the whole repo, not just src/: an editor's workspace is the repo, and
# @alias resolves workspace-wide, so a narrower scope gives different findings
# rather than fewer. --configpath pins the config, because .luarc.json is
# personal editor preference and the count moves with it.
.PHONY: typecheck
typecheck:
	@if command -v lua-language-server >/dev/null 2>&1; then \
		echo "Running lua-language-server $$(lua-language-server --version)..."; \
		lua-language-server --check "$(CURDIR)" --checklevel=Warning \
			--configpath="$(CURDIR)/.luarc-typecheck.json" --logpath="$(CURDIR)/build/luals"; \
	else \
		echo "lua-language-server not found. Install with: make install-deps"; \
		exit 1; \
	fi

.PHONY: check
check: format-check lint typecheck
	@echo "Code quality checks complete."

# Clean generated files
.PHONY: clean
clean:
	rm -rf build/

# Help
.PHONY: help
help:
	@echo "Lua Crypto Library - Makefile targets"
	@echo ""
	@echo "Testing:"
	@echo "  make test               - Run all tests"
	@echo "  make test-<name>        - Run specific test (e.g., make test-sha512)"
	@echo "  make test-matrix        - Run tests across all Lua versions"
	@echo "  make test-matrix-<name> - Run specific test across all Lua versions"
	@echo ""
	@echo "Benchmarking:"
	@echo "  make bench               - Run all benchmarks"
	@echo "  make bench-<name>        - Run specific benchmark (e.g., make bench-sha512)"
	@echo "  make bench-matrix        - Run benchmarks across all Lua versions"
	@echo "  make bench-matrix-<name> - Run specific benchmark across all Lua versions"
	@echo ""
	@echo "Building:"
	@echo "  make build              - Build single-file distribution"
	@echo ""
	@echo "Code Quality:"
	@echo "  make check              - Run format-check and lint"
	@echo "  make format             - Format code with stylua"
	@echo "  make format-check       - Check code formatting"
	@echo "  make lint               - Lint code with luacheck"
	@echo "  make typecheck          - Check annotations with lua-language-server"
	@echo ""
	@echo "Setup:"
	@echo "  make install-deps       - Install development dependencies"
	@echo "  make clean              - Remove generated files"
	@echo ""
	@echo "  make help               - Show this help"
