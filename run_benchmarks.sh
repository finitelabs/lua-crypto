#!/bin/bash

# lua-crypto Benchmark Runner
#
# Usage: ./run_benchmarks.sh [module_names...]
#
# Examples:
#   ./run_benchmarks.sh                 # Run all module benchmarks
#   ./run_benchmarks.sh sha512          # Run only sha512
#   ./run_benchmarks.sh chacha20 x25519 # Run a subset
#
# Available modules: sha256, sha512, blake2, chacha20, chacha20_poly1305,
#                    poly1305, aes_gcm, x25519, x448

set -e  # Exit on any error

echo "============================================="
echo "Crypto Library - Benchmark Runner"
echo "============================================="
echo

# Colors for output
green='\033[0;32m'
red='\033[0;31m'
blue='\033[0;34m'
nc='\033[0m' # No Color

# Lua binary to use (LuaJIT recommended for best performance)
lua_binary="${LUA_BINARY:-luajit}"
if ! command -v "$lua_binary" &> /dev/null; then
    lua_binary="lua"
fi
if ! command -v "$lua_binary" &> /dev/null; then
    echo -e "${red}Error: no lua/luajit binary found.${nc}"
    exit 1
fi
echo "$($lua_binary -v)"
echo

# Get script directory and set up package path
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
lua_path="$script_dir/?.lua;$script_dir/?/init.lua;$script_dir/src/?.lua;$script_dir/src/?/init.lua;$script_dir/vendor/?.lua;$LUA_PATH"

# Determine which modules to run
all_modules=("sha256" "sha512" "blake2" "chacha20" "chacha20_poly1305" "poly1305" "aes_gcm" "x25519" "x448")
modules_to_run=("$@")

if [ ${#modules_to_run[@]} -eq 0 ] || [ "${modules_to_run[0]}" = "all" ]; then
    modules_to_run=("${all_modules[@]}")
fi

# Validate
for module in "${modules_to_run[@]}"; do
    valid=0
    for valid_module in "${all_modules[@]}"; do
        [ "$module" = "$valid_module" ] && valid=1 && break
    done
    if [ $valid -eq 0 ]; then
        echo -e "${red}Error: Unknown module '$module'${nc}"
        echo "Available modules: ${all_modules[*]}"
        exit 1
    fi
done

echo "Benchmarking modules: ${modules_to_run[*]}"
echo

failed=0
for module in "${modules_to_run[@]}"; do
    echo "---------------------------------------------"
    echo -e "${blue}Benchmarking $module...${nc}"
    echo "---------------------------------------------"
    if ! LUA_PATH="$lua_path" "$lua_binary" -e "require('crypto.$module').benchmark()" 2>&1; then
        echo -e "${red}$module: BENCHMARK FAILED${nc}"
        failed=1
    fi
    echo
done

if [ $failed -eq 0 ]; then
    echo -e "${green}Benchmarks complete.${nc}"
    exit 0
else
    echo -e "${red}Some benchmarks failed.${nc}"
    exit 1
fi
