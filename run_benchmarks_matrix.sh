#!/bin/bash

# Lua bitN Library - Benchmark Matrix Runner
# Runs benchmarks across multiple Lua versions using luaenv
#
# Usage: ./run_benchmarks_matrix.sh [module_names...]
#
# Examples:
#   ./run_benchmarks_matrix.sh                   # Run all benchmarks on all versions
#   ./run_benchmarks_matrix.sh bit32             # Run bit32 benchmarks on all versions
#   ./run_benchmarks_matrix.sh bit32 bit64       # Run specific benchmarks on all versions

# List of luaenv versions to benchmark
LUA_VERSIONS=("5.1.5" "5.2.4" "5.3.6" "5.4.8" "luajit-2.1-dev")

# Colors for output
green='\033[0;32m'
yellow='\033[1;33m'
red='\033[0;31m'
nc='\033[0m' # No Color

luaenv_binary="${LUAENV_BINARY:-luaenv}"

# Get script directory
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

if ! command -v "$luaenv_binary" &> /dev/null; then
    echo -e "${red}❌ Error: $luaenv_binary command not found.${nc}"
    exit 1
fi

if [ ! -d "$($luaenv_binary prefix)/../../plugins/luaenv-luarocks" ]; then
    echo -e "${red}❌ Error: luaenv-luarocks plugin not found. Please install it first.${nc}"
    exit 1
fi

# Track overall results
failed_versions=()
passed_versions=()

for lua_version in "${LUA_VERSIONS[@]}"; do
    echo -e "${yellow}~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~${nc}"
    echo -e "${yellow}Running benchmarks with $lua_version${nc}"
    echo -e "${yellow}~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~${nc}"
    echo

    "$luaenv_binary" install -s $lua_version
    lua_prefix="$($luaenv_binary prefix $lua_version)"
    lua_binary="$lua_prefix/bin/lua"

    # Run the benchmarks and pass all arguments
    if ! LUA_BINARY="$lua_binary" "$script_dir/run_benchmarks.sh" "$@"; then
        failed_versions+=("$lua_version")
    else
        passed_versions+=("$lua_version")
    fi
done

# Final summary
echo "============================================="
echo "📊 Matrix Benchmark Summary"
echo "============================================="

if [ ${#failed_versions[@]} -eq 0 ]; then
    echo -e "${green}✅ All LUA VERSIONS COMPLETED:${nc}"
    printf '%s\n' "${passed_versions[@]}"
    exit 0
else
    echo -e "${red}💥 SOME LUA VERSIONS FAILED:${nc}"
    printf '%s\n' "${failed_versions[@]}"
    exit 1
fi
