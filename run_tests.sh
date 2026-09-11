#!/bin/bash

# lua-crypto Test Runner
#
# Usage: ./run_tests.sh [module_names...]
#
# Examples:
#   ./run_tests.sh                    # Run all modules
#   ./run_tests.sh sha512             # Run only sha512
#   ./run_tests.sh sha256 x25519      # Run only sha256 and x25519
#
# Available modules: sha256, sha512, blake2, chacha20, chacha20_poly1305,
#                    poly1305, aes_gcm, hkdf, random, bignum, srp, x25519, x448,
#                    ed25519, openssl_wrapper

set -e  # Exit on any error

echo "============================================="
echo "Crypto Library - Test Suite Runner"
echo "============================================="
echo

# Colors for output
green='\033[0;32m'
red='\033[0;31m'
blue='\033[0;34m'
nc='\033[0m' # No Color

# Track overall results
passed_modules=()
failed_modules=()

# Lua binary to use for running tests
lua_binary="${LUA_BINARY:-lua}"

# Check if the lua binary is available
if ! command -v "$lua_binary" &> /dev/null; then
    echo -e "${red}Error: $lua_binary command not found.${nc}"
    exit 1
fi
echo "$($lua_binary -v)"
echo

# Get script directory
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

# Add repository root to Lua's package path
# This allows require() to find modules in the src/vendor directories
lua_path="$script_dir/?.lua;$script_dir/?/init.lua;$script_dir/src/?.lua;$script_dir/src/?/init.lua;$script_dir/vendor/?.lua;$LUA_PATH"

# Parse command line arguments to determine which modules to run
all_modules=("sha256" "sha512" "blake2" "chacha20" "chacha20_poly1305" "poly1305" "aes_gcm" "hkdf" "random" "bignum" "srp" "x25519" "x448" "ed25519" "openssl_wrapper" "lpack")
default_modules=("${all_modules[@]}")
modules_to_run=("$@")

# Validate modules if specified
if [ ${#modules_to_run[@]} -gt 0 ] && [ "${modules_to_run[0]}" != "all" ]; then
    for module in "${modules_to_run[@]}"; do
        valid=0
        for valid_module in "${all_modules[@]}"; do
            if [ "$module" = "$valid_module" ]; then
                valid=1
                break
            fi
        done
        if [ $valid -eq 0 ]; then
            echo -e "${red}Error: Unknown module '$module'${nc}"
            echo "Available modules: ${all_modules[*]}"
            exit 1
        fi
    done
fi

if [ ${#modules_to_run[@]} -eq 0 ]; then
    modules_to_run=("${default_modules[@]}")
    echo "Running default modules: ${modules_to_run[*]}"
elif [ "${modules_to_run[0]}" = "all" ]; then
    modules_to_run=("${all_modules[@]}")
    echo "Running all modules: ${modules_to_run[*]}"
else
    echo "Running specified modules: ${modules_to_run[*]}"
fi
echo

# Function to check if a module should be run
should_run_module() {
    local module_key="$1"
    for module in "${modules_to_run[@]}"; do
        if [ "$module" = "$module_key" ]; then
            return 0
        fi
    done
    return 1
}

# Function to run a test and capture result
run_test() {
    local module_name="$1"
    local module_key="$2"
    local lua_command="$3"

    if ! should_run_module "$module_key"; then
        return
    fi

    echo "---------------------------------------------"
    echo -e "${blue}Testing $module_name...${nc}"
    echo "---------------------------------------------"

    if LUA_PATH="$lua_path" "$lua_binary" -e "$lua_command" 2>&1; then
        echo -e "${green}$module_name: ALL TESTS PASSED${nc}"
        passed_modules+=("$module_name")
    else
        echo -e "${red}$module_name: TESTS FAILED${nc}"
        failed_modules+=("$module_name")
    fi

    echo
}

run_selftest() {
  local module_name="$1"
  local module_key="$2"
  local lua_module="$3"
  run_test "$module_name" "$module_key" "
    local result = require('$lua_module').selftest()
    if result == false then
        os.exit(1)
    end
  "
}

# Run module tests
run_selftest "SHA-256"            "sha256"            "crypto.sha256"
run_selftest "SHA-512"            "sha512"            "crypto.sha512"
run_selftest "BLAKE2"             "blake2"            "crypto.blake2"
run_selftest "ChaCha20"           "chacha20"          "crypto.chacha20"
run_selftest "ChaCha20-Poly1305"  "chacha20_poly1305" "crypto.chacha20_poly1305"
run_selftest "Poly1305"           "poly1305"          "crypto.poly1305"
run_selftest "AES-GCM"            "aes_gcm"           "crypto.aes_gcm"
run_selftest "HKDF"               "hkdf"              "crypto.hkdf"
run_selftest "Randomness"         "random"            "crypto.random"
run_selftest "Bignum"             "bignum"            "crypto.bignum"
run_selftest "SRP-6a"             "srp"               "crypto.srp"
run_selftest "X25519"             "x25519"            "crypto.x25519"
run_selftest "X448"               "x448"              "crypto.x448"
run_selftest "Ed25519"            "ed25519"           "crypto.ed25519"
run_selftest "OpenSSL gating"     "openssl_wrapper"   "crypto.openssl_wrapper"

# Control4's LuaJIT has string.pack/unpack as lpack, a different dialect: every
# selftest again with that shape installed before bitn loads.
run_test "All selftests with lpack-shaped string.pack" "lpack" "
    dofile('$script_dir/test/lpack_stub.lua')
    if not require('crypto').selftest() then
        os.exit(1)
    end
  "

passed_count=${#passed_modules[@]}
failed_count=${#failed_modules[@]}
total_count=$((passed_count + failed_count))

# If only one module is run, no need to summarize
if [ $total_count -eq 1 ]; then
    if [ $failed_count -gt 0 ]; then
        exit 1
    fi
    exit 0
fi

# Summary
echo "============================================="
echo "TEST SUMMARY"
echo "============================================="

if [ $passed_count -eq $total_count ]; then
    echo -e "${green}ALL MODULES PASSED: $passed_count/$total_count${nc}"
    echo
    echo "Passed modules:"
    for module in "${passed_modules[@]}"; do
        echo "  $module: PASS"
    done
    exit 0
else
    echo -e "${red}SOME MODULES FAILED: $passed_count/$total_count passed${nc}"
    echo
    echo "Failed modules:"
    for module in "${failed_modules[@]}"; do
        echo "  $module: FAIL"
    done
    exit 1
fi
