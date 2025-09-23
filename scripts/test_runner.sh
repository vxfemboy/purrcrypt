#!/bin/bash

# PurrCrypt Comprehensive Test Runner
# This script runs all tests with detailed reporting and performance metrics

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Test configuration
TEST_TIMEOUT=300  # 5 minutes per test
VERBOSE=false
BENCHMARK=false
COVERAGE=false
INTEGRATION=false
STRESS=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -b|--benchmark)
            BENCHMARK=true
            shift
            ;;
        -c|--coverage)
            COVERAGE=true
            shift
            ;;
        -i|--integration)
            INTEGRATION=true
            shift
            ;;
        -s|--stress)
            STRESS=true
            shift
            ;;
        -h|--help)
            echo "PurrCrypt Test Runner"
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  -v, --verbose     Enable verbose output"
            echo "  -b, --benchmark   Run performance benchmarks"
            echo "  -c, --coverage    Generate code coverage report"
            echo "  -i, --integration Run integration tests"
            echo "  -s, --stress      Run stress tests"
            echo "  -h, --help        Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Function to print colored output
print_status() {
    local color=$1
    local message=$2
    echo -e "${color}[$(date '+%H:%M:%S')] ${message}${NC}"
}

# Function to run tests with timeout
run_test() {
    local test_name=$1
    local test_command=$2
    local timeout_seconds=${3:-$TEST_TIMEOUT}
    
    print_status $BLUE "Running: $test_name"
    
    if timeout $timeout_seconds bash -c "$test_command" 2>&1 | tee /tmp/test_output.log; then
        print_status $GREEN "✓ $test_name passed"
        return 0
    else
        local exit_code=$?
        if [ $exit_code -eq 124 ]; then
            print_status $RED "✗ $test_name timed out after ${timeout_seconds}s"
        else
            print_status $RED "✗ $test_name failed with exit code $exit_code"
        fi
        return $exit_code
    fi
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check prerequisites
print_status $CYAN "Checking prerequisites..."

if ! command_exists cargo; then
    print_status $RED "Error: cargo not found. Please install Rust."
    exit 1
fi

if ! command_exists rustc; then
    print_status $RED "Error: rustc not found. Please install Rust."
    exit 1
fi

# Check Rust version
RUST_VERSION=$(rustc --version | cut -d' ' -f2)
print_status $GREEN "Rust version: $RUST_VERSION"

# Install additional tools if needed
if [ "$COVERAGE" = true ] && ! command_exists cargo-tarpaulin; then
    print_status $YELLOW "Installing cargo-tarpaulin for coverage..."
    cargo install cargo-tarpaulin
fi

if [ "$BENCHMARK" = true ] && ! command_exists cargo-criterion; then
    print_status $YELLOW "Installing cargo-criterion for benchmarks..."
    cargo install cargo-criterion
fi

# Create test results directory
mkdir -p test_results
cd test_results

# Start test execution
print_status $PURPLE "Starting PurrCrypt comprehensive test suite..."
print_status $PURPLE "Test configuration:"
print_status $PURPLE "  Verbose: $VERBOSE"
print_status $PURPLE "  Benchmark: $BENCHMARK"
print_status $PURPLE "  Coverage: $COVERAGE"
print_status $PURPLE "  Integration: $INTEGRATION"
print_status $PURPLE "  Stress: $STRESS"
echo ""

# Test counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Function to update test counters
update_counters() {
    local result=$1
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    if [ $result -eq 0 ]; then
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
}

# 1. Basic compilation tests
print_status $CYAN "=== COMPILATION TESTS ==="

run_test "Debug build" "cargo build --verbose"
update_counters $?

run_test "Release build" "cargo build --release --verbose"
update_counters $?

run_test "Check formatting" "cargo fmt -- --check"
update_counters $?

run_test "Clippy linting" "cargo clippy --all-targets --all-features -- -D warnings"
update_counters $?

# 2. Unit tests
print_status $CYAN "=== UNIT TESTS ==="

run_test "Core library tests" "cargo test --lib --verbose"
update_counters $?

run_test "Steganographic RP tests" "cargo test --lib cipher::steganographic_rp --verbose"
update_counters $?

run_test "Efficient cipher tests" "cargo test --lib cipher::efficient --verbose"
update_counters $?

run_test "Post-quantum crypto tests" "cargo test --lib crypto::post_quantum --verbose"
update_counters $?

run_test "Compression tests" "cargo test --lib crypto::efficient_compression --verbose"
update_counters $?

run_test "Key management tests" "cargo test --lib keys --verbose"
update_counters $?

run_test "Configuration tests" "cargo test --lib config --verbose"
update_counters $?

# 3. Integration tests
if [ "$INTEGRATION" = true ]; then
    print_status $CYAN "=== INTEGRATION TESTS ==="
    
    run_test "CLI functionality test" "
        cargo build --release
        ./target/release/purr --help
        ./target/release/purr genkey test_key
        echo 'Hello World! This is a test message.' > test_input.txt
        ./target/release/purr encrypt --recipient test_key --input test_input.txt --output test_encrypted.purr
        ./target/release/purr decrypt --key test_key --input test_encrypted.purr --output test_decrypted.txt
        diff test_input.txt test_decrypted.txt
        rm -f test_key.pub test_key.sec test_input.txt test_encrypted.purr test_decrypted.txt
    "
    update_counters $?
    
    run_test "File encryption/decryption test" "
        cargo build --release
        ./target/release/purr genkey integration_test
        echo 'Integration test data with special characters: 🐱🐶💕✨🎉🚀' > integration_input.txt
        ./target/release/purr encrypt --recipient integration_test --input integration_input.txt --output integration_encrypted.purr
        ./target/release/purr decrypt --key integration_test --input integration_encrypted.purr --output integration_decrypted.txt
        diff integration_input.txt integration_decrypted.txt
        rm -f integration_test.pub integration_test.sec integration_input.txt integration_encrypted.purr integration_decrypted.txt
    "
    update_counters $?
fi

# 4. Performance tests
if [ "$BENCHMARK" = true ]; then
    print_status $CYAN "=== PERFORMANCE TESTS ==="
    
    run_test "Steganographic RP performance" "cargo test --lib cipher::steganographic_rp::tests::test_performance_benchmark --verbose -- --nocapture"
    update_counters $?
    
    run_test "Efficient cipher performance" "cargo test --lib cipher::efficient::tests::test_performance_benchmark_efficient --verbose -- --nocapture"
    update_counters $?
    
    run_test "Post-quantum crypto performance" "cargo test --lib crypto::post_quantum::tests::test_performance_benchmark --verbose -- --nocapture"
    update_counters $?
    
    run_test "Compression performance" "cargo test --lib crypto::efficient_compression::tests::test_compression_performance --verbose -- --nocapture"
    update_counters $?
fi

# 5. Stress tests
if [ "$STRESS" = true ]; then
    print_status $CYAN "=== STRESS TESTS ==="
    
    run_test "Large data encoding/decoding" "
        cargo test --lib cipher::steganographic_rp::tests::test_large_data --verbose -- --nocapture
        cargo test --lib cipher::efficient::tests::test_large_data_efficient --verbose -- --nocapture
    "
    update_counters $?
    
    run_test "Unicode data handling" "
        cargo test --lib cipher::steganographic_rp::tests::test_unicode_data --verbose -- --nocapture
        cargo test --lib cipher::efficient::tests::test_unicode_data_efficient --verbose -- --nocapture
    "
    update_counters $?
    
    run_test "Edge cases" "
        cargo test --lib cipher::steganographic_rp::tests::test_edge_cases --verbose -- --nocapture
        cargo test --lib cipher::efficient::tests::test_edge_cases_efficient --verbose -- --nocapture
    "
    update_counters $?
fi

# 6. Coverage tests
if [ "$COVERAGE" = true ]; then
    print_status $CYAN "=== COVERAGE TESTS ==="
    
    run_test "Code coverage analysis" "cargo tarpaulin --verbose --all-features --out Html --output-dir coverage"
    update_counters $?
fi

# 7. Security tests
print_status $CYAN "=== SECURITY TESTS ==="

run_test "MAC verification tests" "cargo test --lib crypto::post_quantum::tests::test_mac_verification --verbose -- --nocapture"
update_counters $?

run_test "Message corruption tests" "cargo test --lib crypto::post_quantum::tests::test_message_corruption --verbose -- --nocapture"
update_counters $?

run_test "Constant time comparison tests" "cargo test --lib crypto::post_quantum::tests::test_constant_time_comparison --verbose -- --nocapture"
update_counters $?

# 8. Comprehensive feature tests
print_status $CYAN "=== FEATURE TESTS ==="

run_test "All personality tests" "cargo test --lib cipher::steganographic_rp::tests::test_all_personalities --verbose -- --nocapture"
update_counters $?

run_test "All dialect tests" "cargo test --lib cipher::steganographic_rp::tests::test_all_dialects --verbose -- --nocapture"
update_counters $?

run_test "All emotional context tests" "cargo test --lib cipher::efficient::tests::test_all_emotional_contexts --verbose -- --nocapture"
update_counters $?

run_test "All file type tests" "cargo test --lib cipher::efficient::tests::test_all_file_types --verbose -- --nocapture"
update_counters $?

# Generate test report
print_status $PURPLE "=== TEST SUMMARY ==="
echo ""
print_status $GREEN "Total tests run: $TOTAL_TESTS"
print_status $GREEN "Passed: $PASSED_TESTS"
if [ $FAILED_TESTS -gt 0 ]; then
    print_status $RED "Failed: $FAILED_TESTS"
else
    print_status $GREEN "Failed: $FAILED_TESTS"
fi

# Calculate success rate
if [ $TOTAL_TESTS -gt 0 ]; then
    SUCCESS_RATE=$((PASSED_TESTS * 100 / TOTAL_TESTS))
    print_status $CYAN "Success rate: $SUCCESS_RATE%"
else
    print_status $RED "No tests were run!"
    exit 1
fi

# Save test results
echo "Test Results Summary" > test_summary.txt
echo "===================" >> test_summary.txt
echo "Date: $(date)" >> test_summary.txt
echo "Total tests: $TOTAL_TESTS" >> test_summary.txt
echo "Passed: $PASSED_TESTS" >> test_summary.txt
echo "Failed: $FAILED_TESTS" >> test_summary.txt
echo "Success rate: $SUCCESS_RATE%" >> test_summary.txt
echo "" >> test_summary.txt

if [ $FAILED_TESTS -gt 0 ]; then
    print_status $RED "Some tests failed! Check the logs above for details."
    exit 1
else
    print_status $GREEN "All tests passed! 🎉"
    exit 0
fi


