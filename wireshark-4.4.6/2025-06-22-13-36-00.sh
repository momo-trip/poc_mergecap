#!/bin/bash

# This script tests the mergecap command to trigger fill_manifest function

echo "Creating test directory if it doesn't exist"
mkdir -p test_files

# Find the location of the mergecap binary
MERGECAP_PATH="$(find /home/ubuntu/shellgen/workspace_mergecap -name mergecap -type f -executable | head -n 1)"

if [ -z "$MERGECAP_PATH" ]; then
    echo "Error: mergecap executable not found"
    exit 1
fi

echo "Found mergecap at: $MERGECAP_PATH"

# Create a test file
echo "Creating test file"
echo "test data" > test_files/test1.txt

# Set environment variables to ensure logging is active
export WIRESHARK_LOG_LEVEL=debug

echo "Running tests to trigger fill_manifest function"

# Test 1: Run with debug level logging to ensure log messages are generated
echo "Test 1: Running with debug level logging"
$MERGECAP_PATH --log-level=debug -w /dev/null test_files/test1.txt

# Test 2: Run with verbose flag to generate more log messages
echo "Test 2: Running with verbose flag"
$MERGECAP_PATH -V --log-level=debug -w /dev/null test_files/test1.txt

# Test 3: Run with noisy logging for main domain
echo "Test 3: Running with noisy logging for main domain"
$MERGECAP_PATH --log-noisy=LOG_DOMAIN_MAIN -w /dev/null test_files/test1.txt

# Test 4: Run with debug logging for main domain
echo "Test 4: Running with debug logging for main domain"
$MERGECAP_PATH --log-debug=LOG_DOMAIN_MAIN -w /dev/null test_files/test1.txt

# Test 5: Run with fatal domain to trigger error logging
echo "Test 5: Running with fatal domain"
$MERGECAP_PATH --log-fatal-domain=LOG_DOMAIN_MAIN -w /dev/null test_files/test1.txt

# Test 6: Run with invalid file to trigger error logging
echo "Test 6: Running with invalid file"
$MERGECAP_PATH --log-level=debug -w /dev/null nonexistent_file.pcap

# Test 7: Run with invalid output path to trigger error logging
echo "Test 7: Running with invalid output path"
$MERGECAP_PATH --log-level=debug -w /invalid/path/output.pcap test_files/test1.txt

# Test 8: Run with invalid file format to trigger error logging
echo "Test 8: Running with invalid file format"
$MERGECAP_PATH --log-level=debug -F invalid_format -w /dev/null test_files/test1.txt

# Test 9: Run with log file output to capture logs
echo "Test 9: Running with log file output"
$MERGECAP_PATH --log-level=debug --log-file=test_files/mergecap_log.txt -w /dev/null test_files/test1.txt

# Test 10: Run with help option to trigger info logging
echo "Test 10: Running with help option"
$MERGECAP_PATH --log-level=debug -h

# Test 11: Run with critical log level
echo "Test 11: Running with critical log level"
$MERGECAP_PATH --log-level=critical -w /dev/null test_files/test1.txt

# Test 12: Run with warning log level
echo "Test 12: Running with warning log level"
$MERGECAP_PATH --log-level=warning -w /dev/null test_files/test1.txt

# Test 13: Run with error log level
echo "Test 13: Running with error log level"
$MERGECAP_PATH --log-level=error -w /dev/null test_files/test1.txt

# Test 14: Run with info log level
echo "Test 14: Running with info log level"
$MERGECAP_PATH --log-level=info -w /dev/null test_files/test1.txt

# Test 15: Run with message log level
echo "Test 15: Running with message log level"
$MERGECAP_PATH --log-level=message -w /dev/null test_files/test1.txt

# Test 16: Run with echo log level
echo "Test 16: Running with echo log level"
$MERGECAP_PATH --log-level=echo -w /dev/null test_files/test1.txt

# Test 17: Run with noisy log level
echo "Test 17: Running with noisy log level"
$MERGECAP_PATH --log-level=noisy -w /dev/null test_files/test1.txt

# Test 18: Run with invalid log level to trigger error
echo "Test 18: Running with invalid log level"
$MERGECAP_PATH --log-level=invalid -w /dev/null test_files/test1.txt

# Test 19: Run with version flag
echo "Test 19: Running with version flag"
$MERGECAP_PATH -v

echo "Tests completed."
