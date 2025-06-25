#!/bin/bash

# This script tests the mergecap command to trigger fill_manifest function

echo "Creating test directory if it doesn't exist"
mkdir -p test_files

# Create a test file
echo "Creating test file"
echo "test data" > test_files/test1.txt

# Set environment variables to ensure logging is active
export WIRESHARK_LOG_LEVEL=debug

echo "Running tests to trigger fill_manifest function"

# Test 1: Run with debug level logging to ensure log messages are generated
echo "Test 1: Running with debug level logging"
./mergecap --log-level=debug -w /dev/null test_files/test1.txt

# Test 2: Run with verbose flag to generate more log messages
echo "Test 2: Running with verbose flag"
./mergecap -V --log-level=debug -w /dev/null test_files/test1.txt

# Test 3: Run with noisy logging for main domain
echo "Test 3: Running with noisy logging for main domain"
./mergecap --log-noisy=LOG_DOMAIN_MAIN -w /dev/null test_files/test1.txt

# Test 4: Run with debug logging for main domain
echo "Test 4: Running with debug logging for main domain"
./mergecap --log-debug=LOG_DOMAIN_MAIN -w /dev/null test_files/test1.txt

# Test 5: Run with fatal domain to trigger error logging
echo "Test 5: Running with fatal domain"
./mergecap --log-fatal-domain=LOG_DOMAIN_MAIN -w /dev/null test_files/test1.txt

# Test 6: Run with invalid file to trigger error logging
echo "Test 6: Running with invalid file"
./mergecap --log-level=debug -w /dev/null nonexistent_file.pcap

# Test 7: Run with invalid output path to trigger error logging
echo "Test 7: Running with invalid output path"
./mergecap --log-level=debug -w /invalid/path/output.pcap test_files/test1.txt

# Test 8: Run with invalid file format to trigger error logging
echo "Test 8: Running with invalid file format"
./mergecap --log-level=debug -F invalid_format -w /dev/null test_files/test1.txt

# Test 9: Run with log file output to capture logs
echo "Test 9: Running with log file output"
./mergecap --log-level=debug --log-file=test_files/mergecap_log.txt -w /dev/null test_files/test1.txt

# Test 10: Run with help option to trigger info logging
echo "Test 10: Running with help option"
./mergecap --log-level=debug -h

echo "Tests completed."
