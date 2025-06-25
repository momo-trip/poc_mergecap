#!/bin/bash

# This script tests the mergecap command to trigger log_write_dispatch function

echo "Creating test files..."

# Create a test directory if it doesn't exist
mkdir -p test_files

# Create a test file to use with mergecap
echo "test data" > test_files/test1.txt

echo "Running test to trigger log_write_dispatch..."

# Set environment variables to ensure logging is active
export WIRESHARK_LOG_LEVEL=debug
export WIRESHARK_LOG_DOMAIN=LOG_DOMAIN_MAIN

# Test 1: Run mergecap with --log-level option to trigger logging
echo "Test 1: Running with --log-level option"
./mergecap --log-level=debug -w /dev/null test_files/test1.txt

# Test 2: Run mergecap with invalid options to trigger error logging
echo "Test 2: Running with invalid options"
./mergecap --invalid-option

# Test 3: Run mergecap with invalid file format
echo "Test 3: Running with invalid file format"
./mergecap -T invalid_format -w /dev/null test_files/test1.txt

# Test 4: Run mergecap with non-capture file
echo "Test 4: Running with non-capture file"
./mergecap -a -w /dev/null test_files/test1.txt

# Test 5: Run mergecap with a file that doesn't exist
echo "Test 5: Running with non-existent file"
./mergecap -a -w /dev/null nonexistent_file.pcap

# Test 6: Run mergecap with an invalid output path
echo "Test 6: Running with invalid output path"
./mergecap -a -w /invalid/path/output.pcap test_files/test1.txt

# Test 7: Run mergecap with verbose option
echo "Test 7: Running with verbose option"
./mergecap -V -w /dev/null test_files/test1.txt

# Test 8: Run mergecap with debug logging for specific domain
echo "Test 8: Running with debug logging for specific domain"
./mergecap --log-debug=LOG_DOMAIN_MAIN -w /dev/null test_files/test1.txt

# Test 9: Run mergecap with noisy logging
echo "Test 9: Running with noisy logging"
./mergecap --log-noisy=LOG_DOMAIN_MAIN -w /dev/null test_files/test1.txt

# Test 10: Run mergecap with log file output
echo "Test 10: Running with log file output"
./mergecap --log-file=test_files/mergecap_log.txt -w /dev/null test_files/test1.txt

# Test 11: Run mergecap with help option to trigger info logging
echo "Test 11: Running with help option"
./mergecap -h

# Test 12: Run mergecap with version option
echo "Test 12: Running with version option"
./mergecap -v

echo "Tests completed."
