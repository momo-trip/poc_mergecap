#!/bin/bash

# This script tests the mergecap command to trigger ws_log_fatal_full function

cd "$(dirname "$0")"

# Create a test directory if it doesn't exist
mkdir -p test_files

# Create a test file to use with mergecap
echo "Creating test files..."
echo "test data" > test_files/test1.txt

# Try to trigger ws_log_fatal_full by setting a fatal domain and then triggering an error
# The --log-fatal-domain option sets domains that will be treated as fatal
# The --log-fatal=warning option sets the log level that will be treated as fatal
# We'll try to trigger a fatal error by setting the main domain as fatal and then causing an error

echo "Running test to trigger ws_log_fatal_full..."

# Set LOG_DOMAIN_MAIN as a fatal domain and set warning level as fatal
./mergecap --log-fatal-domain=LOG_DOMAIN_MAIN --log-fatal=warning --log-level=warning -a -w /dev/null test_files/test1.txt

# If the above doesn't work, try with an invalid file format
./mergecap --log-fatal-domain=LOG_DOMAIN_MAIN --log-fatal=warning --log-level=warning -a -w /dev/null test_files/nonexistent.pcap

# Try with an invalid output file path
./mergecap --log-fatal-domain=LOG_DOMAIN_MAIN --log-fatal=warning --log-level=warning -a -w /invalid/path/output.pcap test_files/test1.txt

# Try with invalid command line options
./mergecap --log-fatal-domain=LOG_DOMAIN_MAIN --log-fatal=warning --log-level=warning --invalid-option

# Try with invalid file format
./mergecap --log-fatal-domain=LOG_DOMAIN_MAIN --log-fatal=warning --log-level=warning -T invalid_format -w /dev/null test_files/test1.txt

# Try with a non-capture file
./mergecap --log-fatal-domain=LOG_DOMAIN_MAIN --log-fatal=warning --log-level=warning -a -w /dev/null test_files/test1.txt

# Try with a file that doesn't exist
./mergecap --log-fatal-domain=LOG_DOMAIN_MAIN --log-fatal=warning --log-level=warning -a -w /dev/null nonexistent_file.pcap

echo "Tests completed."
