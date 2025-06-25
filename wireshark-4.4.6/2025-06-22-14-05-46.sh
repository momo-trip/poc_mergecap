#!/bin/bash

# This script tests the mergecap command to trigger wmem_alloc function

echo "Creating test directory if it doesn't exist"
mkdir -p test_files

# Find the location of the mergecap binary
MERGECAP_PATH="$(find /home/ubuntu/shellgen/workspace_mergecap -name mergecap -type f -executable | head -n 1)"

if [ -z "$MERGECAP_PATH" ]; then
    echo "Error: mergecap executable not found"
    # If we can't find it in the path, try using the relative path
    MERGECAP_PATH="./mergecap"
fi

echo "Using mergecap at: $MERGECAP_PATH"

# Create a test pcap file
echo "Creating test pcap file"
cat > test_files/test1.pcap << 'EOT'




EOT

# Write a valid pcap header
printf "\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x01\x00\x00\x00" > test_files/test1.pcap

# Create a second test pcap file
echo "Creating test pcap file 2"
cat > test_files/test2.pcap << 'EOT'




EOT

# Write a valid pcap header
printf "\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x01\x00\x00\x00" > test_files/test2.pcap

# Create a pcapng file
echo "Creating test pcapng file"
cat > test_files/test.pcapng << 'EOT'




EOT

# Write a valid pcapng header (Section Header Block)
printf "\x0a\x0d\x0d\x0a\x1c\x00\x00\x00\x4d\x3c\x2b\x1a\x01\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\x1c\x00\x00\x00" > test_files/test.pcapng

echo "Running tests to trigger wmem_alloc function"

# Test 1: Run with version flag to trigger version info which uses wmem_alloc
echo "Test 1: Running with version flag"
$MERGECAP_PATH -v

# Test 2: Run with help flag to trigger help text which uses wmem_alloc
echo "Test 2: Running with help flag"
$MERGECAP_PATH -h

# Test 3: Run with invalid option to trigger error message which uses wmem_alloc
echo "Test 3: Running with invalid option"
$MERGECAP_PATH --invalid-option

# Test 4: Merge pcap files with verbose output
echo "Test 4: Merging pcap files with verbose output"
$MERGECAP_PATH -v -w test_files/output1.pcap test_files/test1.pcap test_files/test2.pcap

# Test 5: Merge pcap files with specific encapsulation type
echo "Test 5: Merging pcap files with specific encapsulation type"
$MERGECAP_PATH -T ether -w test_files/output2.pcap test_files/test1.pcap test_files/test2.pcap

# Test 6: Merge pcap files with snaplen option
echo "Test 6: Merging pcap files with snaplen option"
$MERGECAP_PATH -s 65535 -w test_files/output3.pcap test_files/test1.pcap test_files/test2.pcap

# Test 7: Merge pcap files with IDB merge mode
echo "Test 7: Merging pcap files with IDB merge mode"
$MERGECAP_PATH -I any -w test_files/output4.pcap test_files/test1.pcap test_files/test2.pcap

# Test 8: Merge pcap files with strict time order
echo "Test 8: Merging pcap files with strict time order"
$MERGECAP_PATH -a -w test_files/output5.pcap test_files/test1.pcap test_files/test2.pcap

# Test 9: Convert pcap to pcapng
echo "Test 9: Converting pcap to pcapng"
$MERGECAP_PATH -F pcapng -w test_files/output6.pcapng test_files/test1.pcap

# Test 10: Merge with all options combined
echo "Test 10: Merging with all options combined"
$MERGECAP_PATH -v -a -s 65535 -I any -F pcapng -w test_files/output7.pcapng test_files/test1.pcap test_files/test2.pcap

# Test 11: Merge with compression
echo "Test 11: Merging with compression"
$MERGECAP_PATH --compress=gzip -w test_files/output8.pcapng.gz test_files/test1.pcap test_files/test2.pcap

# Test 12: Merge with invalid options to trigger error handling
echo "Test 12: Merging with invalid options"
$MERGECAP_PATH -I invalid -w test_files/output9.pcap test_files/test1.pcap test_files/test2.pcap

# Test 13: Merge with duplicate frame detection
echo "Test 13: Merging with duplicate frame detection"
$MERGECAP_PATH -D -w test_files/output10.pcap test_files/test1.pcap test_files/test2.pcap

# Test 14: Run with non-existent input files to trigger error handling
echo "Test 14: Running with non-existent input files"
$MERGECAP_PATH -w test_files/output11.pcap nonexistent1.pcap nonexistent2.pcap

# Test 15: Run with invalid output path to trigger error handling
echo "Test 15: Running with invalid output path"
$MERGECAP_PATH -w /invalid/path/output.pcap test_files/test1.pcap test_files/test2.pcap

echo "Tests completed."
