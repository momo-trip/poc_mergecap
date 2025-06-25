#!/bin/bash

# This script tests the mergecap command to trigger wtap_block_get_option function

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

# Create a test pcap file with the dd command
echo "Creating test pcap file"
dd if=/dev/zero of=test_files/test1.pcap bs=1 count=24 2>/dev/null
# Write a valid pcap header
printf "\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x01\x00\x00\x00" > test_files/test1.pcap

# Create another test pcap file
echo "Creating test pcap file 2"
dd if=/dev/zero of=test_files/test2.pcap bs=1 count=24 2>/dev/null
# Write a valid pcap header
printf "\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x01\x00\x00\x00" > test_files/test2.pcap

# Create a pcapng file
echo "Creating test pcapng file"
dd if=/dev/zero of=test_files/test.pcapng bs=1 count=32 2>/dev/null
# Write a valid pcapng header (Section Header Block)
printf "\x0a\x0d\x0d\x0a\x1c\x00\x00\x00\x4d\x3c\x2b\x1a\x01\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\x1c\x00\x00\x00" > test_files/test.pcapng

echo "Running tests to trigger wtap_block_get_option function"

# Test 1: Merge pcap files with verbose output
echo "Test 1: Merging pcap files with verbose output"
$MERGECAP_PATH -v -w test_files/output1.pcap test_files/test1.pcap test_files/test2.pcap

# Test 2: Merge pcap files with specific encapsulation type
echo "Test 2: Merging pcap files with specific encapsulation type"
$MERGECAP_PATH -T ether -w test_files/output2.pcap test_files/test1.pcap test_files/test2.pcap

# Test 3: Merge pcap files with snaplen option
echo "Test 3: Merging pcap files with snaplen option"
$MERGECAP_PATH -s 65535 -w test_files/output3.pcap test_files/test1.pcap test_files/test2.pcap

# Test 4: Merge pcap files with IDB merge mode
echo "Test 4: Merging pcap files with IDB merge mode"
$MERGECAP_PATH -I any -w test_files/output4.pcap test_files/test1.pcap test_files/test2.pcap

# Test 5: Merge pcap files with strict time order
echo "Test 5: Merging pcap files with strict time order"
$MERGECAP_PATH -a -w test_files/output5.pcap test_files/test1.pcap test_files/test2.pcap

# Test 6: Merge pcapng file (which has blocks with options)
echo "Test 6: Merging pcapng file"
$MERGECAP_PATH -v -w test_files/output6.pcapng test_files/test.pcapng

# Test 7: Merge pcap files with specific file type
echo "Test 7: Merging pcap files with specific file type"
$MERGECAP_PATH -F pcapng -w test_files/output7.pcapng test_files/test1.pcap test_files/test2.pcap

# Test 8: Merge pcap files with compression
echo "Test 8: Merging pcap files with compression"
$MERGECAP_PATH --compress=gzip -w test_files/output8.pcapng.gz test_files/test1.pcap test_files/test2.pcap

# Test 9: Merge pcap files with all options combined
echo "Test 9: Merging pcap files with all options combined"
$MERGECAP_PATH -v -a -s 65535 -I any -F pcapng -w test_files/output9.pcapng test_files/test1.pcap test_files/test2.pcap

# Test 10: Try to merge with invalid options to trigger error handling
echo "Test 10: Merging with invalid options"
$MERGECAP_PATH -I invalid -w test_files/output10.pcap test_files/test1.pcap test_files/test2.pcap

echo "Tests completed."
