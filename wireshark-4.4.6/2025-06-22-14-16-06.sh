#!/bin/bash

# This script tests the mergecap command to trigger wmem_free function

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

# Set environment variable to force wmem to use simple allocator
# This should ensure that wmem_free is called directly
export WIRESHARK_DEBUG_WMEM_OVERRIDE="simple"

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

echo "Running tests to trigger wmem_free function"

# Test 1: Run with version flag to trigger version info which uses wmem_free
echo "Test 1: Running with version flag"
$MERGECAP_PATH -v

# Test 2: Run with help flag to trigger help text which uses wmem_free
echo "Test 2: Running with help flag"
$MERGECAP_PATH -h

# Test 3: Run with invalid option to trigger error message which uses wmem_free
echo "Test 3: Running with invalid option"
$MERGECAP_PATH --invalid-option

# Test 4: Merge pcap files with verbose output
# This should allocate and free memory for file handling
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

# Test 13: Run with non-existent input files to trigger error handling
echo "Test 13: Running with non-existent input files"
$MERGECAP_PATH -w test_files/output10.pcap nonexistent1.pcap nonexistent2.pcap

# Test 14: Run with invalid output path to trigger error handling
echo "Test 14: Running with invalid output path"
$MERGECAP_PATH -w /invalid/path/output.pcap test_files/test1.pcap test_files/test2.pcap

# Test 15: Run with empty file list to trigger error handling
echo "Test 15: Running with empty file list"
$MERGECAP_PATH -w test_files/output11.pcap

# Test 16: Run with -F option without argument to list file types
echo "Test 16: Running with -F option without argument"
$MERGECAP_PATH -F

# Test 17: Run with -I option without argument to list merge modes
echo "Test 17: Running with -I option without argument"
$MERGECAP_PATH -I

# Test 18: Run with --compress option without argument
echo "Test 18: Running with --compress option without argument"
$MERGECAP_PATH --compress -w test_files/output12.pcap test_files/test1.pcap

# Test 19: Run with very large snaplen to potentially trigger memory allocation/free issues
echo "Test 19: Running with very large snaplen"
$MERGECAP_PATH -s 1000000 -w test_files/output13.pcap test_files/test1.pcap

# Test 20: Create a temporary file and then process it to trigger cleanup
echo "Test 20: Creating and processing temporary file"
cp test_files/test1.pcap test_files/temp.pcap
$MERGECAP_PATH -w test_files/output14.pcap test_files/temp.pcap
rm test_files/temp.pcap

# Test 21: Run multiple operations in sequence to trigger memory cleanup
echo "Test 21: Running multiple operations in sequence"
for i in {1..3}; do
  $MERGECAP_PATH -v -w test_files/output_seq_${i}.pcap test_files/test1.pcap
done

# Test 22: Run with realloc scenario (first allocate small, then large)
echo "Test 22: Running with realloc scenario"
$MERGECAP_PATH -s 100 -w test_files/output_small.pcap test_files/test1.pcap
$MERGECAP_PATH -s 10000 -w test_files/output_large.pcap test_files/test1.pcap

echo "Tests completed."
