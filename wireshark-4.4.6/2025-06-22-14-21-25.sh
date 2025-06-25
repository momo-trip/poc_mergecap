#!/bin/bash

# This script tests the mergecap command to trigger wmem_realloc function

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

# Set environment variable to force wmem to use strict allocator
# This should ensure that wmem_realloc is called directly and tracked
export WIRESHARK_DEBUG_WMEM_OVERRIDE="strict"

# Create a test pcap file with a valid header
echo "Creating test pcap file"
cat > test_files/test1.pcap << 'EOT'




EOT

# Write a valid pcap header
printf "\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x01\x00\x00\x00" > test_files/test1.pcap

# Create a second test pcap file with a valid header
echo "Creating test pcap file 2"
cat > test_files/test2.pcap << 'EOT'




EOT

# Write a valid pcap header
printf "\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x01\x00\x00\x00" > test_files/test2.pcap

# Create a pcapng file with a valid header
echo "Creating test pcapng file"
cat > test_files/test.pcapng << 'EOT'




EOT

# Write a valid pcapng header (Section Header Block)
printf "\x0a\x0d\x0d\x0a\x1c\x00\x00\x00\x4d\x3c\x2b\x1a\x01\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\x1c\x00\x00\x00" > test_files/test.pcapng

# Create a larger pcap file with some packet data
echo "Creating larger pcap file with packet data"
cat > test_files/large.pcap << 'EOT'




EOT

# Write a valid pcap header
printf "\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x01\x00\x00\x00" > test_files/large.pcap

# Add multiple packet headers and data to force buffer resizing
for i in {1..10}; do
  # Add packet header (timestamp, captured length, original length)
  printf "\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x40\x00\x00\x00" >> test_files/large.pcap
  # Add packet data (64 bytes)
  dd if=/dev/urandom of=test_files/temp_data bs=64 count=1 2>/dev/null
  cat test_files/temp_data >> test_files/large.pcap
done
rm -f test_files/temp_data

# Create a very large pcap file to force memory reallocation
echo "Creating very large pcap file"
cat > test_files/verylarge.pcap << 'EOT'




EOT

# Write a valid pcap header
printf "\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x01\x00\x00\x00" > test_files/verylarge.pcap

# Add many packet headers and data to force buffer resizing
for i in {1..20}; do
  # Add packet header (timestamp, captured length, original length)
  printf "\x00\x00\x00\x00\x00\x00\x00\x00\xff\x00\x00\x00\xff\x00\x00\x00" >> test_files/verylarge.pcap
  # Add packet data (255 bytes)
  dd if=/dev/urandom of=test_files/temp_data bs=255 count=1 2>/dev/null
  cat test_files/temp_data >> test_files/verylarge.pcap
done
rm -f test_files/temp_data

echo "Running tests to trigger wmem_realloc function"

# Test 1: Run with version flag to trigger version info
echo "Test 1: Running with version flag"
$MERGECAP_PATH -v

# Test 2: Run with help flag
echo "Test 2: Running with help flag"
$MERGECAP_PATH -h

# Test 3: Merge pcap files with verbose output
echo "Test 3: Merging pcap files with verbose output"
$MERGECAP_PATH -v -w test_files/output1.pcap test_files/test1.pcap test_files/test2.pcap

# Test 4: Merge pcap files with specific encapsulation type
echo "Test 4: Merging pcap files with specific encapsulation type"
$MERGECAP_PATH -T ether -w test_files/output2.pcap test_files/test1.pcap test_files/test2.pcap

# Test 5: Merge pcap files with snaplen option
echo "Test 5: Merging pcap files with snaplen option"
$MERGECAP_PATH -s 65535 -w test_files/output3.pcap test_files/test1.pcap test_files/test2.pcap

# Test 6: Merge pcap files with IDB merge mode
echo "Test 6: Merging pcap files with IDB merge mode"
$MERGECAP_PATH -I any -w test_files/output4.pcap test_files/test1.pcap test_files/test2.pcap

# Test 7: Merge pcap files with strict time order
echo "Test 7: Merging pcap files with strict time order"
$MERGECAP_PATH -a -w test_files/output5.pcap test_files/test1.pcap test_files/test2.pcap

# Test 8: Convert pcap to pcapng
echo "Test 8: Converting pcap to pcapng"
$MERGECAP_PATH -F pcapng -w test_files/output6.pcapng test_files/test1.pcap

# Test 9: Merge with all options combined
echo "Test 9: Merging with all options combined"
$MERGECAP_PATH -v -a -s 65535 -I any -F pcapng -w test_files/output7.pcapng test_files/test1.pcap test_files/test2.pcap

# Test 10: Merge with compression
echo "Test 10: Merging with compression"
$MERGECAP_PATH --compress=gzip -w test_files/output8.pcapng.gz test_files/test1.pcap test_files/test2.pcap

# Test 11: Process large file to trigger buffer reallocation
echo "Test 11: Processing large file"
$MERGECAP_PATH -v -w test_files/output_large.pcap test_files/large.pcap

# Test 12: Process very large file to trigger multiple buffer reallocations
echo "Test 12: Processing very large file"
$MERGECAP_PATH -v -w test_files/output_verylarge.pcap test_files/verylarge.pcap

# Test 13: Merge multiple files with different sizes to trigger reallocation
echo "Test 13: Merging multiple files with different sizes"
$MERGECAP_PATH -v -w test_files/output_mixed.pcap test_files/test1.pcap test_files/large.pcap test_files/verylarge.pcap

# Test 14: Use stdout as output to force buffer handling and reallocation
echo "Test 14: Using stdout as output"
$MERGECAP_PATH -w - test_files/large.pcap > test_files/output_stdout.pcap

# Test 15: Use stdin as input to force buffer handling and reallocation
echo "Test 15: Using stdin as input"
cat test_files/large.pcap | $MERGECAP_PATH -w test_files/output_stdin.pcap -

# Test 16: Merge files with different encapsulation types to force reallocation
echo "Test 16: Merging files with different encapsulation types"
# First create a file with a different encapsulation type
cp test_files/test1.pcap test_files/different_encap.pcap
# Try to merge them
$MERGECAP_PATH -w test_files/output_diff_encap.pcap test_files/test1.pcap test_files/different_encap.pcap

# Test 17: Use snaplen to force reallocation during processing
echo "Test 17: Using snaplen to force reallocation"
$MERGECAP_PATH -s 1024 -w test_files/output_snaplen.pcap test_files/verylarge.pcap

# Test 18: Use a very small snaplen first, then a larger one to trigger reallocation
echo "Test 18: Using varying snaplen sizes"
$MERGECAP_PATH -s 64 -w test_files/output_small_snaplen.pcap test_files/verylarge.pcap
$MERGECAP_PATH -s 1024 -w test_files/output_large_snaplen.pcap test_files/verylarge.pcap

# Test 19: Convert between file formats to trigger reallocation
echo "Test 19: Converting between file formats"
$MERGECAP_PATH -F pcapng -w test_files/output_convert1.pcapng test_files/large.pcap
$MERGECAP_PATH -F pcap -w test_files/output_convert2.pcap test_files/output_convert1.pcapng

# Test 20: Process files in sequence with increasing sizes to trigger reallocation
echo "Test 20: Processing files in sequence with increasing sizes"
for i in {1..3}; do
  case $i in
    1) $MERGECAP_PATH -w test_files/output_seq_${i}.pcap test_files/test1.pcap ;;
    2) $MERGECAP_PATH -w test_files/output_seq_${i}.pcap test_files/large.pcap ;;
    3) $MERGECAP_PATH -w test_files/output_seq_${i}.pcap test_files/verylarge.pcap ;;
  esac
done

# Test 21: Use different compression methods to trigger reallocation
echo "Test 21: Using different compression methods"
$MERGECAP_PATH --compress=gzip -w test_files/output_gzip.pcapng.gz test_files/large.pcap
$MERGECAP_PATH --compress=lz4 -w test_files/output_lz4.pcapng.lz4 test_files/large.pcap

# Test 22: Merge files with explicit reallocation scenario
echo "Test 22: Explicit reallocation scenario"
# First create a small output
$MERGECAP_PATH -w test_files/temp1.pcap test_files/test1.pcap
# Then append to it, which should trigger reallocation
$MERGECAP_PATH -w test_files/temp2.pcap test_files/temp1.pcap test_files/large.pcap
# Then append even more, which should trigger another reallocation
$MERGECAP_PATH -w test_files/output_realloc.pcap test_files/temp2.pcap test_files/verylarge.pcap
rm -f test_files/temp1.pcap test_files/temp2.pcap

echo "Tests completed."
