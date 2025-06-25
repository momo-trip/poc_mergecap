
#!/bin/bash

# cd workspace_mergecap/wireshark-4.4.6
export ASAN_OPTIONS=log_path=/tmp/asan_logs:detect_leaks=1:abort_on_error=1:symbolize=0:detect_stack_use_after_return=1
export ASAN_SYMBOLIZER_PATH=$(which llvm-symbolizer)
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
#/home/ubuntu/fuzzer/afl++/afl-fuzz -i afl_inputs -o afl_outputs -- ./mergecap
/home/ubuntu/fuzzer/afl++/afl-fuzz -i afl_inputs -o afl_outputs -f @@ -- ./mergecap < @@
