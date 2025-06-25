#!/bin/bash

#!/bin/bash

set -e  # エラー時に停止

echo "=== Wireshark editcap AFL++ ビルドスクリプト ==="

# クリーンアップ
echo "クリーンアップ中..."
rm -rf build
rm -rf CMakeCache.txt CMakeFiles/

# 必要な依存関係の確認
echo "依存関係のチェック..."
if ! command -v afl-clang-fast &> /dev/null; then
    echo "エラー: afl-clang-fast が見つかりません"
    exit 1
fi

# 環境変数設定
echo "環境変数設定..."
export CC=afl-clang-fast
export CXX=afl-clang-fast++

# Address Sanitizerの設定（オプション）
if [ "${USE_ASAN:-0}" = "1" ]; then
    echo "Address Sanitizer を有効化..."
    export CFLAGS="-fsanitize=address -g -O1 -fno-omit-frame-pointer"
    export CXXFLAGS="-fsanitize=address -g -O1 -fno-omit-frame-pointer"
    export LDFLAGS="-fsanitize=address"
    export AFL_USE_ASAN=1
else
    echo "通常モードでビルド..."
    export CFLAGS="-g -O1"
    export CXXFLAGS="-g -O1"
    export LDFLAGS=""
fi

# ビルドディレクトリ作成
echo "ビルドディレクトリ作成..."
mkdir -p build
cd build

# CMake設定
echo "CMake設定中..."
cmake .. \
    -DCMAKE_C_COMPILER=afl-clang-fast \
    -DCMAKE_CXX_COMPILER=afl-clang-fast++ \
    -DCMAKE_BUILD_TYPE=Debug \
    -DBUILD_wireshark=OFF \
    -DBUILD_tshark=ON \
    -DBUILD_dumpcap=ON \
    -DBUILD_rawshark=OFF \
    -DBUILD_dftest=OFF \
    -DBUILD_randpkt=OFF \
    -DENABLE_STATIC=ON \
    -DENABLE_PLUGINS=OFF \
    -DENABLE_PCAP=ON \
    -DENABLE_ZLIB=ON \
    -DCMAKE_C_FLAGS="$CFLAGS" \
    -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
    -DCMAKE_EXE_LINKER_FLAGS="$LDFLAGS"

# ビルド
echo "ビルド開始..."
make -j$(nproc) editcap tshark dumpcap mergecap capinfos text2pcap


# rm -rf build

# # Phase 1: Build tools with normal compiler
# echo "Phase 1: Building tools..."
# export CC=gcc
# export CXX=g++
# unset AFL_USE_ASAN
# unset CFLAGS
# unset CXXFLAGS
# unset LDFLAGS

# mkdir build
# cd build
# cmake .. -DBUILD_wireshark=OFF

# # lemonツールのみ先にビルド
# make lemon

# # Phase 2: Build with AFL++
# echo "Phase 2: Building with AFL++..."
# export AFL_USE_ASAN=1
# export CC=afl-clang-fast
# export CXX=afl-clang-fast++
# export CFLAGS="-fsanitize=address -g -O1"
# export CXXFLAGS="-fsanitize=address -g -O1"
# export LDFLAGS="-fsanitize=address"

# # メインビルド（依存関係が自動的に解決される）
# make


# # #!/bin/bash

# # rm -rf build

# # export AFL_USE_ASAN=1

# # export CC=afl-clang-fast
# # export CXX=afl-clang-fast++

# # export CFLAGS="-fsanitize=address -g -O1"
# # export CXXFLAGS="-fsanitize=address -g -O1"
# # export LDFLAGS="-fsanitize=address"

# # # export CC=afl-gcc
# # # export CFLAGS="-fprofile-arcs -ftest-coverage"
# # # export LDFLAGS="-lgcov --coverage"

# # mkdir build
# # cd build
# # cmake .. -DBUILD_wireshark=OFF ..
# # make