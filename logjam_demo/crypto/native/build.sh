#!/bin/bash
# Build script for C crypto library
# Compiles c_dh.c into a shared library (c_dh.so) for use by Python

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Building C crypto library..."

if ! command -v gcc &> /dev/null; then
    echo "ERROR: gcc not found. Please install gcc to build C extensions."
    echo "  macOS: xcode-select --install"
    echo "  Linux: sudo apt-get install build-essential"
    exit 1
fi

gcc -shared -fPIC -O3 -o c_dh.so c_dh.c -lm

if [ $? -eq 0 ]; then
    echo "Build successful! Library: $SCRIPT_DIR/c_dh.so"
    echo "Crypto operations will now use optimized C implementation."
else
    echo "Build failed!"
    exit 1
fi
