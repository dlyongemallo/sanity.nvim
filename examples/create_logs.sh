#!/bin/bash
#
# Generate valgrind and sanitizer log files from demo.c for use with
# sanity.nvim.  Run this script from the examples/ directory (it expects to
# be located next to demo.c).
#
# Pass -f to overwrite existing output files without prompting.

set -euo pipefail

force=false
if [ "${1:-}" = "-f" ]; then
    force=true
    shift
fi

cd "$(dirname "$0")"

if [ ! -f demo.c ]; then
    echo "error: demo.c not found (expected next to create_logs.sh in examples/)." >&2
    exit 1
fi

output_files=(memcheck.xml helgrind.xml asan.log tsan.log)
if ! $force; then
    existing=()
    for f in "${output_files[@]}"; do
        if [ -f "$f" ]; then
            existing+=("$f")
        fi
    done
    if [ ${#existing[@]} -gt 0 ]; then
        echo "The following output files already exist: ${existing[*]}"
        read -r -p "Overwrite? [y/N] " answer
        if [ "${answer,,}" != "y" ]; then
            echo "Aborted." >&2
            exit 1
        fi
    fi
fi

missing=()
for cmd in gcc valgrind; do
    if ! command -v "$cmd" &>/dev/null; then
        missing+=("$cmd")
    fi
done
if [ ${#missing[@]} -gt 0 ]; then
    echo "error: required command(s) not found: ${missing[*]}" >&2
    exit 1
fi

echo "Compiling demo.c..."
gcc -g -pthread demo.c -o demo

echo "Running memcheck..."
valgrind --tool=memcheck --show-reachable=yes --xml=yes --xml-file=memcheck.xml ./demo

echo "Running helgrind..."
valgrind --tool=helgrind --xml=yes --xml-file=helgrind.xml ./demo

echo "Compiling with AddressSanitizer..."
gcc -g -fsanitize=address -pthread demo.c -o demo_asan

echo "Running AddressSanitizer..."
# ASAN-instrumented binaries exit non-zero when they detect errors.
./demo_asan 2> asan.log || true

echo "Compiling with ThreadSanitizer..."
gcc -g -fsanitize=thread -pthread demo.c -o demo_tsan

echo "Running ThreadSanitizer..."
# TSAN on newer Linux kernels needs ASLR disabled via setarch.  Try
# with setarch first, fall back to running directly (works on macOS
# and older Linux kernels).
if command -v setarch &>/dev/null; then
    setarch "$(uname -m)" --addr-no-randomize ./demo_tsan 2> tsan.log || true
else
    ./demo_tsan 2> tsan.log || true
fi

# Verify all output files were created.
all_ok=true
for f in "${output_files[@]}"; do
    if [ ! -s "$f" ]; then
        echo "warning: $f is missing or empty." >&2
        all_ok=false
    fi
done

if $all_ok; then
    echo "Done.  Load the logs in Neovim with:"
    echo "  nvim -c \":SanityLoadLog memcheck.xml helgrind.xml asan.log tsan.log\""
else
    echo "Some output files were not generated — check the errors above." >&2
    exit 1
fi
