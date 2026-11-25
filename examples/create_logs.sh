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

output_files=(memcheck.xml helgrind.xml asan.log tsan.log ubsan.log)
has_clang=false
if command -v clang &>/dev/null; then
    has_clang=true
fi
# Probe whether clang actually supports MSan on this host. The mere
# presence of clang is not enough: Apple's clang rejects
# `-fsanitize=memory`, and some Linux clang installs lack the MSan
# runtime library.
can_msan=false
if $has_clang; then
    msan_probe=$(mktemp)
    if echo 'int main(void) { return 0; }' \
        | clang -fsanitize=memory -fno-omit-frame-pointer -pthread -x c -o "$msan_probe" - 2>/dev/null; then
        can_msan=true
    fi
    rm -f "$msan_probe"
fi
# Add `msan.log` up front when MSan is available so the overwrite prompt
# and marker verification both cover it. The MSan branch below writes
# it with shell redirection, which would otherwise silently clobber an
# existing file.
if $can_msan; then
    output_files+=(msan.log)
fi

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
        # `${answer,,}` needs bash 4. This pattern is required to be compatible with macOS, which ships bash 3.2.
        case "$answer" in
            [yY]|[yY][eE][sS]) ;;
            *) echo "Aborted." >&2; exit 1 ;;
        esac
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
# and older Linux kernels). Probe setarch with a no-op first: some
# systems have the binary but prohibit disabling ASLR (e.g., restrictive
# security policies), in which case the failure would otherwise be
# swallowed by `|| true` and its error text would make tsan.log pass
# the non-empty validation while containing no TSAN findings.
if command -v setarch &>/dev/null && setarch "$(uname -m)" --addr-no-randomize true 2>/dev/null; then
    setarch "$(uname -m)" --addr-no-randomize ./demo_tsan 2> tsan.log || true
else
    ./demo_tsan 2> tsan.log || true
fi

echo "Compiling with UndefinedBehaviorSanitizer..."
gcc -g -fsanitize=undefined -fno-omit-frame-pointer -pthread demo.c -o demo_ubsan

echo "Running UndefinedBehaviorSanitizer..."
UBSAN_OPTIONS=print_stacktrace=1 ./demo_ubsan 2> ubsan.log || true

if $can_msan; then
    echo "Compiling with MemorySanitizer..."
    # MSAN ideally requires a fully instrumented toolchain; without one,
    # false positives from uninstrumented libc calls are expected.
    clang -g -fsanitize=memory -fno-omit-frame-pointer -pthread demo.c -o demo_msan
    echo "Running MemorySanitizer..."
    ./demo_msan 2> msan.log || true
elif $has_clang; then
    echo "Skipping MemorySanitizer (clang does not support -fsanitize=memory)."
else
    echo "Skipping MemorySanitizer (clang not found)."
fi

# Verify all output files were created and contain the expected marker.
# A case statement rather than an associative array (declare -A) allows the
# script to work on macOS's bash 3.2.
marker_for() {
    case "$1" in
        memcheck.xml) echo '<protocoltool>memcheck</protocoltool>' ;;
        helgrind.xml) echo '<protocoltool>helgrind</protocoltool>' ;;
        asan.log)     echo 'AddressSanitizer:' ;;
        tsan.log)     echo 'WARNING: ThreadSanitizer:' ;;
        ubsan.log)    echo 'runtime error:' ;;
        msan.log)     echo 'MemorySanitizer:' ;;
        *)            echo '' ;;
    esac
}
all_ok=true
for f in "${output_files[@]}"; do
    if [ ! -s "$f" ]; then
        echo "warning: $f is missing or empty." >&2
        all_ok=false
    else
        marker=$(marker_for "$f")
        if [ -n "$marker" ] && ! grep -q -F -- "$marker" "$f"; then
            echo "warning: $f exists but contains no '$marker' marker; the sanitizer runtime likely failed to start." >&2
            all_ok=false
        fi
    fi
done

echo
if $all_ok; then
    echo "Done. Load the logs in Neovim with:"
    echo "  nvim -c \":SanityLoadLog ${output_files[*]}\""
else
    echo "Some output files were not generated or lack a sanitizer marker. Check the errors above." >&2
    exit 1
fi
